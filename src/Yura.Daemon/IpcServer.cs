using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Yura.Core.Agent;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Diagnostics;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon;

/// <summary>Facts about the machine and the daemon's startup, reported through status.</summary>
public sealed record DaemonEnvironment
{
    public required string SocketPath { get; init; }

    /// <summary>Identifies this run of the daemon, so a client can tell it restarted. See <see cref="IpcResponse.Instance"/>.</summary>
    public string Instance { get; init; } = Guid.NewGuid().ToString("N");

    public required IReadOnlyCollection<uint> AllowedUids { get; init; }

    public string? KernelRelease { get; init; }

    public string? NftVersion { get; init; }

    public IReadOnlyList<CheckDto> Checks { get; init; } = [];

    public Func<string?>? ProcessWatcherState { get; init; }

    /// <summary>Where what is routed is written down; read back by the <c>events</c> operation.</summary>
    public Diagnostics.DaemonJournal Journal { get; init; } = Diagnostics.DaemonJournal.None;
}

/// <summary>
/// The daemon's only door: a Unix domain socket speaking newline-delimited JSON.
/// </summary>
/// <remarks>
/// Authorisation is by peer credential. The kernel tells us the uid on the other end of a
/// Unix socket (<c>SO_PEERCRED</c>) and cannot be lied to, so root and the explicitly
/// allowed desktop user get in and nobody else does. No tokens, no secrets on disk.
/// </remarks>
public sealed class IpcServer : IAsyncDisposable
{
    private readonly string _socketPath;
    private readonly IReadOnlySet<uint> _allowedUids;
    private readonly RuleRuntime _runtime;
    private readonly FlowRegistry _flows;
    private readonly SocketOwnership _ownership;
    private readonly ConnectionLister _connections;
    private readonly NftablesManager _nftables;
    private readonly WireGuardManager _wireguard;
    private readonly CommandRunner _commands;
    private readonly LogBuffer _logBuffer;
    private readonly DaemonEnvironment _environment;
    private readonly Action<string> _log;
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly CancellationTokenSource _stopping = new();
    private Socket? _listener;
    private Task? _acceptLoop;

    public IpcServer(
        string socketPath,
        IReadOnlySet<uint> allowedUids,
        RuleRuntime runtime,
        FlowRegistry flows,
        SocketOwnership ownership,
        ConnectionLister connections,
        NftablesManager nftables,
        WireGuardManager wireguard,
        CommandRunner commands,
        LogBuffer logBuffer,
        DaemonEnvironment environment,
        Action<string> log)
    {
        _socketPath = socketPath;
        _allowedUids = allowedUids;
        _runtime = runtime;
        _flows = flows;
        _ownership = ownership;
        _connections = connections;
        _nftables = nftables;
        _wireguard = wireguard;
        _commands = commands;
        _logBuffer = logBuffer;
        _environment = environment;
        _log = log;
    }

    public void Start()
    {
        var directory = Path.GetDirectoryName(_socketPath)!;
        Directory.CreateDirectory(directory);
        if (File.Exists(_socketPath))
        {
            File.Delete(_socketPath);
        }

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
        listener.Listen(16);

        // World-connectable at the filesystem level; SO_PEERCRED does the real gating.
        File.SetUnixFileMode(_socketPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite);

        _listener = listener;
        _acceptLoop = AcceptLoopAsync(listener, _stopping.Token);
        _log($"ipc listening on {_socketPath} (allowed uids: {string.Join(", ", _allowedUids)})");
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                break;
            }

            _ = ServeAsync(client, ct);
        }
    }

    private async Task ServeAsync(Socket client, CancellationToken ct)
    {
        using (client)
        {
            var peerUid = PeerUid(client);
            if (peerUid is null || !_allowedUids.Contains(peerUid.Value))
            {
                _log($"ipc: refused connection from uid {peerUid?.ToString() ?? "unknown"}");
                var refusal = IpcResponse.Failure("Not authorised to control the daemon.");
                refusal.Instance = _environment.Instance;
                await WriteAsync(client, refusal, ct).ConfigureAwait(false);
                return;
            }

            using var stream = new NetworkStream(client, ownsSocket: false);
            using var reader = new StreamReader(stream, Encoding.UTF8);

            while (!ct.IsCancellationRequested)
            {
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
                {
                    break;
                }

                if (line is null)
                {
                    break;
                }

                if (line.Length == 0)
                {
                    continue;
                }

                IpcResponse response;
                try
                {
                    var request = JsonSerializer.Deserialize(line, IpcJsonContext.Default.IpcRequest)
                                  ?? throw new JsonException("empty request");
                    response = await HandleAsync(request, ct).ConfigureAwait(false);
                }
                catch (JsonException e)
                {
                    response = IpcResponse.Failure("Malformed request.", e.Message);
                }
                catch (InvalidDataException e)
                {
                    response = IpcResponse.Failure("Invalid rule.", e.Message);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    _log($"ipc: unhandled error: {e}");
                    response = IpcResponse.Failure("The daemon hit an internal error.", e.ToString());
                }

                response.Instance = _environment.Instance;
                await WriteAsync(client, response, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken ct)
    {
        switch (request.Op)
        {
            case "ping":
                // Cheap enough to ask every few seconds: whether the daemon is there, and — in
                // the instance every response carries — whether it is still the same one.
                return new IpcResponse { Ok = true };

            case "status":
                return new IpcResponse
                {
                    Ok = true,
                    Status = new StatusDto
                    {
                        Version = Program.Version,
                        ActiveRules = _runtime.Rules.Count,
                        ActiveFlows = _flows.ActiveCount,
                        ActiveGroups = _runtime.Groups.Count,
                        UptimeSeconds = (long)_uptime.Elapsed.TotalSeconds,
                        ProcessWatcher = _environment.ProcessWatcherState?.Invoke(),
                        ClassifiedOnExec = _runtime.IncludedOnExec,
                        DnsPolicy = _runtime.Options.DnsPolicy,
                        KernelRelease = _environment.KernelRelease,
                        NftVersion = _environment.NftVersion,
                        CgroupRoot = CgroupManager.Root,
                        SocketPath = _socketPath,
                        AllowedUids = _allowedUids.ToList(),
                        Checks = _environment.Checks.ToList(),
                        Tunnels = (await _wireguard.StatusAsync(ct).ConfigureAwait(false)).ToList(),
                        Agents = _runtime.Agents.States.Select(a => new AgentDto
                        {
                            ProxyId = a.ProxyId,
                            Name = a.Name,
                            Connected = a.Connected,
                            AgentName = a.AgentName,
                            AgentVersion = a.AgentVersion,
                            RoundTripMilliseconds = a.RoundTripMilliseconds,
                            Udp = a.Udp,
                            FullCone = a.FullCone,
                            Resolver = a.Resolver?.ToString(),
                            Failure = a.Failure,
                        }).ToList(),
                    },
                };

            case "set-proxies":
            {
                var proxies = (request.Proxies ?? [])
                    .Select(p => (p.ToEndpoint(), p.ToSecrets()))
                    .ToList();
                var chains = (request.Chains ?? []).Select(c => c.ToChain()).ToList();
                var outcome = await _runtime.SetProxiesAsync(proxies, chains, ct).ConfigureAwait(false);
                // An edited proxy may be another program now, or have credentials that let it be asked.
                NetworkMeasurer.ForgetEarlyAnswers();
                return FromOutcome(outcome);
            }

            case "set-options":
            {
                if (request.Options is null)
                {
                    return IpcResponse.Failure("set-options needs options.");
                }

                var outcome = await _runtime.SetOptionsAsync(new DaemonOptions { DnsPolicy = request.Options.DnsPolicy }, ct)
                    .ConfigureAwait(false);
                return FromOutcome(outcome);
            }

            case "apply-rule":
            {
                if (request.Rule is null)
                {
                    return IpcResponse.Failure("apply-rule needs a rule.");
                }

                var outcome = await _runtime
                    .ApplyRuleAsync(request.Rule.ToRule(), request.ResetExisting, ct)
                    .ConfigureAwait(false);
                return FromOutcome(outcome);
            }

            case "remove-rule":
            {
                if (request.RuleId is null)
                {
                    return IpcResponse.Failure("remove-rule needs a ruleId.");
                }

                var outcome = await _runtime.RemoveRuleAsync(request.RuleId.Value, ct).ConfigureAwait(false);
                return FromOutcome(outcome);
            }

            case "list-rules":
                return new IpcResponse { Ok = true, Rules = _runtime.Rules.Select(RuleDto.From).ToList() };

            case "list-flows":
                return new IpcResponse { Ok = true, Flows = _flows.Snapshot().Select(ToDto).ToList() };

            case "list-connections":
                return new IpcResponse { Ok = true, Connections = _connections.List(request.Pid) };

            case "connection-counts":
                return new IpcResponse
                {
                    Ok = true,
                    Counts = _ownership.CountsByPid().ToDictionary(kv => kv.Key, kv => kv.Value),
                };

            case "probe-proxy":
            {
                if (request.Proxy is null)
                {
                    return IpcResponse.Failure("probe-proxy needs a proxy.");
                }

                var endpoint = request.Proxy.ToEndpoint();
                var probe = endpoint.Protocol == ProxyProtocol.WireGuard
                    ? await _wireguard.ProbeAsync(endpoint, request.Proxy.ToSecrets(), ct).ConfigureAwait(false)
                    : await ProxyProbe.RunAsync(endpoint, request.Proxy.Password, ct).ConfigureAwait(false);
                return new IpcResponse { Ok = true, Probe = probe };
            }

            case "measure":
            {
                if (request.Measure is null)
                {
                    return IpcResponse.Failure("measure needs a target.");
                }

                IPAddress address;
                try
                {
                    address = await ProxyDialer.ResolveAsync(request.Measure.Host, ct).ConfigureAwait(false);
                }
                catch (SocketException e)
                {
                    return IpcResponse.Failure($"The measurement target '{request.Measure.Host}' could not be resolved.", e.Message);
                }

                IReadOnlyList<ProxyHop>? route = null;
                if (request.Measure.ChainId is { } chainId)
                {
                    var (hops, _, failure) = _runtime.State.ResolveRoute(new RuleAction.Chain(chainId));
                    if (failure is not null)
                    {
                        return IpcResponse.Failure(failure);
                    }

                    route = hops;
                }
                else if (request.Measure.ProxyId is { } proxyId)
                {
                    var (hops, _, failure) = _runtime.State.ResolveRoute(new RuleAction.Proxy(proxyId));
                    if (failure is not null)
                    {
                        return IpcResponse.Failure(failure);
                    }

                    route = hops;
                }

                var target = new IPEndPoint(address, request.Measure.Port);
                var measurement = await NetworkMeasurer.MeasureAsync(
                    target, route, request.Measure.Samples, ct).ConfigureAwait(false);

                // A Yura agent will say what the far half of the route costs, which is the only
                // way to tell a slow agent from a slow connection to a fast one.
                if (route is [{ } first, ..] && first.IsAgent &&
                    await _runtime.Agents.GetAsync(first.Endpoint, first.Password, ct).ConfigureAwait(false) is { } session)
                {
                    measurement = measurement with { Legs = await SplitAsync(session, target, request.Measure.Samples, ct).ConfigureAwait(false) };
                }

                return new IpcResponse { Ok = true, Measurement = measurement };
            }

            case "nat-test":
            {
                // Only ever on request. The test talks to a third party to learn what that
                // third party sees, so it is not something to do in the background.
                var wanted = request.NatTest ?? new NatTestRequestDto();

                IReadOnlyList<ProxyHop>? route = null;
                string? routeName = null;
                if (wanted.ChainId is { } chain)
                {
                    var (hops, name, failure) = _runtime.State.ResolveRoute(new RuleAction.Chain(chain));
                    if (failure is not null)
                    {
                        return IpcResponse.Failure(failure);
                    }

                    (route, routeName) = (hops, name);
                }
                else if (wanted.ProxyId is { } proxy)
                {
                    var (hops, name, failure) = _runtime.State.ResolveRoute(new RuleAction.Proxy(proxy));
                    if (failure is not null)
                    {
                        return IpcResponse.Failure(failure);
                    }

                    (route, routeName) = (hops, name);
                }

                // Both at once, each on sockets of its own. The filtering test can spend seconds
                // waiting for answers a NAT keeps out, and the two paths have no reason to queue.
                async Task<NatReportDto?> ProbeAsync(IReadOnlyList<ProxyHop>? path) =>
                    await NatProbe.RunAsync(wanted.Servers, path, ct).ConfigureAwait(false);

                var hasRoute = route is { Count: > 0 };
                var routedProbe = hasRoute ? ProbeAsync(route) : Task.FromResult<NatReportDto?>(null);
                var directProbe = wanted.RouteOnly && hasRoute ? Task.FromResult<NatReportDto?>(null) : ProbeAsync(null);
                await Task.WhenAll(routedProbe, directProbe).ConfigureAwait(false);
                var routed = await routedProbe.ConfigureAwait(false);
                var direct = await directProbe.ConfigureAwait(false);

                return new IpcResponse
                {
                    Ok = true,
                    Nat = new NatTestResultDto
                    {
                        Direct = direct,
                        Routed = routed,
                        RouteName = routeName,
                        TestedAtUtc = DateTimeOffset.UtcNow,
                    },
                };
            }

            case "dump-ruleset":
            {
                var table = await _nftables.DumpAsync(ct).ConfigureAwait(false);
                var rules = await _commands.RunAsync("ip", ["rule", "show"], cancellationToken: ct).ConfigureAwait(false);
                var routes = await _commands.RunAsync("ip", ["route", "show", "table", PolicyRouting.RoutingTable.ToString()],
                    cancellationToken: ct).ConfigureAwait(false);
                var groups = string.Join('\n', _runtime.Groups.OrderBy(g => g.Index).Select(g =>
                    $"{g.Name}: pids [{string.Join(", ", ReadMembers(g.Name))}] rules [{string.Join(", ", g.RuleIds.Select(id => _runtime.Rules.FirstOrDefault(r => r.Id == id)?.Name ?? id.ToString()))}]"));
                // wg show prints public keys and hides private and preshared ones by design.
                var tunnels = _wireguard.Tunnels.Count == 0
                    ? string.Empty
                    : "\n# wg show\n" + (await _commands.RunAsync("wg", ["show"], cancellationToken: ct).ConfigureAwait(false)).StandardOutput;
                var text = $"# nft list table inet yura\n{table}\n# ip rule show\n{rules.StandardOutput}\n# ip route show table {PolicyRouting.RoutingTable}\n{routes.StandardOutput}{tunnels}\n# process groups\n{groups}\n";
                return new IpcResponse { Ok = true, Ruleset = text };
            }

            case "log":
                return new IpcResponse { Ok = true, Log = _logBuffer.Tail(request.Lines ?? 200).ToList() };

            case "events":
                // The written record, so the desktop user can read it without being root.
                return new IpcResponse { Ok = true, Log = _environment.Journal.TailEvents(Math.Clamp(request.Lines ?? 200, 1, 5000)).ToList() };

            default:
                return IpcResponse.Failure($"Unknown operation '{request.Op}'.");
        }
    }

    /// <summary>
    /// Asks the agent to measure the target from where it is, beside our own round trip to it.
    /// </summary>
    /// <remarks>
    /// The two halves are measured the same way as the whole — a TCP connect — so they are
    /// comparable with each other and with the direct figure. They are not expected to add up
    /// exactly: the routed figure includes the agent's own handshake, and this does not, which
    /// is the honest way round for a figure the user is being shown as a split.
    /// </remarks>
    private static async Task<RouteLegsDto> SplitAsync(
        AgentSession session, IPEndPoint target, int samples, CancellationToken ct)
    {
        double? toAgent = null;
        try
        {
            toAgent = (await session.PingAsync(ct).ConfigureAwait(false)).TotalMilliseconds;
        }
        catch (Exception e) when (e is AgentProtocolException or TimeoutException or IOException
                                     or ObjectDisposedException)
        {
        }

        try
        {
            var reply = await session.ProbeAsync(
                AgentAddress.From(target), (byte)Math.Clamp(samples, 1, 10), ct).ConfigureAwait(false);

            // The median, like every other latency figure Yura shows.
            var sorted = reply.Microseconds.Order().ToArray();
            double? fromAgent = sorted.Length == 0
                ? null
                : sorted.Length % 2 == 1
                    ? sorted[sorted.Length / 2] / 1000.0
                    : (sorted[(sorted.Length / 2) - 1] + sorted[sorted.Length / 2]) / 2000.0;

            return new RouteLegsDto
            {
                AgentName = session.AgentName,
                ToAgentMilliseconds = toAgent,
                FromAgentMilliseconds = fromAgent,
                Failure = reply.Failure,
            };
        }
        catch (Exception e) when (e is AgentProtocolException or TimeoutException or IOException
                                     or ObjectDisposedException)
        {
            return new RouteLegsDto
            {
                AgentName = session.AgentName,
                ToAgentMilliseconds = toAgent,
                Failure = e.Message,
            };
        }
    }

    private static IReadOnlyList<int> ReadMembers(string groupName)
    {
        try
        {
            return File.ReadAllLines($"{CgroupManager.PathFor(groupName)}/cgroup.procs")
                .Where(l => l.Length > 0).Select(int.Parse).ToArray();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
        {
            return [];
        }
    }

    private static IpcResponse FromOutcome(ApplyOutcome outcome) => new()
    {
        Ok = outcome.Succeeded,
        Error = outcome.Succeeded ? null : outcome.FailureReason,
        Diagnostics = outcome.Succeeded ? null : outcome.Diagnostics,
        Apply = new ApplyResultDto
        {
            Succeeded = outcome.Succeeded,
            FailureReason = outcome.FailureReason,
            Diagnostics = outcome.Diagnostics,
            ConfirmedAtUtc = outcome.ConfirmedAtUtc,
            MigratedProcesses = outcome.MigratedProcesses,
            PreExistingConnections = outcome.PreExistingConnections,
            ResetConnections = outcome.ResetConnections,
            ResetFailure = outcome.ResetFailure,
            Warnings = outcome.Warnings.ToList(),
        },
    };

    private static FlowDto ToDto(Flow flow) => new()
    {
        Id = flow.Id,
        Client = flow.Client.ToString(),
        Destination = flow.OriginalDestination.ToString(),
        Protocol = flow.Protocol,
        State = flow.State,
        Route = flow.Route,
        RuleId = flow.RuleId,
        RuleName = flow.RuleName,
        ProxyName = flow.ProxyName,
        OwnerPid = flow.OwnerPid,
        ProcessName = flow.ProcessName,
        Host = flow.Host,
        BytesUp = flow.BytesUp,
        BytesDown = flow.BytesDown,
        CreatedAtUtc = flow.CreatedAtUtc,
        FailureReason = flow.FailureReason,
    };

    private static async Task WriteAsync(Socket client, IpcResponse response, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(response, IpcJsonContext.Default.IpcResponse) + "\n";
        try
        {
            await client.SendAsync(Encoding.UTF8.GetBytes(json), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException)
        {
        }
    }

    /// <summary>Reads SO_PEERCRED: struct ucred { pid_t pid; uid_t uid; gid_t gid; }.</summary>
    private static uint? PeerUid(Socket socket)
    {
        try
        {
            var buffer = new byte[12];
            var length = socket.GetRawSocketOption(1 /* SOL_SOCKET */, 17 /* SO_PEERCRED */, buffer);
            return length >= 8 ? BitConverter.ToUInt32(buffer, 4) : null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stopping.Cancel();
        _listener?.Dispose();
        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }

        try
        {
            File.Delete(_socketPath);
        }
        catch (IOException)
        {
        }

        _stopping.Dispose();
    }
}
