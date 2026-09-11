using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Yura.Core.Connections;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>
/// Talks to the privileged daemon over its Unix domain socket.
/// </summary>
/// <remarks>
/// One request per call on a fresh connection: the protocol is a single line in and a single
/// line out, calls are infrequent and user-driven, and a per-call connection means a daemon
/// restart needs no reconnection logic here. A persistent connection would buy nothing and
/// would need its own recovery path.
///
/// Every failure surfaces as a result object with an operator-facing reason, never an
/// exception thrown at the view model. The app must stay usable when the daemon is not.
/// </remarks>
public sealed class UnixSocketDaemonClient : IDaemonClient
{
    private readonly string _socketPath;
    private DaemonState _state = DaemonState.Disconnected;
    private string? _unavailableReason;

    public UnixSocketDaemonClient(string? socketPath = null) =>
        _socketPath = socketPath ?? IpcProtocol.DefaultSocketPath;

    public DaemonState State => _state;

    public event EventHandler<DaemonState>? StateChanged;

    public string? UnavailableReason => _state == DaemonState.Connected
        ? null
        : _unavailableReason ?? $"No daemon is listening on {_socketPath}. Install it from Settings, or start it with: sudo systemctl start yura-daemon";

    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        SetState(DaemonState.Connecting);
        var response = await SendAsync(new IpcRequest { Op = "status" }, cancellationToken).ConfigureAwait(false);
        SetState(response.Ok ? DaemonState.Connected : DaemonState.Disconnected);
    }

    public async Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest { Op = "status" }, cancellationToken).ConfigureAwait(false);
        if (!response.Ok || response.Status is not { } status)
        {
            return null;
        }

        return new DaemonStatus
        {
            Version = status.Version,
            ActiveRules = status.ActiveRules,
            ActiveFlows = status.ActiveFlows,
            ActiveGroups = status.ActiveGroups,
            Uptime = TimeSpan.FromSeconds(status.UptimeSeconds),
            ProcessWatcher = status.ProcessWatcher,
            ClassifiedOnExec = status.ClassifiedOnExec,
            DnsPolicy = status.DnsPolicy,
            KernelRelease = status.KernelRelease,
            NftVersion = status.NftVersion,
            CgroupRoot = status.CgroupRoot,
            SocketPath = status.SocketPath,
            AllowedUids = status.AllowedUids,
            Checks = status.Checks.Select(c => new DaemonCheck(c.Name, c.Passed, c.Detail)).ToArray(),
            Tunnels = status.Tunnels.Select(t => new TunnelStatus(
                t.ProxyId, t.Name, t.Interface, t.Up, t.Failure, t.LatestHandshakeUtc, t.RxBytes, t.TxBytes, t.Endpoint)).ToArray(),
            Agents = status.Agents.Select(a => new AgentStatus(
                a.ProxyId, a.Name, a.Connected, a.AgentName, a.AgentVersion, a.RoundTripMilliseconds, a.Udp,
                a.Resolver, a.Failure)).ToArray(),
        };
    }

    public async Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest { Op = "connection-counts" }, cancellationToken).ConfigureAwait(false);
        return response.Counts ?? new Dictionary<int, int>();
    }

    public async Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(
        int? pid = null, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest { Op = "list-connections", Pid = pid }, cancellationToken)
            .ConfigureAwait(false);
        if (response.Connections is null)
        {
            return [];
        }

        return response.Connections.Select(ToRecord).ToArray();
    }

    public async Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(
            new IpcRequest { Op = "apply-rule", Rule = RuleDto.From(rule) }, cancellationToken).ConfigureAwait(false);
        return ToApplyResult(response);
    }

    public async Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(
            new IpcRequest { Op = "remove-rule", RuleId = ruleId }, cancellationToken).ConfigureAwait(false);
        return ToApplyResult(response);
    }

    public async Task<IReadOnlyList<(Guid Id, string Name)>> GetInstalledRulesAsync(
        CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(
            new IpcRequest { Op = "list-rules" }, cancellationToken).ConfigureAwait(false);
        if (!response.Ok || response.Rules is null)
        {
            return [];
        }

        // System rules are the daemon's own and are not the app's to remove.
        return response.Rules
            .Where(r => r.Origin != RuleOrigin.System)
            .Select(r => (r.Id, r.Name))
            .ToArray();
    }

    public async Task<RuleApplyResult> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> proxies,
        IReadOnlyList<ProxyChain> chains,
        CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest
        {
            Op = "set-proxies",
            Proxies = proxies.Select(p => ProxyDto.From(p.Endpoint, p.Secrets)).ToList(),
            Chains = chains.Select(ChainDto.From).ToList(),
        }, cancellationToken).ConfigureAwait(false);
        return ToApplyResult(response);
    }

    public async Task<RuleApplyResult> SetDnsPolicyAsync(DnsPolicy policy, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest
        {
            Op = "set-options",
            Options = new OptionsDto { DnsPolicy = policy },
        }, cancellationToken).ConfigureAwait(false);
        return ToApplyResult(response);
    }

    public async Task<ProxyProbeResult> ProbeProxyAsync(
        ProxyEndpoint endpoint, ProxySecrets secrets, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest
        {
            Op = "probe-proxy",
            Proxy = ProxyDto.From(endpoint, secrets),
        }, cancellationToken).ConfigureAwait(false);

        if (!response.Ok || response.Probe is null)
        {
            return new ProxyProbeResult
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Reachable = false,
                FailureReason = response.Error ?? "The daemon did not answer the probe.",
                Diagnostics = response.Diagnostics,
            };
        }

        var probe = response.Probe;
        return new ProxyProbeResult
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Reachable = probe.Reachable,
            HandshakeLatency = probe.HandshakeMilliseconds is { } ms ? TimeSpan.FromMilliseconds(ms) : null,
            Udp = probe.Udp,
            FailureReason = probe.FailureReason,
            Diagnostics = probe.Diagnostics,
        };
    }

    public async Task<MeasurementDto?> MeasureAsync(
        string host, ushort port, Guid? proxyId, Guid? chainId, int samples,
        CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest
        {
            Op = "measure",
            Measure = new MeasureRequestDto
            {
                Host = host,
                Port = port,
                ProxyId = proxyId,
                ChainId = chainId,
                Samples = samples,
            },
        }, cancellationToken).ConfigureAwait(false);

        return response.Ok ? response.Measurement : null;
    }

    public async Task<string?> DumpRulesetAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest { Op = "dump-ruleset" }, cancellationToken).ConfigureAwait(false);
        return response.Ok ? response.Ruleset : response.Error;
    }

    public async Task<IReadOnlyList<string>> GetLogAsync(int lines = 200, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest { Op = "log", Lines = lines }, cancellationToken).ConfigureAwait(false);
        return response.Log ?? [];
    }

    // -- transport -----------------------------------------------------------

    private async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(_socketPath), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException e)
        {
            _unavailableReason = e.SocketErrorCode switch
            {
                SocketError.AccessDenied =>
                    $"Not permitted to use {_socketPath}. The daemon only accepts root and the user that started it.",
                _ => $"No daemon is listening on {_socketPath}. Install it from Settings, or start it with: sudo systemctl start yura-daemon",
            };
            SetState(DaemonState.Disconnected);
            return IpcResponse.Failure(_unavailableReason, e.Message);
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
            SetState(DaemonState.Disconnected);
            return IpcResponse.Failure("Could not reach the daemon.", e.Message);
        }

        try
        {
            using var stream = new NetworkStream(socket, ownsSocket: false);
            using var reader = new StreamReader(stream, Encoding.UTF8);

            var json = JsonSerializer.Serialize(request, IpcProtocol.Json) + "\n";
            await socket.SendAsync(Encoding.UTF8.GetBytes(json), cancellationToken).ConfigureAwait(false);

            var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                SetState(DaemonState.Disconnected);
                return IpcResponse.Failure("The daemon closed the connection without answering.");
            }

            var response = JsonSerializer.Deserialize<IpcResponse>(line, IpcProtocol.Json)
                           ?? IpcResponse.Failure("The daemon sent an empty response.");
            SetState(response.Ok ? DaemonState.Connected : _state);
            return response;
        }
        catch (Exception e) when (e is IOException or SocketException or JsonException or OperationCanceledException)
        {
            SetState(DaemonState.Disconnected);
            return IpcResponse.Failure("The daemon stopped responding.", e.Message);
        }
    }

    private void SetState(DaemonState state)
    {
        if (_state == state)
        {
            return;
        }

        _state = state;
        if (state == DaemonState.Connected)
        {
            _unavailableReason = null;
        }

        StateChanged?.Invoke(this, state);
    }

    private static RuleApplyResult ToApplyResult(IpcResponse response) => new()
    {
        Succeeded = response.Ok && (response.Apply?.Succeeded ?? true),
        ConfirmedAtUtc = response.Apply?.ConfirmedAtUtc,
        FailureReason = response.Error ?? response.Apply?.FailureReason,
        Diagnostics = response.Diagnostics ?? response.Apply?.Diagnostics,
        PreExistingConnections = response.Apply?.PreExistingConnections,
        Warnings = response.Apply?.Warnings ?? [],
    };

    private static ConnectionRecord ToRecord(ConnectionDto connection) => new()
    {
        Id = connection.Id,
        OwnerPid = connection.Pid,
        ProcessDisplayName = connection.ProcessName,
        Local = ParseEndpoint(connection.Local),
        Remote = ParseEndpoint(connection.Remote),
        RemoteHost = connection.Host,
        Protocol = connection.Protocol,
        State = connection.State,
        KernelState = connection.KernelState,
        Route = connection.Route,
        MatchedRuleId = connection.RuleId,
        MatchedRuleName = connection.RuleName,
        ProxyName = connection.ProxyName,
        BytesUp = connection.BytesUp,
        BytesDown = connection.BytesDown,
        CreatedAtUtc = connection.CreatedAtUtc,
        FailureReason = connection.FailureReason,
        Note = connection.Note,
    };

    private static IPEndPoint ParseEndpoint(string text) =>
        IPEndPoint.TryParse(text, out var endpoint) ? endpoint : new IPEndPoint(IPAddress.None, 0);
}
