using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Yura.Core.Connections;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon;

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
        Action<string> log)
    {
        _socketPath = socketPath;
        _allowedUids = allowedUids;
        _runtime = runtime;
        _flows = flows;
        _ownership = ownership;
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
                await WriteAsync(client, IpcResponse.Failure("Not authorised to control the daemon."), ct)
                    .ConfigureAwait(false);
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
                    var request = JsonSerializer.Deserialize<IpcRequest>(line, IpcProtocol.Json)
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

                await WriteAsync(client, response, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken ct)
    {
        switch (request.Op)
        {
            case "status":
                return new IpcResponse
                {
                    Ok = true,
                    Status = new StatusDto
                    {
                        Version = Program.Version,
                        ActiveRules = _runtime.Rules.Count,
                        ActiveFlows = _flows.ActiveCount,
                        UptimeSeconds = (long)_uptime.Elapsed.TotalSeconds,
                    },
                };

            case "set-proxies":
            {
                var proxies = (request.Proxies ?? [])
                    .Select(p => (p.ToEndpoint(), p.Password))
                    .ToList();
                var outcome = await _runtime.SetProxiesAsync(proxies, ct).ConfigureAwait(false);
                return FromOutcome(outcome);
            }

            case "apply-rule":
            {
                if (request.Rule is null)
                {
                    return IpcResponse.Failure("apply-rule needs a rule.");
                }

                var outcome = await _runtime.ApplyRuleAsync(request.Rule.ToRule(), ct).ConfigureAwait(false);
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

                var probe = await ProxyProbe.RunAsync(request.Proxy.ToEndpoint(), request.Proxy.Password, ct)
                    .ConfigureAwait(false);
                return new IpcResponse { Ok = true, Probe = probe };
            }

            default:
                return IpcResponse.Failure($"Unknown operation '{request.Op}'.");
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
        // The daemon holds both sockets of every flow it lists, which is the one and only
        // condition under which "proxied" may be claimed.
        Route = flow.State switch
        {
            ConnectionState.Failed => RouteObservation.Unknown,
            ConnectionState.Establishing => RouteObservation.Pending,
            _ => RouteObservation.ConfirmedProxied,
        },
        RuleId = flow.RuleId,
        ProxyName = flow.ProxyName,
        BytesUp = flow.BytesUp,
        BytesDown = flow.BytesDown,
        CreatedAtUtc = flow.CreatedAtUtc,
        FailureReason = flow.FailureReason,
    };

    private static async Task WriteAsync(Socket client, IpcResponse response, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(response, IpcProtocol.Json) + "\n";
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
