using Yura.Core.Connections;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>
/// A stand-in daemon used only for design review (<c>--demo</c>).
/// </summary>
/// <remarks>
/// This exists so states that cannot occur without a running daemon — a confirmed proxy
/// route, a populated connection list, a successful probe — can be laid out and inspected
/// before the daemon exists. It is never selected by default, and every screenshot produced
/// with it is labelled as simulated. Nothing here is a substitute for the acceptance tests:
/// it proves the UI can render a state, not that the state is achievable.
/// </remarks>
public sealed class SimulatedDaemonClient : IDaemonClient
{
    private readonly Random _random = new(20260910);

    public DaemonState State => DaemonState.Connected;

    public event EventHandler<DaemonState>? StateChanged
    {
        add { }
        remove { }
    }

    public string? UnavailableReason => null;

    public Task ConnectAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyDictionary<int, int>>(new Dictionary<int, int>());

    public Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ConnectionRecord>>([]);

    public async Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default)
    {
        // A real apply is not instant, and the UI has to look right while it is in flight.
        await Task.Delay(320, cancellationToken).ConfigureAwait(false);

        return new RuleApplyResult
        {
            Succeeded = true,
            ConfirmedAtUtc = DateTimeOffset.UtcNow,
            PreExistingConnections = _random.Next(0, 4),
        };
    }

    public async Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default)
    {
        await Task.Delay(180, cancellationToken).ConfigureAwait(false);
        return new RuleApplyResult { Succeeded = true, ConfirmedAtUtc = DateTimeOffset.UtcNow };
    }

    public async Task<ProxyProbeResult> ProbeProxyAsync(
        ProxyEndpoint endpoint,
        string? password,
        CancellationToken cancellationToken = default)
    {
        await Task.Delay(500, cancellationToken).ConfigureAwait(false);

        return new ProxyProbeResult
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Reachable = true,
            HandshakeLatency = TimeSpan.FromMilliseconds(_random.Next(12, 60)),
            Udp = endpoint.Protocol == ProxyProtocol.Socks5
                ? CapabilityState.Supported
                : CapabilityState.Unsupported,
        };
    }
}
