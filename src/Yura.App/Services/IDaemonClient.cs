using Yura.Core.Connections;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>Connection state of the privileged daemon.</summary>
public enum DaemonState
{
    Disconnected,
    Connecting,
    Connected,
}

/// <summary>Outcome of asking the daemon to install a rule.</summary>
public sealed record RuleApplyResult
{
    public required bool Succeeded { get; init; }

    /// <summary>Set when the daemon confirmed the rule is live in the kernel.</summary>
    public DateTimeOffset? ConfirmedAtUtc { get; init; }

    /// <summary>Operator-facing failure text: what failed and what to do next.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Raw detail for the expandable technical section.</summary>
    public string? Diagnostics { get; init; }

    /// <summary>
    /// Number of connections that already existed when the rule was applied and are
    /// therefore still on their previous route. Null when the daemon could not count them.
    /// </summary>
    public int? PreExistingConnections { get; init; }
}

/// <summary>
/// The unprivileged app's only channel to the privileged daemon.
/// </summary>
/// <remarks>
/// Everything that needs privilege lives behind this interface, which keeps the app itself
/// unprivileged and makes the trust boundary a single, reviewable surface. The app never
/// touches nftables, cgroups or raw sockets.
/// </remarks>
public interface IDaemonClient
{
    DaemonState State { get; }

    event EventHandler<DaemonState>? StateChanged;

    /// <summary>Human-readable reason the daemon is unreachable, when it is.</summary>
    string? UnavailableReason { get; }

    Task ConnectAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Per-process socket counts. Only the daemon can attribute sockets to processes it
    /// does not own, so an unconnected daemon yields an empty map rather than zeros.
    /// </summary>
    Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(CancellationToken cancellationToken = default);

    Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default);

    Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default);

    Task<ProxyProbeResult> ProbeProxyAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken = default);
}

/// <summary>
/// The client used when no daemon is running.
/// </summary>
/// <remarks>
/// It refuses every privileged operation with an actionable message instead of throwing or
/// pretending to succeed. This is the default: the app is fully usable for browsing and
/// composing rules with the daemon absent, and says plainly that nothing will take effect.
/// </remarks>
public sealed class DisconnectedDaemonClient : IDaemonClient
{
    private readonly string _socketPath;

    public DisconnectedDaemonClient(string socketPath = "/run/yura/yura.sock") => _socketPath = socketPath;

    public DaemonState State => DaemonState.Disconnected;

    public event EventHandler<DaemonState>? StateChanged
    {
        add { }
        remove { }
    }

    public string? UnavailableReason =>
        $"No daemon is listening on {_socketPath}. Start it with: systemctl start yura-daemon";

    public Task ConnectAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyDictionary<int, int>>(new Dictionary<int, int>());

    public Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ConnectionRecord>>([]);

    public Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default) =>
        Task.FromResult(Refused());

    public Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Refused());

    public Task<ProxyProbeResult> ProbeProxyAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken = default) =>
        Task.FromResult(new ProxyProbeResult
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Reachable = false,
            FailureReason = "The daemon is not running, so the proxy could not be tested.",
            Diagnostics = UnavailableReason,
        });

    private RuleApplyResult Refused() => new()
    {
        Succeeded = false,
        FailureReason = "The daemon is not running, so the rule was not applied.",
        Diagnostics = UnavailableReason,
    };
}
