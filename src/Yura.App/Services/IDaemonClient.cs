using Yura.Core.Connections;
using Yura.Core.Ipc;
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

    /// <summary>Things the daemon could not do, that did not stop the rule being installed.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

/// <summary>What the daemon reports about itself, for the Diagnostics page.</summary>
public sealed record DaemonStatus
{
    public required string Version { get; init; }

    public int ActiveRules { get; init; }

    public int ActiveFlows { get; init; }

    public int ActiveGroups { get; init; }

    public TimeSpan Uptime { get; init; }

    /// <summary>"netlink" when process events come from the kernel, otherwise why they do not.</summary>
    public string? ProcessWatcher { get; init; }

    /// <summary>Processes classified at exec, before they could open a socket.</summary>
    public long ClassifiedOnExec { get; init; }

    public DnsPolicy DnsPolicy { get; init; }

    public string? KernelRelease { get; init; }

    public string? NftVersion { get; init; }

    public string? CgroupRoot { get; init; }

    public string? SocketPath { get; init; }

    public IReadOnlyList<uint> AllowedUids { get; init; } = [];

    public IReadOnlyList<DaemonCheck> Checks { get; init; } = [];

    /// <summary>Every WireGuard exit the daemon knows, whether or not it came up.</summary>
    public IReadOnlyList<TunnelStatus> Tunnels { get; init; } = [];

    /// <summary>Every Yura agent exit the daemon knows, whether or not it is connected.</summary>
    public IReadOnlyList<AgentStatus> Agents { get; init; } = [];
}

public sealed record DaemonCheck(string Name, bool Passed, string? Detail);

/// <summary>What the kernel reports about one WireGuard exit. Never carries a key.</summary>
public sealed record TunnelStatus(
    Guid ProxyId,
    string Name,
    string? Interface,
    bool Up,
    string? Failure,
    DateTimeOffset? LatestHandshakeUtc,
    long RxBytes,
    long TxBytes,
    string? Endpoint);

/// <summary>
/// What the daemon reports about one Yura agent exit. Never carries the token.
/// </summary>
/// <param name="Connected">
/// The control session. TCP flows do not need it — each opens its own connection — so an
/// agent that is not connected is degraded rather than unusable, and the UI says which.
/// </param>
public sealed record AgentStatus(
    Guid ProxyId,
    string Name,
    bool Connected,
    string? AgentName,
    string? AgentVersion,
    double? RoundTripMilliseconds,
    bool Udp,
    string? Resolver,
    string? Failure);

/// <summary>
/// The unprivileged app's only channel to the privileged daemon.
/// </summary>
/// <remarks>
/// Everything that needs privilege lives behind this interface, which keeps the app itself
/// unprivileged and makes the trust boundary a single, reviewable surface. The app never
/// touches nftables, cgroups or raw sockets.
///
/// Every method returns a result rather than throwing: the app must stay usable when the
/// daemon is absent, and "this did not work, here is why" is information the UI shows.
/// </remarks>
public interface IDaemonClient
{
    DaemonState State { get; }

    event EventHandler<DaemonState>? StateChanged;

    /// <summary>Human-readable reason the daemon is unreachable, when it is.</summary>
    string? UnavailableReason { get; }

    Task ConnectAsync(CancellationToken cancellationToken = default);

    Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Per-process socket counts. Only the daemon can attribute sockets to processes it
    /// does not own, so an unconnected daemon yields an empty map rather than zeros.
    /// </summary>
    Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default);

    /// <summary>Every connection the daemon can see, or those of one process.</summary>
    Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(
        int? pid = null, CancellationToken cancellationToken = default);

    Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default);

    Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The user-editable rules the daemon currently holds, by id and name.
    /// </summary>
    /// <remarks>
    /// The app is the source of truth for what should be installed, but it is not the only
    /// thing that has ever talked to this daemon: a rule left behind by a previous app run, or
    /// one the app superseded while the removal failed, keeps deciding routes from a position
    /// the user cannot see. Asking is the only way to find those.
    /// </remarks>
    Task<IReadOnlyList<(Guid Id, string Name)>> GetInstalledRulesAsync(
        CancellationToken cancellationToken = default);

    /// <summary>Replaces the daemon's proxy and chain list. Secrets travel only here.</summary>
    Task<RuleApplyResult> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> proxies,
        IReadOnlyList<ProxyChain> chains,
        CancellationToken cancellationToken = default);

    Task<RuleApplyResult> SetDnsPolicyAsync(DnsPolicy policy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tests an endpoint. The secrets are passed in rather than read by the daemon: only the
    /// app can reach the user's secret store, and the daemon holds no credentials at rest.
    /// </summary>
    Task<ProxyProbeResult> ProbeProxyAsync(
        ProxyEndpoint endpoint, ProxySecrets secrets, CancellationToken cancellationToken = default);

    /// <summary>Measures one target directly and, when a route is given, through it.</summary>
    Task<MeasurementDto?> MeasureAsync(
        string host, ushort port, Guid? proxyId, Guid? chainId, int samples,
        CancellationToken cancellationToken = default);

    /// <summary>The nftables table, policy routing and group membership the daemon installed.</summary>
    Task<string?> DumpRulesetAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetLogAsync(int lines = 200, CancellationToken cancellationToken = default);
}

/// <summary>
/// The client used when no daemon is running.
/// </summary>
/// <remarks>
/// It refuses every privileged operation with an actionable message instead of throwing or
/// pretending to succeed. The app is fully usable for browsing and composing rules with the
/// daemon absent, and says plainly that nothing will take effect.
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
        $"No daemon is listening on {_socketPath}. Install it from Settings, or start it with: sudo systemctl start yura-daemon";

    public Task ConnectAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<DaemonStatus?>(null);

    public Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyDictionary<int, int>>(new Dictionary<int, int>());

    public Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(
        int? pid = null, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ConnectionRecord>>([]);

    public Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default) =>
        Task.FromResult(Refused());

    public Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Refused());

    public Task<IReadOnlyList<(Guid Id, string Name)>> GetInstalledRulesAsync(
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<(Guid, string)>>([]);

    public Task<RuleApplyResult> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> proxies,
        IReadOnlyList<ProxyChain> chains,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Refused());

    public Task<RuleApplyResult> SetDnsPolicyAsync(DnsPolicy policy, CancellationToken cancellationToken = default) =>
        Task.FromResult(Refused());

    public Task<ProxyProbeResult> ProbeProxyAsync(
        ProxyEndpoint endpoint, ProxySecrets secrets, CancellationToken cancellationToken = default) =>
        Task.FromResult(new ProxyProbeResult
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Reachable = false,
            FailureReason = "The daemon is not running, so the proxy could not be tested.",
            Diagnostics = UnavailableReason,
        });

    public Task<MeasurementDto?> MeasureAsync(
        string host, ushort port, Guid? proxyId, Guid? chainId, int samples,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<MeasurementDto?>(null);

    public Task<string?> DumpRulesetAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<string?>(null);

    public Task<IReadOnlyList<string>> GetLogAsync(int lines = 200, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    private RuleApplyResult Refused() => new()
    {
        Succeeded = false,
        FailureReason = "The daemon is not running, so the rule was not applied.",
        Diagnostics = UnavailableReason,
    };
}
