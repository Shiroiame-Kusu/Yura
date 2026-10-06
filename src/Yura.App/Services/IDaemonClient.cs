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

    /// <summary>
    /// Connections the daemon aborted so the rule reaches them too, which it does by making
    /// the application reconnect. Null when it was not asked to abort any.
    /// </summary>
    public int? ResetConnections { get; init; }

    /// <summary>Why connections that should have been aborted were not.</summary>
    public string? ResetFailure { get; init; }

    /// <summary>Things the daemon could not do, that did not stop the rule being installed.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>
    /// False when no answer came back at all: the daemon was unreachable, not unwilling.
    /// </summary>
    /// <remarks>
    /// The difference decides what a failure means. A daemon that answered no to a rule for a
    /// process that has gone means the rule is finished with; a daemon that could not be reached
    /// says nothing about the rule, and dropping it on that account lost the user's choice to a
    /// moment's disconnection.
    /// </remarks>
    public bool Answered { get; init; } = true;
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
/// <param name="FullCone">
/// UDP through the agent keeps one address for every peer and can be reached by anyone, which is
/// what a peer-to-peer game needs. Without it each peer sees a different port: a Strict NAT.
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
    string? Failure,
    bool FullCone = false);

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

    /// <summary>Raised on any thread when <see cref="State"/> changes.</summary>
    event EventHandler<DaemonState>? StateChanged;

    /// <summary>
    /// Raised on any thread when an answer comes from a different run of the daemon than the
    /// last one did: it restarted, and holds none of the proxies and rules it was given.
    /// </summary>
    /// <remarks>
    /// Not implied by <see cref="StateChanged"/>. A daemon restarted under systemd is back
    /// within two seconds, and the app may never have asked it anything while it was away.
    /// </remarks>
    event EventHandler? InstanceChanged;

    /// <summary>Human-readable reason the daemon is unreachable, when it is.</summary>
    string? UnavailableReason { get; }

    Task ConnectAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Asks whether the daemon is there, as cheaply as it can be asked. Keeps
    /// <see cref="State"/> current, and notices a restart, without anything else being polled.
    /// </summary>
    Task<bool> PingAsync(CancellationToken cancellationToken = default);

    Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Per-process socket counts. Only the daemon can attribute sockets to processes it
    /// does not own, so an unconnected daemon yields an empty map rather than zeros.
    /// </summary>
    Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default);

    /// <summary>Every connection the daemon can see, or those of one process.</summary>
    Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(
        int? pid = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Installs a rule in the kernel.
    /// </summary>
    /// <param name="resetExisting">
    /// Also abort the covered processes' open connections whose route this rule changes. A
    /// socket's cgroup is fixed when it is created, so a rule can otherwise only govern the
    /// next connection; aborting makes the application reconnect under the rule.
    /// </param>
    Task<RuleApplyResult> ApplyRuleAsync(
        RoutingRule rule, bool resetExisting = false, CancellationToken cancellationToken = default);

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

    /// <summary>
    /// Discovers the NAT behaviour of the direct path and, when a route is given, of the
    /// route — which is what decides whether a peer-to-peer game can connect players.
    /// </summary>
    /// <remarks>
    /// Only ever on request: the test asks third-party STUN servers what address they see,
    /// which is not something to do in the background on someone's behalf.
    /// </remarks>
    Task<NatTestResultDto?> TestNatAsync(
        Guid? proxyId, Guid? chainId, CancellationToken cancellationToken = default);

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

    public event EventHandler? InstanceChanged
    {
        add { }
        remove { }
    }

    public string? UnavailableReason =>
        $"No daemon is listening on {_socketPath}. Install it from Settings, or start it with: sudo systemctl start yura-daemon";

    public Task ConnectAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<bool> PingAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);

    public Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<DaemonStatus?>(null);

    public Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyDictionary<int, int>>(new Dictionary<int, int>());

    public Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(
        int? pid = null, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ConnectionRecord>>([]);

    public Task<RuleApplyResult> ApplyRuleAsync(
        RoutingRule rule, bool resetExisting = false, CancellationToken cancellationToken = default) =>
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

    public Task<NatTestResultDto?> TestNatAsync(
        Guid? proxyId, Guid? chainId, CancellationToken cancellationToken = default) =>
        Task.FromResult<NatTestResultDto?>(null);

    public Task<string?> DumpRulesetAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<string?>(null);

    public Task<IReadOnlyList<string>> GetLogAsync(int lines = 200, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    private RuleApplyResult Refused() => new()
    {
        Succeeded = false,
        FailureReason = "The daemon is not running, so the rule was not applied.",
        Diagnostics = UnavailableReason,
        Answered = false,
    };
}
