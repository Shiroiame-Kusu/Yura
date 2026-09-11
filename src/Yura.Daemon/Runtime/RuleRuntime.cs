using System.Net;
using System.Net.Sockets;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Runtime;

/// <summary>What happened when a rule was applied.</summary>
public sealed record ApplyOutcome
{
    public required bool Succeeded { get; init; }

    public string? FailureReason { get; init; }

    public string? Diagnostics { get; init; }

    /// <summary>Processes migrated into a group right now.</summary>
    public int MigratedProcesses { get; init; }

    /// <summary>
    /// Sockets the covered processes already had open at apply time. They keep their old
    /// route. Null when ownership could not be established rather than guessed at zero.
    /// </summary>
    public int? PreExistingConnections { get; init; }

    /// <summary>
    /// Connections the daemon aborted so the rule would apply to them too, which it can only
    /// do by making the application reconnect. Null when it was not asked to abort anything.
    /// </summary>
    public int? ResetConnections { get; init; }

    /// <summary>Why connections that should have been aborted were not. Null when all were.</summary>
    public string? ResetFailure { get; init; }

    /// <summary>Kernel-level warnings that did not stop the apply, e.g. a skipped host rule.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    public DateTimeOffset? ConfirmedAtUtc { get; init; }
}

/// <summary>
/// An immutable view of everything a per-flow decision needs. Replaced wholesale on every
/// reconcile so listeners can read it without taking the runtime's lock.
/// </summary>
public sealed record DeciderState
{
    public static readonly DeciderState Empty = new();

    public IReadOnlyList<RoutingRule> OrderedRules { get; init; } = [];

    public IReadOnlyDictionary<string, ProcessGroup> GroupsByName { get; init; } = new Dictionary<string, ProcessGroup>();

    public IReadOnlyDictionary<Guid, ProxyEndpoint> Proxies { get; init; } = new Dictionary<Guid, ProxyEndpoint>();

    public IReadOnlyDictionary<Guid, ProxySecrets> Secrets { get; init; } = new Dictionary<Guid, ProxySecrets>();

    public IReadOnlyDictionary<Guid, ProxyChain> Chains { get; init; } = new Dictionary<Guid, ProxyChain>();

    /// <summary>WireGuard exits that are up, by proxy id.</summary>
    public IReadOnlyDictionary<Guid, WireGuardTunnel> Tunnels { get; init; } = new Dictionary<Guid, WireGuardTunnel>();

    /// <summary>Why the WireGuard exits that are not up are not, by proxy id.</summary>
    public IReadOnlyDictionary<Guid, string> TunnelFailures { get; init; } = new Dictionary<Guid, string>();

    /// <summary>The resolver each connected agent offered, by proxy id.</summary>
    public IReadOnlyDictionary<Guid, IPAddress> AgentResolvers { get; init; } = new Dictionary<Guid, IPAddress>();

    public bool HasHostRules { get; init; }

    /// <summary>Resolves a rule's action to the hops the dialler needs, or explains why it cannot.</summary>
    public (IReadOnlyList<ProxyHop>? Hops, string RouteName, string? Failure) ResolveRoute(RuleAction action)
    {
        switch (action)
        {
            case RuleAction.Proxy p:
            {
                if (!Proxies.TryGetValue(p.EndpointId, out var endpoint))
                {
                    return (null, "Proxy", "The rule refers to a proxy the daemon does not know about.");
                }

                var (hop, failure) = HopFor(endpoint);
                return hop is null ? (null, endpoint.Name, failure) : ([hop], endpoint.Name, null);
            }

            case RuleAction.Chain c:
            {
                if (!Chains.TryGetValue(c.ChainId, out var chain) || chain.Hops.Count == 0)
                {
                    return (null, "Chain", "The rule refers to a proxy chain the daemon does not know about.");
                }

                var hops = new List<ProxyHop>(chain.Hops.Count);
                foreach (var hopId in chain.Hops)
                {
                    if (!Proxies.TryGetValue(hopId, out var endpoint))
                    {
                        return (null, chain.Name, $"Chain '{chain.Name}' refers to a proxy that no longer exists.");
                    }

                    if (hops.Count > 0 && endpoint.Protocol == ProxyProtocol.WireGuard)
                    {
                        return (null, chain.Name, $"'{endpoint.Name}' is a WireGuard exit and can only be the first hop of chain '{chain.Name}'.");
                    }

                    var (hop, failure) = HopFor(endpoint);
                    if (hop is null)
                    {
                        return (null, chain.Name, failure);
                    }

                    hops.Add(hop);
                }

                return (hops, chain.Name, null);
            }

            default:
                return ([], action is RuleAction.Block ? "Blocked" : "Direct", null);
        }
    }

    /// <summary>One endpoint as a hop: a proxy with its password, or a WireGuard exit that is up.</summary>
    private (ProxyHop? Hop, string? Failure) HopFor(ProxyEndpoint endpoint)
    {
        if (endpoint.Protocol != ProxyProtocol.WireGuard)
        {
            return (new ProxyHop(endpoint, Secrets.GetValueOrDefault(endpoint.Id)?.Password), null);
        }

        if (Tunnels.TryGetValue(endpoint.Id, out var tunnel))
        {
            return (new ProxyHop(endpoint, null, tunnel), null);
        }

        return (null, TunnelFailures.TryGetValue(endpoint.Id, out var why)
            ? $"WireGuard exit '{endpoint.Name}' is not up: {why}"
            : $"WireGuard exit '{endpoint.Name}' is not up.");
    }
}

/// <summary>
/// Keeps the kernel in step with the rule list.
/// </summary>
/// <remarks>
/// The runtime is reconciliation-based: every change recomputes the full desired state —
/// slots, process groups, group membership, listeners, ruleset — and applies the difference.
/// That is slower than surgical updates but it means the kernel state is a pure function of
/// the rule list plus the process table, so there is no sequence of operations that can
/// leave it inconsistent, and a restart after a crash converges to the same state as a
/// clean start.
///
/// Processes are placed in cgroups by the <em>set</em> of rules that cover them, not by one
/// rule, so several rules on one process all get to match in order. Membership is driven by
/// kernel process events when they are available and re-derived from <c>/proc</c> on a
/// periodic sweep either way.
///
/// A slot index, once assigned to a rule, is kept for that rule's lifetime. Changing it
/// would change the rule's listener port for no reason.
/// </remarks>
public sealed class RuleRuntime : IAsyncDisposable, IRouteDecider
{
    private readonly CgroupManager _cgroups;
    private readonly NftablesManager _nftables;
    private readonly WireGuardManager _wireguard;
    private readonly AgentSessionManager _agents;
    private readonly ProcProcessSource _processes;
    private readonly FlowRegistry _flows;
    private readonly SocketOwnership _ownership;
    private readonly SocketReset _reset;
    private readonly Action<string> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly Dictionary<Guid, RoutingRule> _rules = [];
    private readonly Dictionary<Guid, ProxyEndpoint> _proxies = [];
    private readonly Dictionary<Guid, ProxySecrets> _secrets = [];
    private readonly Dictionary<Guid, ProxyChain> _chains = [];
    private readonly Dictionary<Guid, int> _slotIndexByRule = [];
    private readonly Dictionary<string, ProcessGroup> _groupsByKey = [];
    private readonly Dictionary<string, ProcessGroup> _groupsByName = [];

    /// <summary>Rules whose selector matches each pid directly, from the last evaluation.</summary>
    private readonly Dictionary<int, HashSet<Guid>> _direct = [];

    /// <summary>Pids covered by each rule through its descendant policy.</summary>
    private readonly Dictionary<Guid, HashSet<int>> _tree = [];

    /// <summary>
    /// The group each pid was last placed in by us. Concurrent because the fork fast path
    /// reads it from the netlink thread without taking the gate.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, string> _placed = new();

    /// <summary>
    /// Groups a forked child must be moved straight back out of.
    /// </summary>
    /// <remarks>
    /// Only groups whose every rule is instance-scoped and excludes descendants qualify. That
    /// is the precise condition under which a child cannot match any of the group's rules in
    /// its own right, so moving it out on sight cannot be wrong. Replaced wholesale on each
    /// reconcile so the fast path needs no lock.
    /// </remarks>
    private volatile IReadOnlySet<string> _fastExcludeGroups = new HashSet<string>();

    /// <summary>
    /// For each excluding group, the pids that belong in it: the identities its rules name.
    /// </summary>
    /// <remarks>
    /// Taken from the rules rather than from <see cref="_placed"/> so the guard can never evict
    /// the very process the rule is about, which <see cref="_placed"/> would allow during the
    /// window between creating a group and recording the migration into it.
    /// </remarks>
    private volatile IReadOnlyDictionary<string, IReadOnlySet<int>> _fastExcludeMembers =
        new Dictionary<string, IReadOnlySet<int>>();

    /// <summary>
    /// Executable path to the group a process running it belongs in.
    /// </summary>
    /// <remarks>
    /// Precomputed so the exec fast path is a dictionary lookup and one write. Only rules that
    /// are identified by their executable path alone are in it: a Wine rule needs argv, and a
    /// user or instance rule needs <c>/proc</c>, neither of which belongs on that thread.
    /// Replaced wholesale on each reconcile, so the fast path needs no lock.
    /// </remarks>
    private volatile IReadOnlyDictionary<string, string> _fastInclude = new Dictionary<string, string>();

    private long _excludedChildren;
    private long _excludeMisses;
    private long _includedOnExec;
    private readonly CancellationTokenSource _guardStopping = new();
    private Thread? _exclusionGuard;

    private readonly Dictionary<int, SlotListener> _listeners = [];
    private DaemonOptions _options = new();
    private IReadOnlyList<RuleSlot> _installedSlots = [];
    private volatile DeciderState _state = DeciderState.Empty;
    private bool _tornDown;

    public RuleRuntime(
        CgroupManager cgroups,
        NftablesManager nftables,
        WireGuardManager wireguard,
        AgentSessionManager agents,
        ProcProcessSource processes,
        FlowRegistry flows,
        SocketOwnership ownership,
        Action<string> log)
    {
        _cgroups = cgroups;
        _nftables = nftables;
        _wireguard = wireguard;
        _agents = agents;
        _processes = processes;
        _flows = flows;
        _ownership = ownership;
        _reset = new SocketReset(log);
        _log = log;
    }

    public DnsCache Dns { get; } = new();

    public AgentSessionManager Agents => _agents;

    public IReadOnlyList<RoutingRule> Rules => _state.OrderedRules;

    public IReadOnlyList<ProxyEndpoint> Proxies => _state.Proxies.Values.ToArray();

    public IReadOnlyList<ProxyChain> Chains => _state.Chains.Values.ToArray();

    public DaemonOptions Options => _options;

    public IReadOnlyList<RuleSlot> InstalledSlots => _installedSlots;

    public IReadOnlyCollection<ProcessGroup> Groups => _state.GroupsByName.Values.ToArray();

    public DeciderState State => _state;

    public bool SniffHosts => _state.HasHostRules;

    /// <summary>Children moved out of a group that excludes descendants, and failures to do so.</summary>
    public (long Excluded, long Failed) ExclusionCounters =>
        (Interlocked.Read(ref _excludedChildren), Interlocked.Read(ref _excludeMisses));

    /// <summary>Processes placed by the exec fast path, before they could open a socket.</summary>
    public long IncludedOnExec => Interlocked.Read(ref _includedOnExec);

    /// <summary>
    /// Watches the cgroups of rules that exclude descendants and evicts anything that is not
    /// the rule's own process.
    /// </summary>
    /// <remarks>
    /// A child inherits its parent's cgroup at fork, so excluding it is always a race against
    /// the child creating a socket — a socket's cgroup is fixed when it is created. The fork
    /// notification is the fast path, but its latency is at the kernel's and the scheduler's
    /// discretion. This bounds the window to the poll interval instead, which is the one part
    /// Yura controls. Reading one small file per group costs microseconds, and the thread only
    /// exists while a rule actually excludes descendants.
    ///
    /// It does not close the race. A child that connects within the interval keeps the route it
    /// inherited, and that is reported rather than hidden.
    /// </remarks>
    private void ExclusionGuardLoop()
    {
        var token = _guardStopping.Token;
        while (!token.IsCancellationRequested)
        {
            var groups = _fastExcludeGroups;
            if (groups.Count == 0)
            {
                // Nothing to guard: wait to be woken rather than spinning.
                token.WaitHandle.WaitOne(100);
                continue;
            }

            var members = _fastExcludeMembers;
            foreach (var group in groups)
            {
                if (!members.TryGetValue(group, out var belong))
                {
                    continue;
                }

                foreach (var pid in _cgroups.ReadMembers(group))
                {
                    // The rule's own process belongs here; everything else only inherited it.
                    if (belong.Contains(pid))
                    {
                        continue;
                    }

                    if (_cgroups.RestoreToResolved(pid, _cgroups.ResolvedOriginOf(pid)))
                    {
                        Interlocked.Increment(ref _excludedChildren);
                    }
                }
            }

            Thread.Sleep(1);
        }
    }

    private void EnsureExclusionGuard()
    {
        if (_exclusionGuard is not null || _fastExcludeGroups.Count == 0)
        {
            return;
        }

        _exclusionGuard = new Thread(ExclusionGuardLoop)
        {
            IsBackground = true,
            Name = "yura-exclusion-guard",
            // It sleeps almost all the time, and the one thing it does is latency-critical:
            // under load at normal priority it loses the race it exists to win.
            Priority = ThreadPriority.AboveNormal,
        };
        _exclusionGuard.Start();
    }

    /// <summary>
    /// Moves a just-forked child out of a group that excludes descendants, on the netlink
    /// thread, before it can create a socket. Returns true when it did.
    /// </summary>
    /// <remarks>
    /// Deliberately lock-free and /proc-free: a dictionary lookup and one write. The full
    /// handler still runs afterwards for bookkeeping — by then the child is already out, and
    /// moving it to the same place twice is harmless.
    /// </remarks>
    public bool TryExcludeChildFast(int parentPid, int childPid)
    {
        if (!_placed.TryGetValue(parentPid, out var group) || !_fastExcludeGroups.Contains(group))
        {
            return false;
        }

        // The child would have landed wherever its parent came from, so that is where it goes.
        // Taken from the parent rather than /proc, and pre-resolved, so this costs one write.
        // Nothing is logged here: formatting a line and writing it would delay the next fork's
        // move, which is the only thing this path exists to make fast. The event handler logs
        // it a moment later, off this thread.
        var moved = _cgroups.RestoreToResolved(childPid, _cgroups.ResolvedOriginOf(parentPid));
        Interlocked.Increment(ref moved ? ref _excludedChildren : ref _excludeMisses);
        return moved;
    }

    /// <summary>
    /// Places a just-exec'd process in its rule's cgroup, on the kernel's event thread, before
    /// it can create a socket. Returns true when it did.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what makes a rule work for a program that connects the instant it starts. The
    /// ordinary path — queue, lock, read six files under <c>/proc</c>, migrate — takes a few
    /// milliseconds, and a socket created inside that window keeps the cgroup it was born in
    /// for its whole life, whatever happens to the process afterwards. Measured on this
    /// machine: a program that connects within about two milliseconds of <c>exec</c> was never
    /// captured at all before this existed.
    /// </para>
    /// <para>
    /// One readlink and one write, both on paths that are already resolved. The group is known
    /// to exist because a rule's group is created when the rule is applied and kept for as long
    /// as the rule lives. The full handler still runs a moment later; moving a process to the
    /// same group twice costs nothing, and moving it to a wider group — one covering several
    /// rules that all match it — is what the slow path is for.
    /// </para>
    /// </remarks>
    public bool TryIncludeOnExecFast(int pid)
    {
        var map = _fastInclude;
        if (map.Count == 0 || pid == 1 || pid == Environment.ProcessId)
        {
            return false;
        }

        string? executable;
        try
        {
            executable = File.ResolveLinkTarget($"/proc/{pid}/exe", returnFinalTarget: false)?.FullName;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }

        if (executable is null || !map.TryGetValue(executable, out var group))
        {
            return false;
        }

        if (!_cgroups.MoveFast(group, pid))
        {
            return false;
        }

        Interlocked.Increment(ref _includedOnExec);
        return true;
    }

    // -- configuration ---------------------------------------------------------

    public async Task<ApplyOutcome> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> proxies,
        IReadOnlyList<ProxyChain> chains,
        CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _proxies.Clear();
            _secrets.Clear();
            _chains.Clear();
            foreach (var (endpoint, secrets) in proxies)
            {
                _proxies[endpoint.Id] = endpoint;
                _secrets[endpoint.Id] = secrets;
            }

            foreach (var chain in chains)
            {
                _chains[chain.Id] = chain;
            }

            // Exits first: the decider snapshot published by the reconcile below must know
            // which of them are up, and an exit that failed is a warning, not a failed apply.
            var tunnelWarnings = await _wireguard.ReconcileAsync(proxies, ct).ConfigureAwait(false);
            // Agent sessions are opened here rather than on first use, so a game's first
            // connection does not wait for a handshake and the UI can say whether the agent is
            // there before anything is routed through it.
            var agentWarnings = await _agents.ReconcileAsync(proxies, ct).ConfigureAwait(false);
            var outcome = await ReconcileAsync(ct).ConfigureAwait(false);
            return outcome with { Warnings = [.. tunnelWarnings, .. agentWarnings, .. outcome.Warnings] };
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<ApplyOutcome> SetOptionsAsync(DaemonOptions options, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _options = options;
            _log($"options: dns policy {options.DnsPolicy}");
            return await ReconcileAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    // -- rules -----------------------------------------------------------------

    /// <summary>
    /// Installs a rule and reports what the kernel confirmed.
    /// </summary>
    /// <param name="resetExisting">
    /// Abort the covered processes' open connections whose route this rule changes, so the
    /// rule governs them too. A socket's cgroup is fixed when it is created, so this is the
    /// only way a rule can reach a connection that predates it: the application's connection
    /// fails, it reconnects, and the new socket is created under the rule.
    /// </param>
    public async Task<ApplyOutcome> ApplyRuleAsync(RoutingRule rule, bool resetExisting, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (rule.Action is RuleAction.Proxy proxy && !_proxies.ContainsKey(proxy.EndpointId))
            {
                return new ApplyOutcome
                {
                    Succeeded = false,
                    FailureReason = "The rule refers to a proxy the daemon does not know about.",
                    Diagnostics = $"proxy id {proxy.EndpointId} is not in the daemon's endpoint list",
                };
            }

            if (rule.Action is RuleAction.Chain chain)
            {
                if (!_chains.TryGetValue(chain.ChainId, out var known))
                {
                    return new ApplyOutcome
                    {
                        Succeeded = false,
                        FailureReason = "The rule refers to a proxy chain the daemon does not know about.",
                        Diagnostics = $"chain id {chain.ChainId} is not in the daemon's chain list",
                    };
                }

                var missing = known.Hops.FirstOrDefault(h => !_proxies.ContainsKey(h));
                if (known.Hops.Count == 0 || missing != Guid.Empty)
                {
                    return new ApplyOutcome
                    {
                        Succeeded = false,
                        FailureReason = $"Chain '{known.Name}' has a hop that is not a configured proxy.",
                    };
                }

                if (ProxyChain.Validate(known.Hops.Select(h => _proxies[h]).ToList()) is { } invalid)
                {
                    return new ApplyOutcome { Succeeded = false, FailureReason = $"Chain '{known.Name}': {invalid}" };
                }
            }

            // A rule on an exit that is down is still a rule: its flows are refused with the
            // reason until the exit comes up, and the reason is said here too. A chain counts:
            // its first hop is the exit, so the whole chain is unusable while that is down.
            var exitWarning = DescribeDownExit(rule.Action);

            if (rule.Process.Kind == ProcessSelectorKind.Instance && rule.Process.Identity is { } identity)
            {
                // Refuse up front if the instance is already gone. Applying a rule to a pid
                // that has been reused is precisely the thing this whole design exists to
                // prevent.
                var current = _processes.TryRead(identity.Pid);
                if (current is null || !identity.Matches(current.Identity))
                {
                    return new ApplyOutcome
                    {
                        Succeeded = false,
                        FailureReason = "That process has exited. Select it again if it was restarted.",
                        Diagnostics = current is null
                            ? $"pid {identity.Pid} no longer exists"
                            : $"pid {identity.Pid} now belongs to a different process (start ticks {current.Identity.StartTicks}, expected {identity.StartTicks})",
                    };
                }
            }

            var snapshot = _processes.Enumerate();

            // Counted BEFORE the rule is installed: afterwards these sockets are
            // indistinguishable from ones opened under the new rule, and they are exactly
            // the connections that will keep their previous route.
            var preExisting = CountExistingSockets(rule, snapshot);

            // Listed before the install too, and for the same reason: the route each of those
            // sockets is on can only be worked out from the rules as they stand now. Which of
            // them the new rule actually changes is decided once it is in place.
            var resetCandidates = resetExisting ? GatherResetCandidates(rule, snapshot) : [];

            var previous = _rules.GetValueOrDefault(rule.Id);
            _rules[rule.Id] = rule;

            // Existing descendants are only swept in when the rule says so, and only once,
            // at apply time. Everything forked afterwards arrives through fork events.
            if (rule.Process.Descendants == DescendantPolicy.IncludeExistingAndFuture)
            {
                var roots = snapshot.Where(rule.Process.MatchesProcess).Select(p => p.Identity.Pid).ToList();
                var members = _tree.TryGetValue(rule.Id, out var existing) ? existing : (_tree[rule.Id] = []);
                foreach (var root in roots)
                {
                    foreach (var descendant in Descendants(root, snapshot))
                    {
                        members.Add(descendant.Identity.Pid);
                    }
                }
            }
            else if (previous is null || previous.Process.Descendants != rule.Process.Descendants)
            {
                _tree.Remove(rule.Id);
            }

            var outcome = await ReconcileAsync(ct, snapshot).ConfigureAwait(false);
            outcome = outcome with
            {
                PreExistingConnections = preExisting,
                Warnings = exitWarning is null ? outcome.Warnings : [.. outcome.Warnings, exitWarning],
            };

            // Only once the rule is really in the kernel. Aborting a connection before the
            // rule is installed would hand the application a reconnect that goes out on the
            // old route, which is worse than not aborting it at all.
            if (outcome.Succeeded && resetExisting)
            {
                var reset = ResetChangedRoutes(resetCandidates);
                outcome = outcome with
                {
                    ResetConnections = reset.Reset + reset.AlreadyGone,
                    ResetFailure = reset.Failure,
                };
            }

            if (!outcome.Succeeded)
            {
                // Do not keep a rule the kernel refused; the list must describe reality.
                if (previous is null)
                {
                    _rules.Remove(rule.Id);
                }
                else
                {
                    _rules[rule.Id] = previous;
                }

                await ReconcileAsync(ct).ConfigureAwait(false);
            }

            return outcome;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Why a rule's route may not carry traffic yet, when the exit it names is not up.
    /// </summary>
    /// <remarks>
    /// The two kinds of exit fail differently and are described differently. A WireGuard exit
    /// that is down refuses every flow, because there is no tunnel to originate from. An agent
    /// whose session is down still relays TCP — each flow opens its own connection — so the
    /// warning says what will and will not work rather than implying the rule is dead.
    /// </remarks>
    private string? DescribeDownExit(RuleAction action)
    {
        var endpointId = action switch
        {
            RuleAction.Proxy p => p.EndpointId,
            RuleAction.Chain c => _chains.TryGetValue(c.ChainId, out var chain) && chain.Hops.Count > 0
                ? chain.Hops[0]
                : (Guid?)null,
            _ => null,
        };

        if (endpointId is not { } id || !_proxies.TryGetValue(id, out var exit))
        {
            return null;
        }

        if (exit.Protocol == ProxyProtocol.WireGuard && !_wireguard.Tunnels.ContainsKey(id))
        {
            return _wireguard.Failures.TryGetValue(id, out var why)
                ? $"WireGuard exit '{exit.Name}' is not up: {why}. Connections under this rule are refused until it is."
                : $"WireGuard exit '{exit.Name}' is not up. Connections under this rule are refused until it is.";
        }

        if (exit.Protocol == ProxyProtocol.YuraAgent &&
            _agents.States.FirstOrDefault(a => a.ProxyId == id) is { Connected: false } agent)
        {
            return $"Agent exit '{exit.Name}' is not answering" +
                   $"{(agent.Failure is { } detail ? $": {detail}" : ".")} " +
                   "TCP connections under this rule will be attempted anyway; UDP cannot be carried until it answers.";
        }

        return null;
    }

    public async Task<ApplyOutcome> RemoveRuleAsync(Guid ruleId, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!_rules.Remove(ruleId))
            {
                return new ApplyOutcome { Succeeded = true, ConfirmedAtUtc = DateTimeOffset.UtcNow };
            }

            _tree.Remove(ruleId);
            return await ReconcileAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    // -- process events --------------------------------------------------------

    public async Task HandleProcessEventAsync(ProcessEvent evt, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_tornDown)
            {
                return;
            }

            switch (evt.Kind)
            {
                case ProcessEventKind.Fork:
                    await OnForkAsync(evt.Pid, evt.ChildPid, ct).ConfigureAwait(false);
                    break;
                case ProcessEventKind.Exec:
                    await OnExecAsync(evt.Pid, ct).ConfigureAwait(false);
                    break;
                case ProcessEventKind.Exit:
                    await OnExitAsync(evt.Pid, ct).ConfigureAwait(false);
                    break;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task OnForkAsync(int parent, int child, CancellationToken ct)
    {
        if (!_placed.TryGetValue(parent, out var inheritedName) || !_groupsByName.TryGetValue(inheritedName, out var inherited))
        {
            return; // The parent is not ours, so the child is not either.
        }

        if (_fastExcludeGroups.Contains(inheritedName))
        {
            // Already moved out on the netlink thread; nothing here can improve on that, so
            // this is only where it gets recorded.
            if (CgroupManager.GroupOf(child) is null)
            {
                _log($"fork: pid {child} excluded from {inheritedName}");
            }
            else
            {
                _log($"fork: pid {child} could not be excluded from {inheritedName}; it may keep the group's route");
                _cgroups.Restore(child);
            }

            return;
        }

        var childSnapshot = _processes.TryRead(child);
        if (childSnapshot is null)
        {
            return; // Already gone.
        }

        var members = new HashSet<Guid>();
        var direct = new HashSet<Guid>();
        foreach (var ruleId in inherited.RuleIds)
        {
            if (!_rules.TryGetValue(ruleId, out var rule))
            {
                continue;
            }

            // At fork time the child runs the parent's image, so any executable, name or
            // user rule that covers the parent covers the child in its own right.
            if (rule.Process.Kind != ProcessSelectorKind.Instance && rule.Process.MatchesProcess(childSnapshot))
            {
                direct.Add(ruleId);
                members.Add(ruleId);
            }

            if (rule.Process.Descendants != DescendantPolicy.Exclude)
            {
                (_tree.TryGetValue(ruleId, out var set) ? set : (_tree[ruleId] = [])).Add(child);
                members.Add(ruleId);
            }
        }

        _direct[child] = direct;

        // The child inherited its parent's origin as well as its cgroup.
        if (_cgroups.OriginOf(parent) is { } origin)
        {
            _cgroups.RememberOrigin(child, origin);
        }

        if (members.Count == 0)
        {
            // Excluded: move it out before it can open a socket in the parent's group.
            _cgroups.Restore(child);
            _log($"fork: pid {child} ({childSnapshot.DisplayName}) excluded from {inherited.Name}, returned to its origin");
            return;
        }

        var (desired, created) = GroupFor(members);
        _placed[child] = desired.Name;
        if (desired.Name != inherited.Name)
        {
            _cgroups.Move(desired.Name, child, childSnapshot.DisplayName);
        }

        if (created)
        {
            await ReinstallAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task OnExecAsync(int pid, CancellationToken ct)
    {
        var snapshot = _processes.TryRead(pid);
        if (snapshot is null)
        {
            return;
        }

        var created = PlaceProcess(snapshot, null);
        if (created)
        {
            await ReinstallAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task OnExitAsync(int pid, CancellationToken ct)
    {
        _direct.Remove(pid);
        _placed.TryRemove(pid, out _);
        _cgroups.Forget(pid);
        foreach (var set in _tree.Values)
        {
            set.Remove(pid);
        }

        var expired = ExpireInstanceRulesFor(pid);
        if (expired > 0)
        {
            await ReconcileAsync(ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The periodic safety net: expires instance rules whose process is gone, re-derives
    /// every process's membership from <c>/proc</c>, and retires empty groups. Catches
    /// anything the event stream dropped.
    /// </summary>
    public async Task SweepAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_tornDown)
            {
                return;
            }

            var snapshot = _processes.Enumerate();
            var live = snapshot.Select(p => p.Identity.Pid).ToHashSet();
            var expired = 0;
            foreach (var rule in _rules.Values.Where(r => r.Lifetime == RuleLifetime.Instance && r.Process.Identity is not null).ToList())
            {
                var identity = rule.Process.Identity!;
                var current = live.Contains(identity.Pid) ? _processes.TryRead(identity.Pid) : null;
                if (current is null || !identity.Matches(current.Identity))
                {
                    _rules.Remove(rule.Id);
                    _tree.Remove(rule.Id);
                    _log($"rule '{rule.Name}' expired: its process instance is gone");
                    expired++;
                }
            }

            if (expired > 0)
            {
                await ReconcileAsync(ct, snapshot).ConfigureAwait(false);
                return;
            }

            var warnings = new List<string>();
            var created = RecomputeMembership(snapshot, warnings);
            var pruned = PruneEmptyGroups();
            if (created || pruned)
            {
                await ReinstallAsync(ct).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private int ExpireInstanceRulesFor(int pid)
    {
        var expired = 0;
        foreach (var rule in _rules.Values.Where(r => r.Lifetime == RuleLifetime.Instance && r.Process.Identity?.Pid == pid).ToList())
        {
            var current = _processes.TryRead(pid);
            if (current is not null && rule.Process.Identity!.Matches(current.Identity))
            {
                continue; // Not actually gone; a thread exit, or a stale event.
            }

            _rules.Remove(rule.Id);
            _tree.Remove(rule.Id);
            _log($"rule '{rule.Name}' expired: pid {pid} exited");
            expired++;
        }

        return expired;
    }

    // -- membership ------------------------------------------------------------

    /// <summary>
    /// Puts every process in the group its rule set calls for. Caller holds the gate.
    /// </summary>
    /// <returns>True when a group had to be created, which means the ruleset must be reinstalled.</returns>
    private bool RecomputeMembership(IReadOnlyList<ProcessSnapshot> snapshot, List<string> warnings)
    {
        var live = snapshot.Select(p => p.Identity.Pid).ToHashSet();
        foreach (var pid in _direct.Keys.Where(p => !live.Contains(p)).ToList())
        {
            _direct.Remove(pid);
            _cgroups.Forget(pid);
        }

        foreach (var pid in _placed.Keys.Where(p => !live.Contains(p)).ToList())
        {
            _placed.TryRemove(pid, out _);
            _cgroups.Forget(pid);
        }

        foreach (var set in _tree.Values)
        {
            set.RemoveWhere(p => !live.Contains(p));
        }

        var created = false;
        foreach (var process in snapshot)
        {
            created |= PlaceProcess(process, warnings);
        }

        return created;
    }

    /// <summary>Evaluates one process's rule set and moves it if it is not where it should be.</summary>
    private bool PlaceProcess(ProcessSnapshot process, List<string>? warnings)
    {
        var pid = process.Identity.Pid;
        if (pid == 1 || pid == Environment.ProcessId)
        {
            return false; // Never migrate init or ourselves; a rule that matched them is a mistake.
        }

        var direct = new HashSet<Guid>();
        foreach (var rule in _rules.Values)
        {
            if (rule.Enabled && rule.Process.Kind != ProcessSelectorKind.Any && rule.Process.MatchesProcess(process))
            {
                direct.Add(rule.Id);
            }
        }

        var members = new HashSet<Guid>(direct);
        foreach (var (ruleId, pids) in _tree)
        {
            if (pids.Contains(pid) && _rules.TryGetValue(ruleId, out var rule) && rule.Enabled)
            {
                members.Add(ruleId);
            }
        }

        if (direct.Count == 0)
        {
            _direct.Remove(pid);
        }
        else
        {
            _direct[pid] = direct;
        }

        var tracked = _placed.ContainsKey(pid);
        if (members.Count == 0)
        {
            if (tracked || CgroupManager.GroupOf(pid) is not null)
            {
                _cgroups.Restore(pid);
                _placed.TryRemove(pid, out _);
            }

            return false;
        }

        var (desired, created) = GroupFor(members);
        var actual = CgroupManager.GroupOf(pid);
        if (actual != desired.Name)
        {
            var result = _cgroups.Migrate(desired.Name, process.Identity);
            if (result.Succeeded)
            {
                _placed[pid] = desired.Name;
            }
            else if (result.Outcome != MigrationOutcome.ProcessGone)
            {
                warnings?.Add($"pid {pid} ({process.DisplayName}): {result.Detail}");
            }
        }
        else
        {
            _placed[pid] = desired.Name;
        }

        return created;
    }

    /// <summary>
    /// Makes sure every rule that is classified by cgroup has a group of its own.
    /// </summary>
    /// <remarks>
    /// Without this a rule has no group until something matches it, which means the nftables
    /// rule naming that group does not exist either — so the first instance of a program has
    /// to be placed, the group created, and the ruleset reloaded, all before that program's
    /// first socket. That is a race nothing wins reliably. Creating the group with the rule
    /// turns it into a write to a file that is already there.
    /// </remarks>
    private void EnsureRuleGroups()
    {
        foreach (var rule in _rules.Values)
        {
            if (!rule.Enabled || rule.Process.Kind == ProcessSelectorKind.Any)
            {
                continue;
            }

            GroupFor(new HashSet<Guid> { rule.Id });
        }
    }

    private (ProcessGroup Group, bool Created) GroupFor(IReadOnlySet<Guid> ruleIds)
    {
        var key = ProcessGroup.KeyFor(ruleIds);
        if (_groupsByKey.TryGetValue(key, out var existing))
        {
            if (!_cgroups.GroupExists(existing.Name))
            {
                _cgroups.CreateGroup(existing.Name);
                return (existing, true);
            }

            return (existing, false);
        }

        var used = _groupsByName.Values.Select(g => g.Index).ToHashSet();
        var index = 1;
        while (used.Contains(index))
        {
            index++;
        }

        var group = new ProcessGroup { Index = index, RuleIds = ruleIds.ToHashSet() };
        _groupsByKey[key] = group;
        _groupsByName[group.Name] = group;
        _cgroups.CreateGroup(group.Name);
        _log($"group {group.Name} = {{{string.Join(", ", ruleIds.Select(id => _rules.TryGetValue(id, out var r) ? r.Name : id.ToString()))}}}");
        return (group, true);
    }

    /// <summary>
    /// Retires groups whose rules are gone. Returns true when the ruleset must be reinstalled.
    /// </summary>
    /// <remarks>
    /// A group is kept while every rule it belongs to still exists, even with nothing in it.
    /// Retiring an empty group looks tidier and is a trap: nftables resolved that group's path
    /// to a cgroup id when the ruleset was loaded, so deleting and recreating the directory
    /// leaves the installed rule pointing at an id that no longer exists, matching nothing,
    /// until something happens to reload the ruleset. An empty cgroup costs a directory.
    /// </remarks>
    private bool PruneEmptyGroups()
    {
        var removed = false;
        foreach (var group in _groupsByName.Values.ToList())
        {
            if (group.RuleIds.All(_rules.ContainsKey))
            {
                continue;
            }

            _cgroups.RemoveGroup(group.Name);
            _groupsByName.Remove(group.Name);
            _groupsByKey.Remove(group.Key);
            foreach (var pid in _placed.Where(kv => kv.Value == group.Name).Select(kv => kv.Key).ToList())
            {
                _placed.TryRemove(pid, out _);
            }

            removed = true;
        }

        return removed;
    }

    private static IEnumerable<ProcessSnapshot> Descendants(int rootPid, IReadOnlyList<ProcessSnapshot> snapshot)
    {
        var children = snapshot.ToLookup(p => p.ParentPid);
        var stack = new Stack<int>();
        stack.Push(rootPid);
        while (stack.Count > 0)
        {
            foreach (var child in children[stack.Pop()])
            {
                yield return child;
                stack.Push(child.Identity.Pid);
            }
        }
    }

    // -- reconciliation --------------------------------------------------------

    /// <summary>Makes the kernel match the current rule, proxy and process state. Caller holds the gate.</summary>
    private async Task<ApplyOutcome> ReconcileAsync(CancellationToken ct, IReadOnlyList<ProcessSnapshot>? snapshot = null)
    {
        var warnings = new List<string>();

        // Release indices of rules that no longer exist.
        foreach (var ruleId in _slotIndexByRule.Keys.Where(id => !_rules.ContainsKey(id)).ToList())
        {
            _slotIndexByRule.Remove(ruleId);
        }

        // 1. Membership: which processes belong in which group, decided from live /proc.
        //    Every rule's own group is created first, whether or not anything matches it yet:
        //    the group has to exist before a program starts for the exec fast path to have
        //    somewhere to put it, and nftables resolves a cgroup path to an id when the
        //    ruleset is loaded, so a group that comes and goes needs a reload each time and
        //    silently matches nothing in between.
        EnsureRuleGroups();
        snapshot ??= _processes.Enumerate();
        RecomputeMembership(snapshot, warnings);
        PruneEmptyGroups();

        // 2. Slots and listeners, then the ruleset in one transaction. The listeners are
        //    started first because the kernel chooses their ports and the ruleset has to name
        //    them.
        var slots = await ReconcileListenersAsync(BuildSlots(), warnings).ConfigureAwait(false);

        var skipped = new List<string>();
        var ruleset = NftablesManager.Build(slots, _proxies.Values.ToArray(), _options, skipped);
        warnings.AddRange(skipped);

        var applied = await _nftables.ApplyAsync(ruleset, ct).ConfigureAwait(false);
        if (!applied.Succeeded)
        {
            return new ApplyOutcome
            {
                Succeeded = false,
                FailureReason = "The kernel rejected the routing rules. Nothing was changed.",
                Diagnostics = applied.FailureText + "\n\n" + ruleset,
                Warnings = warnings,
            };
        }

        _installedSlots = slots;
        PublishState();

        return new ApplyOutcome
        {
            Succeeded = true,
            ConfirmedAtUtc = DateTimeOffset.UtcNow,
            MigratedProcesses = _placed.Count,
            Warnings = warnings,
        };
    }

    /// <summary>Reinstalls the ruleset for the current groups without re-deriving membership.</summary>
    private async Task ReinstallAsync(CancellationToken ct)
    {
        var warnings = new List<string>();
        var slots = await ReconcileListenersAsync(BuildSlots(), warnings).ConfigureAwait(false);
        var ruleset = NftablesManager.Build(slots, _proxies.Values.ToArray(), _options);
        var applied = await _nftables.ApplyAsync(ruleset, ct).ConfigureAwait(false);
        if (applied.Succeeded)
        {
            _installedSlots = slots;
            PublishState();
        }
        else
        {
            _log($"ruleset reinstall failed: {applied.FailureText}");
        }
    }

    private List<RuleSlot> BuildSlots()
    {
        var slots = new List<RuleSlot>();
        foreach (var rule in RuleEvaluator.Sort(_rules.Values))
        {
            if (!rule.Enabled)
            {
                continue;
            }

            var disposition = rule.Action switch
            {
                RuleAction.Proxy or RuleAction.Chain => SlotDisposition.Capture,
                _ when rule.Destination.Hosts.Count > 0 => SlotDisposition.Capture,
                RuleAction.Block => SlotDisposition.Block,
                _ => SlotDisposition.Direct,
            };

            // Direct with no process constraint needs no kernel presence; unmatched traffic
            // is Direct anyway.
            if (disposition == SlotDisposition.Direct && rule.Process.Kind == ProcessSelectorKind.Any)
            {
                continue;
            }

            slots.Add(new RuleSlot
            {
                Index = AllocateSlotIndex(rule.Id),
                Rule = rule,
                Disposition = disposition,
                Groups = _groupsByName.Values.Where(g => g.RuleIds.Contains(rule.Id)).OrderBy(g => g.Index).ToArray(),
            });
        }

        return slots;
    }

    private void PublishState()
    {
        var ordered = RuleEvaluator.Sort(_rules.Values);

        // A child can never match an instance rule in its own right, so a group made only of
        // instance rules that exclude descendants is one a forked child must leave at once.
        var excluding = _groupsByName.Values
            .Where(g => g.RuleIds.All(id =>
                _rules.TryGetValue(id, out var rule) &&
                rule.Process.Kind == ProcessSelectorKind.Instance &&
                rule.Process.Descendants == DescendantPolicy.Exclude))
            .ToList();

        _fastExcludeMembers = excluding.ToDictionary(
            g => g.Name,
            g => (IReadOnlySet<int>)g.RuleIds
                .Select(id => _rules.TryGetValue(id, out var rule) ? rule.Process.Identity?.Pid : null)
                .Where(pid => pid is not null)
                .Select(pid => pid!.Value)
                .ToHashSet());
        _fastExcludeGroups = excluding.Select(g => g.Name).ToHashSet();
        _fastInclude = BuildFastInclude();

        EnsureExclusionGuard();

        _state = new DeciderState
        {
            OrderedRules = ordered,
            GroupsByName = new Dictionary<string, ProcessGroup>(_groupsByName),
            Proxies = new Dictionary<Guid, ProxyEndpoint>(_proxies),
            Secrets = new Dictionary<Guid, ProxySecrets>(_secrets),
            Chains = new Dictionary<Guid, ProxyChain>(_chains),
            Tunnels = _wireguard.Tunnels,
            TunnelFailures = _wireguard.Failures,
            AgentResolvers = _agents.Resolvers,
            HasHostRules = ordered.Any(r => r.Enabled && r.Destination.Hosts.Count > 0),
        };
    }

    /// <summary>
    /// The executable paths the exec fast path can act on, and the group each belongs in.
    /// </summary>
    /// <remarks>
    /// A path is only included when every enabled rule naming it is identified by that path
    /// alone. A rule that also names a Wine executable, a user, or one instance needs evidence
    /// the fast path cannot gather in time, so those processes wait for the ordinary handler —
    /// which is correct, just slower, and they are not the programs that connect in their first
    /// millisecond.
    /// </remarks>
    private IReadOnlyDictionary<string, string> BuildFastInclude()
    {
        var byPath = new Dictionary<string, List<RoutingRule>>(StringComparer.Ordinal);
        foreach (var rule in _rules.Values.Where(r => r.Enabled))
        {
            if (rule.Process.ExecutablePath is not { Length: > 0 } path)
            {
                continue;
            }

            (byPath.TryGetValue(path, out var list) ? list : byPath[path] = []).Add(rule);
        }

        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (path, rules) in byPath)
        {
            // Anything that needs more than the path to decide disqualifies the path itself:
            // placing a process by a rule that might not actually match it would be worse than
            // placing it a few milliseconds later.
            if (rules.Any(r => r.Process.Kind != ProcessSelectorKind.ExecutablePath ||
                               r.Process.WineTargetExecutable is { Length: > 0 } ||
                               r.Process.WinePrefix is { Length: > 0 } ||
                               r.Process.Uid is not null))
            {
                continue;
            }

            var wanted = rules.Select(r => r.Id).ToHashSet();
            // The group for the full set when it exists — a process matching two rules belongs
            // in both — otherwise nothing, because the fast path must not create one.
            var group = _groupsByName.Values.FirstOrDefault(g => g.RuleIds.SetEquals(wanted));
            if (group is not null && _cgroups.GroupExists(group.Name))
            {
                map[path] = group.Name;
            }
        }

        return map;
    }

    /// <summary>Sockets already open for the processes a rule covers, or null if unknowable.</summary>
    private int? CountExistingSockets(RoutingRule rule, IReadOnlyList<ProcessSnapshot> snapshot)
    {
        if (rule.Process.Kind == ProcessSelectorKind.Any)
        {
            return null;
        }

        try
        {
            var counts = _ownership.CountsByPid();
            return snapshot.Where(rule.Process.MatchesProcess).Sum(p => counts.GetValueOrDefault(p.Identity.Pid));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // -- making a rule reach connections that predate it -----------------------

    /// <summary>An open socket of a covered process, and the route it is on as things stand.</summary>
    private readonly record struct ResetCandidate(ProcessSnapshot Process, OwnedSocket Socket, RuleAction Before);

    /// <summary>
    /// Lists the open sockets of the processes a rule is about to cover, with the route each
    /// one is on now.
    /// </summary>
    /// <remarks>
    /// Must be called before the rule is installed. Afterwards there is no way to tell what
    /// route a socket was on, and a socket whose route the rule does not change must not be
    /// aborted: the reset exists to make a rule effective, not to drop connections.
    /// </remarks>
    private List<ResetCandidate> GatherResetCandidates(RoutingRule rule, IReadOnlyList<ProcessSnapshot> snapshot)
    {
        var covered = new Dictionary<int, ProcessSnapshot>();
        foreach (var process in snapshot)
        {
            if (CoveredByRule(rule, process))
            {
                covered[process.Identity.Pid] = process;
            }
        }

        if (covered.Count == 0)
        {
            return [];
        }

        var ordered = RuleEvaluator.Sort(_rules.Values);
        var candidates = new List<ResetCandidate>();
        try
        {
            foreach (var socket in _ownership.Snapshot())
            {
                if (socket.OwnerPid is not { } pid ||
                    !covered.TryGetValue(pid, out var process) ||
                    !CanBeReset(socket))
                {
                    continue;
                }

                candidates.Add(new ResetCandidate(process, socket, DecideFor(ordered, process, socket)));
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Ownership could not be established. Nothing is aborted, and the caller reports
            // zero rather than claiming connections were moved.
            return [];
        }

        return candidates;
    }

    /// <summary>Aborts the candidates whose route the installed rule actually changed.</summary>
    private SocketResetOutcome ResetChangedRoutes(List<ResetCandidate> candidates)
    {
        if (candidates.Count == 0)
        {
            return SocketResetOutcome.Nothing;
        }

        var ordered = _state.OrderedRules;
        var targets = new List<ResetTarget>();
        foreach (var candidate in candidates)
        {
            if (DecideFor(ordered, candidate.Process, candidate.Socket) == candidate.Before)
            {
                continue;
            }

            targets.Add(new ResetTarget(candidate.Socket.Protocol, candidate.Socket.Local, candidate.Socket.Remote));
        }

        var outcome = _reset.Destroy(targets);
        if (outcome.Reset > 0)
        {
            _log($"reset {outcome.Reset} connection(s) so the rule applies to them; " +
                 "the application reconnects on the new route");
        }

        return outcome;
    }

    /// <summary>
    /// Whether aborting this socket could achieve anything.
    /// </summary>
    /// <remarks>
    /// A listening socket carries no traffic. A socket with no peer — an unconnected UDP
    /// socket, which is what a game's own protocol usually uses — has no connection to reset:
    /// aborting it hands the application an error it never asked for and does not make it
    /// rebind, so it is left alone and reported as a pre-existing connection instead. Loopback
    /// is excluded because the classifier returns early on it by design, so no rule would
    /// route the reconnection anywhere new.
    /// </remarks>
    private static bool CanBeReset(OwnedSocket socket) =>
        socket.State is "ESTABLISHED" or "SYN_SENT" or "SYN_RECV" or "CLOSE_WAIT" or "UDP" &&
        socket.Remote.Port != 0 &&
        !IPAddress.IsLoopback(socket.Remote.Address);

    /// <summary>Whether a rule covers a process, by its selector or through its process tree.</summary>
    private bool CoveredByRule(RoutingRule rule, ProcessSnapshot process) =>
        rule.Process.MatchesProcess(process) ||
        (_tree.TryGetValue(rule.Id, out var members) && members.Contains(process.Identity.Pid));

    /// <summary>
    /// What the rule list does with one open socket.
    /// </summary>
    /// <remarks>
    /// Runs the shared evaluator, which is the same code the per-flow decision uses, so a
    /// socket is only aborted when the rules really do route it somewhere else. Tree and
    /// instance membership is supplied the way the kernel classifier would supply it, because
    /// the evaluator trusts that answer over re-deriving membership from pids.
    /// </remarks>
    private RuleAction DecideFor(IReadOnlyList<RoutingRule> ordered, ProcessSnapshot process, OwnedSocket socket) =>
        RuleEvaluator.Evaluate(ordered, new RoutingRequest
        {
            Process = process,
            DestinationAddress = socket.Remote.Address,
            DestinationPort = (ushort)socket.Remote.Port,
            Protocol = socket.Protocol == ProtocolType.Udp ? TransportProtocol.Udp : TransportProtocol.Tcp,
            ClassifierMatchedRuleIds = ordered.Where(r => CoveredByRule(r, process)).Select(r => r.Id).ToHashSet(),
        }).Action;

    private int AllocateSlotIndex(Guid ruleId)
    {
        if (_slotIndexByRule.TryGetValue(ruleId, out var existing))
        {
            return existing;
        }

        var used = _slotIndexByRule.Values.ToHashSet();
        for (var index = 1; index <= RuleSlot.MaxSlots; index++)
        {
            if (!used.Contains(index))
            {
                _slotIndexByRule[ruleId] = index;
                return index;
            }
        }

        throw new InvalidOperationException($"more than {RuleSlot.MaxSlots} active rules");
    }

    /// <summary>
    /// Starts a listener for every Capture slot and stops the rest, returning the slots with
    /// the ports the kernel assigned.
    /// </summary>
    /// <remarks>
    /// A listener that cannot bind is reported as a warning and its slot is dropped from the
    /// ruleset rather than throwing: one rule that cannot be served must not stop the others
    /// from being installed, and a Capture slot with no listener would black-hole traffic.
    /// </remarks>
    private async Task<List<RuleSlot>> ReconcileListenersAsync(List<RuleSlot> slots, List<string> warnings)
    {
        var wanted = slots.Where(s => s.Disposition == SlotDisposition.Capture).ToDictionary(s => s.Index);

        foreach (var (index, listener) in _listeners.ToList())
        {
            if (wanted.ContainsKey(index))
            {
                continue;
            }

            await listener.DisposeAsync().ConfigureAwait(false);
            _listeners.Remove(index);
        }

        var result = new List<RuleSlot>(slots.Count);
        foreach (var slot in slots)
        {
            if (slot.Disposition != SlotDisposition.Capture)
            {
                result.Add(slot);
                continue;
            }

            if (!_listeners.TryGetValue(slot.Index, out var listener))
            {
                try
                {
                    // The listener only ever reads the slot's rule id; everything else about
                    // the rule is looked up live at decision time, so a rule edit needs no
                    // restart.
                    listener = SlotListener.Start(slot, this, _flows, _log);
                    _listeners[slot.Index] = listener;
                }
                catch (SocketException e)
                {
                    warnings.Add($"{slot.Rule.Name}: could not open a transparent listener ({e.SocketErrorCode}); " +
                                 "the rule is not in effect");
                    continue;
                }
            }

            result.Add(slot with { Port = listener.Port });
        }

        return result;
    }

    // -- per-flow decisions ----------------------------------------------------

    /// <summary>Pids that could own a flow captured by <paramref name="slot"/>: the members of every group its rule is in.</summary>
    public IReadOnlyCollection<int> CandidateOwners(RuleSlot slot)
    {
        var state = _state;
        var pids = new List<int>();
        foreach (var group in state.GroupsByName.Values)
        {
            if (group.RuleIds.Contains(slot.Rule.Id))
            {
                pids.AddRange(_cgroups.ReadMembers(group.Name));
            }
        }

        return pids;
    }

    /// <summary>
    /// The resolver a route offers of its own, or null when it has none and the application's
    /// choice stands.
    /// </summary>
    private IPAddress? ResolverFor(IReadOnlyList<ProxyHop>? hops, AddressFamily family) => hops switch
    {
        [{ Tunnel: { } tunnel }] => tunnel.DnsFor(family),
        [{ } hop] when hop.IsAgent => _state.AgentResolvers.GetValueOrDefault(hop.Endpoint.Id),
        _ => null,
    };

    public FlowPlan Decide(RuleSlot slot, IPEndPoint client, IPEndPoint destination, TransportProtocol protocol, string? sniffedHost)
    {
        var state = _state;

        var pid = _ownership.FindOwnerPid(
            protocol == TransportProtocol.Tcp ? ProtocolType.Tcp : ProtocolType.Udp,
            client,
            protocol == TransportProtocol.Tcp ? destination : null,
            CandidateOwners(slot));
        var process = pid is { } p ? _processes.TryRead(p) : null;

        IReadOnlySet<Guid> classified = pid is { } owner && CgroupManager.GroupOf(owner) is { } groupName &&
                                        state.GroupsByName.TryGetValue(groupName, out var group)
            ? group.RuleIds
            : new HashSet<Guid> { slot.Rule.Id };

        var host = sniffedHost ?? Dns.Lookup(destination.Address);
        var decision = RuleEvaluator.Evaluate(state.OrderedRules, new RoutingRequest
        {
            Process = process,
            DestinationAddress = destination.Address,
            DestinationPort = (ushort)destination.Port,
            Protocol = protocol,
            DestinationHost = host,
            ClassifierMatchedRuleIds = classified,
        });

        var (hops, routeName, failure) = state.ResolveRoute(decision.Action);
        var kind = decision.Action switch
        {
            RuleAction.Block => FlowPlanKind.Block,
            RuleAction.Direct => FlowPlanKind.Direct,
            _ => failure is null ? FlowPlanKind.Proxy : FlowPlanKind.Fail,
        };

        // A lookup from a process on an exit of our own goes to that exit's resolver: the one
        // the application asked for is usually a LAN or loopback address the far end cannot
        // reach, and where a name is resolved decides which of a game's servers it names.
        // Only when the policy sends DNS through the route at all.
        IPEndPoint? dial = null;
        if (kind == FlowPlanKind.Proxy && destination.Port == 53 && _options.DnsPolicy == DnsPolicy.ThroughProxy &&
            ResolverFor(hops, destination.AddressFamily) is { } resolver && !resolver.Equals(destination.Address))
        {
            dial = new IPEndPoint(resolver, 53);
        }

        return new FlowPlan
        {
            Kind = kind,
            Hops = hops ?? [],
            DialDestination = dial,
            RouteName = routeName,
            RuleId = decision.MatchedRule?.Id,
            RuleName = decision.MatchedRule?.Name,
            OwnerPid = pid,
            ProcessName = process?.DisplayName,
            Host = host,
            Explanation = decision.Explanation,
            FailureReason = failure,
        };
    }

    // -- lifecycle -------------------------------------------------------------

    /// <summary>Removes every trace of the daemon from the kernel.</summary>
    public async Task TeardownAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            // Shutdown calls this explicitly and DisposeAsync calls it again; without the
            // guard the second pass logs a failure for deleting an already-deleted table,
            // which reads like a problem in an operator's log and is not one.
            if (_tornDown)
            {
                return;
            }

            _tornDown = true;

            foreach (var listener in _listeners.Values)
            {
                await listener.DisposeAsync().ConfigureAwait(false);
            }

            _listeners.Clear();
            await _nftables.RemoveAsync().ConfigureAwait(false);
            await _wireguard.RemoveAllAsync().ConfigureAwait(false);
            await _agents.DisposeAsync().ConfigureAwait(false);
            _cgroups.RemoveAllGroups();
            _installedSlots = [];
            _state = DeciderState.Empty;
            _fastExcludeGroups = new HashSet<string>();
            _guardStopping.Cancel();
            _exclusionGuard?.Join(TimeSpan.FromSeconds(2));
            _exclusionGuard = null;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await TeardownAsync().ConfigureAwait(false);
        _guardStopping.Dispose();
        _gate.Dispose();
    }
}
