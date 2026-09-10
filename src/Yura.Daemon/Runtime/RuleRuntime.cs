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

    /// <summary>Processes migrated into the rule's cgroup right now.</summary>
    public int MigratedProcesses { get; init; }

    /// <summary>
    /// Sockets the covered processes already had open at apply time. They keep their old
    /// route. Null when ownership could not be established rather than guessed at zero.
    /// </summary>
    public int? PreExistingConnections { get; init; }

    /// <summary>Kernel-level warnings that did not stop the apply, e.g. a skipped host rule.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    public DateTimeOffset? ConfirmedAtUtc { get; init; }
}

/// <summary>
/// Keeps the kernel in step with the rule list.
/// </summary>
/// <remarks>
/// The runtime is reconciliation-based: every change recomputes the full desired state —
/// slots, cgroups, cgroup membership, listeners, ruleset — and applies the difference. That
/// is slower than surgical updates but it means the kernel state is a pure function of the
/// rule list, so there is no sequence of operations that can leave it inconsistent, and a
/// restart after a crash converges to the same state as a clean start.
///
/// A slot index, once assigned to a rule, is kept for that rule's lifetime. Changing it
/// would change the rule's cgroup path and listener port, which would force every process
/// in it to be migrated again for no reason.
/// </remarks>
public sealed class RuleRuntime : IAsyncDisposable
{
    private readonly CgroupManager _cgroups;
    private readonly NftablesManager _nftables;
    private readonly ProcProcessSource _processes;
    private readonly FlowRegistry _flows;
    private readonly SocketOwnership _ownership;
    private readonly Action<string> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly Dictionary<Guid, RoutingRule> _rules = [];
    private readonly Dictionary<Guid, ProxyEndpoint> _proxies = [];
    private readonly Dictionary<Guid, string?> _passwords = [];
    private readonly Dictionary<Guid, int> _slotIndexByRule = [];
    private readonly Dictionary<int, TransparentTcpListener> _listeners = [];
    private readonly Dictionary<int, TransparentUdpListener> _udpListeners = [];
    private IReadOnlyList<RuleSlot> _installedSlots = [];
    private bool _tornDown;

    public RuleRuntime(
        CgroupManager cgroups,
        NftablesManager nftables,
        ProcProcessSource processes,
        FlowRegistry flows,
        SocketOwnership ownership,
        Action<string> log)
    {
        _cgroups = cgroups;
        _nftables = nftables;
        _processes = processes;
        _flows = flows;
        _ownership = ownership;
        _log = log;
    }

    public IReadOnlyList<RoutingRule> Rules
    {
        get
        {
            _gate.Wait();
            try
            {
                return RuleEvaluator.Sort(_rules.Values);
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public IReadOnlyList<ProxyEndpoint> Proxies
    {
        get
        {
            _gate.Wait();
            try
            {
                return _proxies.Values.ToArray();
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public IReadOnlyList<RuleSlot> InstalledSlots => _installedSlots;

    /// <summary>Which slot, if any, owns a listener port. Used to attribute captured flows.</summary>
    public RuleSlot? SlotForPort(int port) => _installedSlots.FirstOrDefault(s => s.Port == port);

    // -- proxies -------------------------------------------------------------

    public async Task<ApplyOutcome> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, string? Password)> proxies,
        CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _proxies.Clear();
            _passwords.Clear();
            foreach (var (endpoint, password) in proxies)
            {
                _proxies[endpoint.Id] = endpoint;
                _passwords[endpoint.Id] = password;
            }

            return await ReconcileAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    // -- rules ---------------------------------------------------------------

    public async Task<ApplyOutcome> ApplyRuleAsync(RoutingRule rule, CancellationToken ct = default)
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

            if (rule.Action is RuleAction.Chain)
            {
                return new ApplyOutcome
                {
                    Succeeded = false,
                    FailureReason = "Proxy chains are not supported by the forwarder yet.",
                };
            }

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

            // Counted BEFORE the rule is installed: afterwards these sockets are
            // indistinguishable from ones opened under the new rule, and they are exactly
            // the connections that will keep their previous route.
            var preExisting = CountExistingSockets(rule);

            _rules[rule.Id] = rule;
            var outcome = await ReconcileAsync(ct).ConfigureAwait(false);
            outcome = outcome with { PreExistingConnections = preExisting };
            if (!outcome.Succeeded)
            {
                // Do not keep a rule the kernel refused; the list must describe reality.
                _rules.Remove(rule.Id);
                await ReconcileAsync(ct).ConfigureAwait(false);
            }

            return outcome;
        }
        finally
        {
            _gate.Release();
        }
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

            return await ReconcileAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Drops instance rules whose process has exited. Called periodically until the
    /// process-event watcher makes it event-driven.
    /// </summary>
    public async Task<int> ExpireDeadInstancesAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var dead = _rules.Values
                .Where(r => r.Lifetime == RuleLifetime.Instance && r.Process.Identity is not null)
                .Where(r =>
                {
                    var current = _processes.TryRead(r.Process.Identity!.Pid);
                    return current is null || !r.Process.Identity.Matches(current.Identity);
                })
                .ToList();

            foreach (var rule in dead)
            {
                _rules.Remove(rule.Id);
                _log($"rule '{rule.Name}' expired: its process instance is gone");
            }

            if (dead.Count > 0)
            {
                await ReconcileAsync(ct).ConfigureAwait(false);
            }

            return dead.Count;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Migrates newly started processes into the slots whose selectors now cover them.
    /// </summary>
    /// <remarks>
    /// This is what makes a persistent executable rule mean anything: the rule is installed
    /// once, but the processes it covers come and go. Instance slots are skipped — their
    /// membership is fixed by definition.
    ///
    /// Polling is a stand-in for a netlink process-event watcher, and it has a real limit: a
    /// socket's cgroup is fixed when the socket is created, so a process that starts and
    /// connects inside one poll interval is missed. Long-lived applications — the case this
    /// feature exists for — are caught. Short-lived ones need the watcher.
    /// </remarks>
    public async Task<int> RefreshMembershipAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var dynamicSlots = _installedSlots
                .Where(s => s.UsesCgroup && s.Rule.Process.Kind != ProcessSelectorKind.Instance)
                .ToList();

            if (dynamicSlots.Count == 0)
            {
                return 0;
            }

            var snapshot = _processes.Enumerate();
            var warnings = new List<string>();
            var migrated = dynamicSlots.Sum(slot => MigrateMembers(slot, snapshot, warnings));

            if (migrated > 0)
            {
                _log($"membership sweep migrated {migrated} newly started process(es)");
            }

            return migrated;
        }
        finally
        {
            _gate.Release();
        }
    }

    // -- reconciliation ------------------------------------------------------

    /// <summary>Makes the kernel match the current rule and proxy lists. Caller holds the gate.</summary>
    private async Task<ApplyOutcome> ReconcileAsync(CancellationToken ct)
    {
        var warnings = new List<string>();

        // 1. Slots. Rules that need no kernel presence (Direct with no process constraint)
        //    are simply not installed; unmatched traffic is Direct anyway.
        var slots = new List<RuleSlot>();
        foreach (var rule in RuleEvaluator.Sort(_rules.Values))
        {
            if (!rule.Enabled)
            {
                continue;
            }

            var disposition = rule.Action switch
            {
                RuleAction.Proxy => SlotDisposition.Proxy,
                RuleAction.Block => SlotDisposition.Block,
                _ => SlotDisposition.Direct,
            };

            if (disposition == SlotDisposition.Direct && rule.Process.Kind == ProcessSelectorKind.Any)
            {
                continue;
            }

            slots.Add(new RuleSlot
            {
                Index = AllocateSlotIndex(rule.Id),
                Rule = rule,
                Disposition = disposition,
            });
        }

        // Release indices of rules that no longer exist.
        foreach (var ruleId in _slotIndexByRule.Keys.Where(id => !_rules.ContainsKey(id)).ToList())
        {
            _slotIndexByRule.Remove(ruleId);
        }

        // 2. cgroups for every slot that selects on process.
        foreach (var slot in slots.Where(s => s.UsesCgroup))
        {
            _cgroups.CreateSlot(slot.Name);
        }

        // 3. Membership. Which processes belong in which slot, decided from live /proc.
        var migrated = 0;
        var snapshot = _processes.Enumerate();
        foreach (var slot in slots.Where(s => s.UsesCgroup))
        {
            migrated += MigrateMembers(slot, snapshot, warnings);
        }

        // 4. Listeners: start for new proxy slots, stop for slots that changed or vanished.
        await ReconcileListenersAsync(slots).ConfigureAwait(false);

        // 5. The ruleset, in one transaction.
        var skipped = new List<string>();
        var ruleset = NftablesManager.Build(slots, _proxies.Values.ToArray(), skipped);
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

        // 6. Only now retire cgroups of slots that are gone: their rules are no longer in
        //    the kernel, so evicting their members cannot leave anyone half-classified.
        var live = slots.Select(s => s.Name).ToHashSet();
        foreach (var old in _installedSlots.Where(s => s.UsesCgroup && !live.Contains(s.Name)))
        {
            _cgroups.RemoveSlot(old.Name);
        }

        _installedSlots = slots;

        return new ApplyOutcome
        {
            Succeeded = true,
            ConfirmedAtUtc = DateTimeOffset.UtcNow,
            MigratedProcesses = migrated,
            Warnings = warnings,
        };
    }

    /// <summary>Sockets already open for the processes a rule covers, or null if unknowable.</summary>
    private int? CountExistingSockets(RoutingRule rule)
    {
        if (rule.Process.Kind == ProcessSelectorKind.Any)
        {
            return null;
        }

        try
        {
            var counts = _ownership.CountsByPid();
            var snapshot = _processes.Enumerate();
            var pids = rule.Process.Kind == ProcessSelectorKind.Instance
                ? snapshot.Where(p => rule.Process.Identity?.Matches(p.Identity) == true)
                : snapshot.Where(rule.Process.MatchesProcess);

            return pids.Sum(p => counts.GetValueOrDefault(p.Identity.Pid));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

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
    /// Puts every process the slot's selector covers into the slot's cgroup.
    /// </summary>
    /// <remarks>
    /// Membership of a cgroup is what the kernel classifies on, so this is where the
    /// selector semantics become real:
    /// <list type="bullet">
    /// <item>Instance: exactly that identity, re-verified against live /proc first.</item>
    /// <item>Instance with existing descendants: the identity plus its current subtree.</item>
    /// <item>Executable / name / user: every currently running match. Future matches are
    /// the process watcher's job.</item>
    /// </list>
    /// Migrating a process already in the right cgroup is a harmless no-op, so this is safe
    /// to run on every reconcile.
    /// </remarks>
    private int MigrateMembers(RuleSlot slot, IReadOnlyList<ProcessSnapshot> snapshot, List<string> warnings)
    {
        var selector = slot.Rule.Process;
        var targets = new List<ProcessSnapshot>();

        if (selector.Kind == ProcessSelectorKind.Instance)
        {
            if (selector.Identity is null)
            {
                return 0;
            }

            var self = snapshot.FirstOrDefault(p => selector.Identity.Matches(p.Identity));
            if (self is null)
            {
                warnings.Add($"{slot.Rule.Name}: the process instance is no longer running");
                return 0;
            }

            targets.Add(self);
            if (selector.Descendants == DescendantPolicy.IncludeExistingAndFuture)
            {
                targets.AddRange(Descendants(self.Identity.Pid, snapshot));
            }
        }
        else
        {
            targets.AddRange(snapshot.Where(selector.MatchesProcess));
            if (selector.Descendants == DescendantPolicy.IncludeExistingAndFuture)
            {
                foreach (var match in targets.ToList())
                {
                    targets.AddRange(Descendants(match.Identity.Pid, snapshot));
                }
            }
        }

        var already = _cgroups.ReadMembers(slot.Name).ToHashSet();
        var migrated = 0;
        foreach (var process in targets.DistinctBy(p => p.Identity.Pid))
        {
            if (already.Contains(process.Identity.Pid))
            {
                continue;
            }

            // Never migrate ourselves or init; a rule that matched them is a mistake.
            if (process.Identity.Pid is 1 || process.Identity.Pid == Environment.ProcessId)
            {
                continue;
            }

            var result = _cgroups.Migrate(slot.Name, process.Identity);
            if (result.Succeeded)
            {
                migrated++;
            }
            else if (result.Outcome != MigrationOutcome.ProcessGone)
            {
                warnings.Add($"{slot.Rule.Name}: pid {process.Identity.Pid}: {result.Detail}");
            }
        }

        return migrated;
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

    private async Task ReconcileListenersAsync(IReadOnlyList<RuleSlot> slots)
    {
        var wanted = slots
            .Where(s => s.Disposition == SlotDisposition.Proxy)
            .ToDictionary(s => s.Index);

        // Stop listeners whose slot is gone or now points at a different proxy.
        foreach (var (index, listener) in _listeners.ToList())
        {
            var keep = wanted.TryGetValue(index, out var slot) &&
                       slot.Rule.Action is RuleAction.Proxy p &&
                       listener.ProxyId == p.EndpointId;
            if (!keep)
            {
                await listener.DisposeAsync().ConfigureAwait(false);
                _listeners.Remove(index);
                if (_udpListeners.Remove(index, out var udp))
                {
                    await udp.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        foreach (var (index, slot) in wanted)
        {
            if (_listeners.ContainsKey(index))
            {
                continue;
            }

            var proxyId = ((RuleAction.Proxy)slot.Rule.Action).EndpointId;
            var proxy = _proxies[proxyId];
            var password = _passwords.GetValueOrDefault(proxyId);

            var tcp = new TransparentTcpListener(slot, proxy, password, _flows, _log);
            tcp.Start();
            _listeners[index] = tcp;

            if (proxy.Protocol == ProxyProtocol.Socks5)
            {
                var udp = new TransparentUdpListener(slot, proxy, password, _flows, _log);
                udp.Start();
                _udpListeners[index] = udp;
            }
        }
    }

    // -- lifecycle -----------------------------------------------------------

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

            foreach (var listener in _udpListeners.Values)
            {
                await listener.DisposeAsync().ConfigureAwait(false);
            }

            _listeners.Clear();
            _udpListeners.Clear();
            await _nftables.RemoveAsync().ConfigureAwait(false);
            _cgroups.RemoveAllSlots();
            _installedSlots = [];
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await TeardownAsync().ConfigureAwait(false);
        _gate.Dispose();
    }
}
