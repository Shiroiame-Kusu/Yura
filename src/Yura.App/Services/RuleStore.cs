using System.Collections.ObjectModel;
using Yura.App.ViewModels;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>
/// A route a rule or a game can be pointed at: one proxy, or a chain of them.
/// </summary>
/// <remarks>
/// The two are interchangeable everywhere a route is chosen, and a UI that binds to a common
/// shape rather than to <c>object</c> keeps compiled bindings — which is what catches a typo
/// in a binding path at build time instead of at render time.
/// </remarks>
public sealed record RouteOption(Guid Id, string Name, bool IsChain, CapabilityState UdpSupport, string Detail)
{
    public static RouteOption For(ProxyEndpoint proxy) =>
        new(proxy.Id, proxy.Name, false, proxy.UdpSupport, $"{proxy.ProtocolDisplay} · {proxy.Authority}");

    /// <summary>"Home server → Tokyo relay", with a missing hop shown as "?" rather than hidden.</summary>
    public static string DescribeHops(ProxyChain chain, IEnumerable<ProxyEndpoint> proxies) =>
        string.Join(" → ", chain.Hops.Select(id => proxies.FirstOrDefault(p => p.Id == id)?.Name ?? "?"));

    public static RouteOption For(ProxyChain chain, IEnumerable<ProxyEndpoint> proxies) =>
        new(chain.Id, chain.Name, true, chain.SupportsUdp, DescribeHops(chain, proxies));

    public RuleAction ToAction() => IsChain ? new RuleAction.Chain(Id) : new RuleAction.Proxy(Id);
}

/// <summary>A rule edit that can be taken back.</summary>
/// <remarks>
/// Undo is offered for rule edits because a wrong routing rule is disruptive and obvious, and
/// the correction is always the same: put back exactly what was there. Holding the previous
/// rule — or its absence — is the whole mechanism.
/// </remarks>
public sealed record RuleUndo(string Description, RoutingRule? Previous, RoutingRule? Current);

/// <summary>
/// The single ordered rule list, shared by manual process selections and game profiles.
/// </summary>
/// <remarks>
/// The app keeps its own copy so it can explain and preview decisions without a round trip,
/// but the daemon remains the authority on what is actually installed. A rule only counts
/// as active once <see cref="RoutingRule.AppliedAtUtc"/> has been set from a daemon reply.
/// </remarks>
public sealed class RuleStore
{
    /// <summary>
    /// Order bands, so the two workflows have a predictable precedence without the user
    /// having to reason about absolute numbers. Lower evaluates first.
    /// </summary>
    public const int ProcessSelectionBand = 100;

    public const int GameProfileBand = 300;

    public const int ManualBand = 500;

    private readonly List<RoutingRule> _rules = [];

    public RuleStore()
    {
        Proxies.CollectionChanged += (_, _) => RebuildRoutes();
        Chains.CollectionChanged += (_, _) => RebuildRoutes();
    }

    /// <summary>
    /// Keeps <see cref="Routes"/> in step, in place.
    /// </summary>
    /// <remarks>
    /// Updated rather than replaced so a combo box that has one selected does not lose it
    /// every time an unrelated proxy is edited.
    /// </remarks>
    private void RebuildRoutes()
    {
        var desired = Proxies.Select(RouteOption.For)
            .Concat(Chains.Select(c => RouteOption.For(c, Proxies)))
            .ToList();

        for (var i = Routes.Count - 1; i >= 0; i--)
        {
            if (desired.All(d => d.Id != Routes[i].Id))
            {
                Routes.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            var existing = Routes.FirstOrDefault(r => r.Id == desired[i].Id);
            if (existing is null)
            {
                Routes.Insert(Math.Min(i, Routes.Count), desired[i]);
            }
            else if (existing != desired[i])
            {
                Routes[Routes.IndexOf(existing)] = desired[i];
            }
        }
    }

    /// <summary>The option for a route id, when it still exists.</summary>
    public RouteOption? FindRoute(Guid id) => Routes.FirstOrDefault(r => r.Id == id);

    public ObservableCollection<ProxyEndpoint> Proxies { get; } = [];

    public ObservableCollection<ProxyChain> Chains { get; } = [];

    /// <summary>Proxies and chains as one list, rebuilt whenever either changes.</summary>
    public ObservableCollection<RouteOption> Routes { get; } = [];

    public IReadOnlyList<RoutingRule> Rules => RuleEvaluator.Sort(_rules);

    public event EventHandler? Changed;

    /// <summary>The last edit, while it can still be undone.</summary>
    public RuleUndo? PendingUndo { get; private set; }

    /// <summary>Display name of a route id, whether it is a proxy or a chain.</summary>
    public string? RouteName(Guid id) =>
        Proxies.FirstOrDefault(p => p.Id == id)?.Name ?? Chains.FirstOrDefault(c => c.Id == id)?.Name;

    /// <summary>Rules whose action names this proxy or chain directly.</summary>
    public IReadOnlyList<RoutingRule> RulesUsing(Guid routeId) =>
        _rules.Where(r => r.Action switch
        {
            RuleAction.Proxy p => p.EndpointId == routeId,
            RuleAction.Chain c => c.ChainId == routeId,
            _ => false,
        }).ToArray();

    /// <summary>Chains that have this proxy as a hop.</summary>
    public IReadOnlyList<ProxyChain> ChainsUsing(Guid proxyId) =>
        Chains.Where(c => c.Hops.Contains(proxyId)).ToArray();

    /// <summary>
    /// Removes a proxy and takes it out of every chain that used it. Rules that named it are
    /// left in place: they show an unknown route rather than silently changing meaning.
    /// </summary>
    /// <returns>Chains that were left with no hops and were therefore removed too.</returns>
    public IReadOnlyList<ProxyChain> RemoveProxy(Guid proxyId)
    {
        var emptied = new List<ProxyChain>();
        foreach (var chain in Chains.Where(c => c.Hops.Contains(proxyId)).ToList())
        {
            var remaining = chain.Hops.Where(h => h != proxyId).ToArray();
            if (remaining.Length == 0)
            {
                Chains.Remove(chain);
                emptied.Add(chain);
            }
            else
            {
                Chains[Chains.IndexOf(chain)] = chain with { Hops = remaining };
            }
        }

        var proxy = Proxies.FirstOrDefault(p => p.Id == proxyId);
        if (proxy is not null)
        {
            Proxies.Remove(proxy);
        }

        return emptied;
    }

    /// <summary>Adds or replaces a chain, keeping its position when it already exists.</summary>
    public void PutChain(ProxyChain chain)
    {
        var existing = Chains.FirstOrDefault(c => c.Id == chain.Id);
        if (existing is null)
        {
            Chains.Add(chain);
        }
        else
        {
            Chains[Chains.IndexOf(existing)] = chain;
        }
    }

    public void RemoveChain(Guid chainId)
    {
        var chain = Chains.FirstOrDefault(c => c.Id == chainId);
        if (chain is not null)
        {
            Chains.Remove(chain);
        }
    }

    /// <summary>
    /// Replaces the rule list with what was loaded from disk.
    /// </summary>
    /// <remarks>
    /// Used once at startup, before anything is applied. Rules arrive without
    /// <see cref="RoutingRule.AppliedAtUtc"/> set: a rule that was live in a previous session
    /// is not live now, and showing it as active before the daemon has confirmed it would be
    /// the exact lie the pending state exists to prevent.
    /// </remarks>
    public void LoadPersisted(IEnumerable<RoutingRule> rules)
    {
        _rules.Clear();
        foreach (var rule in rules)
        {
            _rules.Add(rule with { AppliedAtUtc = null });
        }

        PendingUndo = null;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// The earlier selection a new rule for the same subject would replace, if there is one.
    /// </summary>
    /// <remarks>
    /// Asked before the new rule is installed, so the caller can install it <em>in place</em> of
    /// this one — same id, same position — which the daemon does in one step. Installed beside
    /// it and removed afterwards, the old rule was still winning at the moment the daemon
    /// compared routes before and after, so "apply to connections already open" found nothing
    /// to move.
    /// </remarks>
    public RoutingRule? FindSupersededBy(RoutingRule rule) =>
        _rules.FirstOrDefault(r => r.Id != rule.Id && r.Origin == rule.Origin && SameSubject(r, rule));

    /// <summary>
    /// Adds a rule, replacing every earlier selection for the same subject.
    /// </summary>
    /// <returns>
    /// The rules this one superseded that had a different id. The caller must take them out of
    /// the daemon as well: dropping them from this list only changes what the app shows, and a
    /// superseded rule left installed keeps deciding routes from its position. A rule installed
    /// in place of the one it replaces — same id — needs no such removal.
    /// </returns>
    /// <remarks>
    /// Every one, not the first. Until destinations were compared by value, a rule restored from
    /// the configuration was never superseded, so a saved configuration can hold several
    /// selections for one subject — and replacing only the first left another deciding routes.
    /// </remarks>
    public IReadOnlyList<RoutingRule> Add(RoutingRule rule)
    {
        // A new selection for the same process replaces the previous one rather than
        // stacking, so the effective policy is never the result of two competing overrides.
        var sameId = _rules.FirstOrDefault(r => r.Id == rule.Id);
        var superseded = _rules
            .Where(r => r.Id != rule.Id && r.Origin == rule.Origin && SameSubject(r, rule))
            .ToList();

        if (sameId is not null)
        {
            _rules.Remove(sameId);
        }

        foreach (var old in superseded)
        {
            _rules.Remove(old);
        }

        _rules.Add(rule);
        PendingUndo = new RuleUndo(rule.Name, sameId ?? superseded.FirstOrDefault(), rule);
        Changed?.Invoke(this, EventArgs.Empty);
        return superseded;
    }

    /// <summary>
    /// Records that nothing is confirmed any more: the daemon went away, or came back as a new
    /// process holding none of the rules it was given.
    /// </summary>
    /// <remarks>
    /// Every rule reads as pending until the daemon confirms it again. Left as they were, the
    /// pages kept saying "Active" and "Proxied" about rules no kernel was carrying out.
    /// </remarks>
    public void MarkAllPending()
    {
        var changed = false;
        for (var i = 0; i < _rules.Count; i++)
        {
            if (_rules[i].AppliedAtUtc is not null)
            {
                _rules[i] = _rules[i] with { AppliedAtUtc = null };
                changed = true;
            }
        }

        if (changed)
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>
    /// Records that the daemon confirmed a rule is live in the kernel.
    /// </summary>
    /// <remarks>
    /// Nothing else may set <see cref="RoutingRule.AppliedAtUtc"/>. It is the difference
    /// between "the user asked for this" and "the kernel is doing this", and the UI renders
    /// the two differently on purpose.
    /// </remarks>
    public void MarkApplied(Guid id, DateTimeOffset? confirmedAtUtc)
    {
        var index = _rules.FindIndex(r => r.Id == id);
        if (index < 0)
        {
            return;
        }

        _rules[index] = _rules[index] with { AppliedAtUtc = confirmedAtUtc ?? DateTimeOffset.UtcNow };
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(Guid id)
    {
        var removed = _rules.FirstOrDefault(r => r.Id == id);
        if (removed is null)
        {
            return;
        }

        _rules.Remove(removed);
        PendingUndo = new RuleUndo(removed.Name, removed, null);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Replaces a rule in place, keeping its id and position.</summary>
    public void Replace(RoutingRule rule)
    {
        var index = _rules.FindIndex(r => r.Id == rule.Id);
        if (index < 0)
        {
            Add(rule);
            return;
        }

        PendingUndo = new RuleUndo(rule.Name, _rules[index], rule);
        _rules[index] = rule;
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Moves a rule one position earlier or later in evaluation order.
    /// </summary>
    /// <remarks>
    /// Reordering rewrites <see cref="RoutingRule.Order"/> on the two rules that swap, rather
    /// than renumbering the list, so unrelated rules keep the numbers the user has seen.
    /// Returns the rules whose order changed, for the caller to reapply.
    /// </remarks>
    public IReadOnlyList<RoutingRule> Move(Guid id, bool earlier)
    {
        var ordered = Rules;
        var index = ordered.ToList().FindIndex(r => r.Id == id);
        var swapWith = earlier ? index - 1 : index + 1;
        if (index < 0 || swapWith < 0 || swapWith >= ordered.Count)
        {
            return [];
        }

        var a = ordered[index];
        var b = ordered[swapWith];

        // Equal Order values are broken by CreatedAtUtc, so swapping the numbers alone would
        // not move anything. Give the one that must come first a strictly lower number.
        var (first, second) = earlier ? (a, b) : (b, a);
        var order = Math.Min(a.Order, b.Order);
        var updated = new[]
        {
            first with { Order = order, AppliedAtUtc = null },
            second with { Order = order + 1, AppliedAtUtc = null },
        };

        foreach (var rule in updated)
        {
            var at = _rules.FindIndex(r => r.Id == rule.Id);
            _rules[at] = rule;
        }

        PendingUndo = null; // A reorder touches two rules; undo covers single edits only.
        Changed?.Invoke(this, EventArgs.Empty);
        return updated;
    }

    public RoutingRule? SetEnabled(Guid id, bool enabled)
    {
        var index = _rules.FindIndex(r => r.Id == id);
        if (index < 0)
        {
            return null;
        }

        var updated = _rules[index] with { Enabled = enabled, AppliedAtUtc = null };
        PendingUndo = new RuleUndo(updated.Name, _rules[index], updated);
        _rules[index] = updated;
        Changed?.Invoke(this, EventArgs.Empty);
        return updated;
    }

    /// <summary>Takes back the last edit and reports what has to happen in the kernel.</summary>
    public RuleUndo? Undo()
    {
        if (PendingUndo is not { } undo)
        {
            return null;
        }

        PendingUndo = null;
        if (undo.Current is not null)
        {
            _rules.RemoveAll(r => r.Id == undo.Current.Id);
        }

        if (undo.Previous is not null)
        {
            _rules.Add(undo.Previous with { AppliedAtUtc = null });
        }

        Changed?.Invoke(this, EventArgs.Empty);
        return undo;
    }

    public void ClearUndo() => PendingUndo = null;

    private static bool SameSubject(RoutingRule a, RoutingRule b)
    {
        if (a.Process.Kind != b.Process.Kind)
        {
            return false;
        }

        // Two rules on the same process but different destinations are not the same subject:
        // replacing one with the other would throw away a constraint the user asked for.
        if (a.Destination != b.Destination)
        {
            return false;
        }

        return a.Process.Kind switch
        {
            ProcessSelectorKind.Instance =>
                a.Process.Identity is not null && b.Process.Identity is not null &&
                a.Process.Identity.Matches(b.Process.Identity),
            ProcessSelectorKind.ExecutablePath =>
                string.Equals(a.Process.ExecutablePath, b.Process.ExecutablePath, StringComparison.Ordinal) &&
                string.Equals(a.Process.WineTargetExecutable, b.Process.WineTargetExecutable, StringComparison.Ordinal),
            ProcessSelectorKind.ProcessName =>
                string.Equals(a.Process.ProcessName, b.Process.ProcessName, StringComparison.Ordinal),
            _ => false,
        };
    }

    /// <summary>
    /// Drops instance rules whose process has exited.
    /// </summary>
    /// <remarks>
    /// This is the app-side half of the PID-reuse guarantee. The daemon enforces the same
    /// thing against the kernel; both sides key on pid + start time, never on pid alone.
    /// </remarks>
    public void ExpireInstanceRulesFor(string rowKey)
    {
        var removed = _rules.RemoveAll(r =>
            r.Lifetime == RuleLifetime.Instance &&
            r.Process.Identity is { } identity &&
            ProcessRowViewModel.MakeKey(identity) == rowKey);

        if (removed > 0)
        {
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>Finds a removable override covering this process, if any.</summary>
    public RoutingRule? FindOverrideFor(ProcessSnapshot process) =>
        Rules.FirstOrDefault(r => r.IsTemporaryOverride && r.Process.MatchesProcess(process));

    /// <summary>Every rule that covers a process, in evaluation order.</summary>
    public IReadOnlyList<RoutingRule> RulesFor(ProcessSnapshot process) =>
        Rules.Where(r => r.Process.Kind != ProcessSelectorKind.Any && r.Process.MatchesProcess(process)).ToArray();

    /// <summary>
    /// Works out how a process's current policy should be labelled.
    /// </summary>
    /// <remarks>
    /// Reports the rule that would win for a *new* connection with no destination constraint.
    /// It says nothing about connections already open — the Connections page is the only place
    /// that claims a flow is proxied, and only when it has observed it.
    /// </remarks>
    public (PolicyKind Kind, string? Detail) DescribePolicy(ProcessSnapshot process)
    {
        var match = Rules.FirstOrDefault(r =>
            r.Enabled && r.Process.Kind != ProcessSelectorKind.Any && r.Process.MatchesProcess(process));
        if (match is null)
        {
            return (PolicyKind.Direct, null);
        }

        if (match.AppliedAtUtc is null)
        {
            return (PolicyKind.Pending, match.Name);
        }

        return match.Action switch
        {
            RuleAction.Block => (PolicyKind.Blocked, null),
            RuleAction.Proxy p => (PolicyKind.Proxied, Proxies.FirstOrDefault(x => x.Id == p.EndpointId)?.Name),
            RuleAction.Chain c => (PolicyKind.Proxied, Chains.FirstOrDefault(x => x.Id == c.ChainId)?.Name),
            _ => (PolicyKind.Direct, null),
        };
    }

    /// <summary>Turns a UI selection into a rule, without widening what the user asked for.</summary>
    public RoutingRule BuildRule(
        ProcessSnapshot process,
        RuleScopeChoice scope,
        RuleAction action,
        bool includeChildren,
        DestinationSelector? destination = null)
    {
        var descendants = includeChildren ? DescendantPolicy.IncludeFuture : DescendantPolicy.Exclude;

        var selector = scope switch
        {
            RuleScopeChoice.Executable => new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = process.ExecutablePath,
                Descendants = descendants,
                // Carrying the Wine target keeps a rule on a shared runtime binary from
                // reaching other games using the same runtime.
                WineTargetExecutable = process.Wine?.TargetExecutable,
                WinePrefix = process.Wine?.Prefix,
            },
            RuleScopeChoice.Tree => new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = process.Identity,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
                WineTargetExecutable = process.Wine?.TargetExecutable,
                WinePrefix = process.Wine?.Prefix,
            },
            _ => new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = process.Identity,
                Descendants = descendants,
                WineTargetExecutable = process.Wine?.TargetExecutable,
                WinePrefix = process.Wine?.Prefix,
            },
        };

        return new RoutingRule
        {
            Id = Guid.NewGuid(),
            Order = NextOrder(RuleOrigin.ProcessSelection),
            Name = DescribeRuleName(process, scope),
            Origin = RuleOrigin.ProcessSelection,
            Lifetime = scope == RuleScopeChoice.Executable ? RuleLifetime.Persistent : RuleLifetime.Instance,
            Process = selector,
            Destination = destination ?? DestinationSelector.Any,
            Action = action,
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>
    /// The next order value in an origin's band.
    /// </summary>
    /// <remarks>
    /// Process selections sit above game profiles by default, so an explicit choice the user
    /// just made is never silently overridden by a background profile. Both sit above rules
    /// typed on the Rules page, which are the broad ones.
    /// </remarks>
    public int NextOrder(RuleOrigin origin)
    {
        var band = origin switch
        {
            RuleOrigin.ProcessSelection => ProcessSelectionBand,
            RuleOrigin.GameProfile => GameProfileBand,
            _ => ManualBand,
        };

        var used = _rules.Where(r => r.Origin == origin).Select(r => r.Order).ToList();
        return used.Count == 0 ? band : Math.Max(band, used.Max() + 1);
    }

    private static string DescribeRuleName(ProcessSnapshot process, RuleScopeChoice scope) => scope switch
    {
        RuleScopeChoice.Instance => $"{process.DisplayName} (pid {process.Identity.Pid})",
        RuleScopeChoice.Executable => $"{process.DisplayName} (all instances)",
        _ => $"{process.DisplayName} and children",
    };
}
