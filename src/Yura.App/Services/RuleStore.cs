using System.Collections.ObjectModel;
using Yura.App.ViewModels;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

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
    private readonly List<RoutingRule> _rules = [];

    public ObservableCollection<ProxyEndpoint> Proxies { get; } = [];

    public IReadOnlyList<RoutingRule> Rules => RuleEvaluator.Sort(_rules);

    public event EventHandler? Changed;

    public void Add(RoutingRule rule)
    {
        // A new selection for the same process replaces the previous one rather than
        // stacking, so the effective policy is never the result of two competing overrides.
        _rules.RemoveAll(r => r.Origin == rule.Origin && SameSubject(r, rule));
        _rules.Add(rule);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(Guid id)
    {
        _rules.RemoveAll(r => r.Id == id);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    private static bool SameSubject(RoutingRule a, RoutingRule b)
    {
        if (a.Process.Kind != b.Process.Kind)
        {
            return false;
        }

        return a.Process.Kind switch
        {
            ProcessSelectorKind.Instance =>
                a.Process.Identity is not null && b.Process.Identity is not null &&
                a.Process.Identity.Matches(b.Process.Identity),
            ProcessSelectorKind.ExecutablePath =>
                string.Equals(a.Process.ExecutablePath, b.Process.ExecutablePath, StringComparison.Ordinal),
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

    /// <summary>
    /// Works out how a process's current policy should be labelled.
    /// </summary>
    /// <remarks>
    /// Reports the rule that would win for a *new* connection. It says nothing about
    /// connections already open — the Connections page is the only place that claims a flow
    /// is proxied, and only when it has observed it.
    /// </remarks>
    public (PolicyKind Kind, string? Detail) DescribePolicy(ProcessSnapshot process)
    {
        var match = Rules.FirstOrDefault(r => r.Enabled && r.Process.MatchesProcess(process));
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
            RuleAction.Chain => (PolicyKind.Proxied, match.Name),
            _ => (PolicyKind.Direct, null),
        };
    }

    /// <summary>Turns a UI selection into a rule, without widening what the user asked for.</summary>
    public RoutingRule BuildRule(
        ProcessSnapshot process,
        RuleScopeChoice scope,
        RuleAction action,
        bool includeChildren)
    {
        var selector = scope switch
        {
            RuleScopeChoice.Instance => new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = process.Identity,
                Descendants = includeChildren ? DescendantPolicy.IncludeFuture : DescendantPolicy.Exclude,
                // Carrying the Wine target keeps a rule on a shared runtime binary from
                // reaching other games using the same runtime.
                WineTargetExecutable = process.Wine?.TargetExecutable,
                WinePrefix = process.Wine?.Prefix,
            },
            RuleScopeChoice.Executable => new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = process.ExecutablePath,
                Descendants = includeChildren ? DescendantPolicy.IncludeFuture : DescendantPolicy.Exclude,
                WineTargetExecutable = process.Wine?.TargetExecutable,
                WinePrefix = process.Wine?.Prefix,
            },
            _ => new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = process.Identity,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
                WineTargetExecutable = process.Wine?.TargetExecutable,
                WinePrefix = process.Wine?.Prefix,
            },
        };

        return new RoutingRule
        {
            Id = Guid.NewGuid(),
            Order = NextOrder(),
            Name = DescribeRuleName(process, scope),
            Origin = RuleOrigin.ProcessSelection,
            Lifetime = scope == RuleScopeChoice.Executable ? RuleLifetime.Persistent : RuleLifetime.Instance,
            Process = selector,
            Destination = DestinationSelector.Any,
            Action = action,
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>
    /// Process selections go above game profiles by default, so an explicit choice the user
    /// just made is never silently overridden by a background profile.
    /// </summary>
    private int NextOrder()
    {
        const int ProcessSelectionBand = 100;
        var used = _rules.Where(r => r.Origin == RuleOrigin.ProcessSelection).Select(r => r.Order).ToList();
        return used.Count == 0 ? ProcessSelectionBand : used.Max() + 1;
    }

    private static string DescribeRuleName(ProcessSnapshot process, RuleScopeChoice scope) => scope switch
    {
        RuleScopeChoice.Instance => $"{process.DisplayName} (pid {process.Identity.Pid})",
        RuleScopeChoice.Executable => $"{process.DisplayName} (all instances)",
        _ => $"{process.DisplayName} and children",
    };
}
