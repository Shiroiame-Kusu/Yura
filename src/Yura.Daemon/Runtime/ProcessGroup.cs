namespace Yura.Daemon.Runtime;

/// <summary>
/// One cgroup: the set of processes that are covered by exactly the same set of rules.
/// </summary>
/// <remarks>
/// A process can live in only one cgroup, but several rules may cover it — an instance rule
/// and an executable rule on the same program, say, with different destination facets. If
/// each rule owned a cgroup, the process could only satisfy one of them and first-match
/// evaluation would silently break for the others. Grouping by rule *set* instead means the
/// ruleset can emit every rule's match against every group that contains it, in rule order,
/// and the kernel then evaluates exactly what the rule list says.
/// </remarks>
public sealed record ProcessGroup
{
    public required int Index { get; init; }

    /// <summary>Ids of every rule whose process side covers this group's members.</summary>
    public required IReadOnlySet<Guid> RuleIds { get; init; }

    /// <summary>cgroup directory name, e.g. <c>g007</c>.</summary>
    public string Name => $"g{Index:D3}";

    /// <summary>Canonical key for a rule set, so equal sets map to the same group.</summary>
    public static string KeyFor(IEnumerable<Guid> ruleIds) =>
        string.Join(',', ruleIds.Select(id => id.ToString("N")).Order(StringComparer.Ordinal));

    public string Key => KeyFor(RuleIds);
}
