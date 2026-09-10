using Yura.Core.Processes;

namespace Yura.Core.Rules;

/// <summary>How a rule decides which processes it covers.</summary>
public enum ProcessSelectorKind
{
    /// <summary>Matches every process. Used by destination-only rules.</summary>
    Any,

    /// <summary>
    /// Matches exactly one running instance, keyed on pid + start time + uid.
    /// Never widens to other instances of the same executable.
    /// </summary>
    Instance,

    /// <summary>Matches any process whose resolved <c>/proc/[pid]/exe</c> equals a path.</summary>
    ExecutablePath,

    /// <summary>
    /// Matches on the process name only. Deliberately broader than
    /// <see cref="ExecutablePath"/> and only ever set when the user explicitly asks for it.
    /// </summary>
    ProcessName,

    /// <summary>Matches every process owned by a uid.</summary>
    User,
}

/// <summary>What to do about a matched process's children.</summary>
public enum DescendantPolicy
{
    /// <summary>Only the matched process itself. Children keep whatever policy they had.</summary>
    Exclude,

    /// <summary>
    /// Children forked after the rule is applied are covered; already-running children keep
    /// their current route. This is what cgroup membership gives us for free, because a
    /// forked child inherits its parent's cgroup.
    /// </summary>
    IncludeFuture,

    /// <summary>
    /// Children forked after the rule is applied are covered, and descendants that were
    /// already running when the rule was applied are migrated as well. Migrating an existing
    /// child does not change sockets it has already opened.
    /// </summary>
    IncludeExistingAndFuture,
}

/// <summary>The process side of a rule's match condition.</summary>
public sealed record ProcessSelector
{
    public static readonly ProcessSelector Any = new() { Kind = ProcessSelectorKind.Any };

    public required ProcessSelectorKind Kind { get; init; }

    /// <summary>Set when <see cref="Kind"/> is <see cref="ProcessSelectorKind.Instance"/>.</summary>
    public ProcessIdentity? Identity { get; init; }

    /// <summary>
    /// Set for <see cref="ProcessSelectorKind.ExecutablePath"/>. Compared against the
    /// resolved target of <c>/proc/[pid]/exe</c>, so symlinked launchers match their target.
    /// </summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Set for <see cref="ProcessSelectorKind.ProcessName"/>.</summary>
    public string? ProcessName { get; init; }

    /// <summary>Set for <see cref="ProcessSelectorKind.User"/>.</summary>
    public uint? Uid { get; init; }

    public DescendantPolicy Descendants { get; init; } = DescendantPolicy.Exclude;

    /// <summary>
    /// For Wine/Proton: additionally require that the process is running this Windows
    /// executable. Without it, a rule on <c>wine-preloader</c> would capture every other
    /// Wine application on the system, which the specification forbids.
    /// </summary>
    public string? WineTargetExecutable { get; init; }

    /// <summary>Restrict to a single Wine prefix, distinguishing two copies of one game.</summary>
    public string? WinePrefix { get; init; }

    /// <summary>True when the selector covers exactly one process instance and cannot widen.</summary>
    public bool IsInstanceScoped => Kind == ProcessSelectorKind.Instance;

    /// <summary>
    /// Evaluates the process side of the rule against a snapshot.
    /// </summary>
    /// <remarks>
    /// Descendant handling is deliberately absent here. Membership of a process tree is
    /// decided by the classifier (cgroup membership), not by walking parent pids at match
    /// time, because a walk would race with re-parenting when an intermediate process exits.
    /// </remarks>
    public bool MatchesProcess(ProcessSnapshot process)
    {
        if (!MatchesWine(process))
        {
            return false;
        }

        return Kind switch
        {
            ProcessSelectorKind.Any => true,
            ProcessSelectorKind.Instance =>
                Identity is not null && Identity.Matches(process.Identity),
            ProcessSelectorKind.ExecutablePath =>
                ExecutablePath is not null &&
                process.ExecutablePath is not null &&
                string.Equals(ExecutablePath, process.ExecutablePath, StringComparison.Ordinal),
            ProcessSelectorKind.ProcessName =>
                ProcessName is not null &&
                (string.Equals(ProcessName, process.Name, StringComparison.Ordinal) ||
                 string.Equals(ProcessName, Path.GetFileName(process.ExecutablePath), StringComparison.Ordinal)),
            ProcessSelectorKind.User => Uid == process.Identity.Uid,
            _ => false,
        };
    }

    private bool MatchesWine(ProcessSnapshot process)
    {
        if (WineTargetExecutable is { Length: > 0 } target)
        {
            var actual = process.Wine?.TargetExecutable;
            if (actual is null || !string.Equals(target, actual, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        if (WinePrefix is { Length: > 0 } prefix)
        {
            var actual = process.Wine?.Prefix;
            if (actual is null || !string.Equals(prefix, actual, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>One-line description used in the rule list and in match explanations.</summary>
    public string Describe() => Kind switch
    {
        ProcessSelectorKind.Any => "Any process",
        ProcessSelectorKind.Instance => Identity is null
            ? "Instance (unresolved)"
            : $"Instance {Identity.ToShortString()}",
        ProcessSelectorKind.ExecutablePath => $"Path {ExecutablePath}",
        ProcessSelectorKind.ProcessName => $"Name {ProcessName}",
        ProcessSelectorKind.User => $"User {Uid}",
        _ => Kind.ToString(),
    };
}
