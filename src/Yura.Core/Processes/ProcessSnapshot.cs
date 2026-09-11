namespace Yura.Core.Processes;

/// <summary>
/// How much of a process's executable path we were actually able to resolve.
/// </summary>
/// <remarks>
/// The UI must never present a guess as a fact, so the reason a path is missing travels
/// with the snapshot instead of being flattened into an empty string.
/// </remarks>
public enum ExecutablePathState
{
    /// <summary><c>/proc/[pid]/exe</c> resolved to a path that exists.</summary>
    Resolved,

    /// <summary>The link resolved but the target has been unlinked (upgrade, temp file).</summary>
    Deleted,

    /// <summary>We are not permitted to read the link. Shown as "Permission denied", never blank.</summary>
    PermissionDenied,

    /// <summary>Kernel thread or otherwise pathless process.</summary>
    None,
}

/// <summary>Best-effort classification of a Wine/Proton process.</summary>
public sealed record WineContext
{
    /// <summary>The Windows executable the Wine process is actually running, when known.</summary>
    public string? TargetExecutable { get; init; }

    /// <summary>Value of <c>WINEPREFIX</c> for the process, when readable.</summary>
    public string? Prefix { get; init; }
}

/// <summary>
/// One row of the Processes page: everything we know about a process at one instant.
/// </summary>
public sealed record ProcessSnapshot
{
    public required ProcessIdentity Identity { get; init; }

    /// <summary>Comm name from the kernel (<c>/proc/[pid]/comm</c>), max 15 chars.</summary>
    public required string Name { get; init; }

    /// <summary>Resolved target of <c>/proc/[pid]/exe</c>, or null when unresolvable.</summary>
    public string? ExecutablePath { get; init; }

    public required ExecutablePathState ExecutablePathState { get; init; }

    /// <summary>Parent pid from <c>/proc/[pid]/stat</c>. Zero once reparented to init.</summary>
    public required int ParentPid { get; init; }

    /// <summary>Resolved user name, falling back to the numeric uid when unresolvable.</summary>
    public required string UserName { get; init; }

    /// <summary>Full argv, already split. Empty for kernel threads.</summary>
    public IReadOnlyList<string> CommandLine { get; init; } = [];

    /// <summary>Unified cgroup v2 path relative to the cgroup root, e.g. <c>/user.slice/...</c>.</summary>
    public string? CgroupPath { get; init; }

    /// <summary>
    /// Number of currently tracked sockets owned by this process, or null when the count
    /// could not be determined. Null renders as "Unavailable", never as 0.
    /// </summary>
    public int? ConnectionCount { get; init; }

    /// <summary>Set when the process was recognised as a Wine or Proton process.</summary>
    public WineContext? Wine { get; init; }

    /// <summary>
    /// The Steam app id from the process's environment, for anything Steam launched.
    /// </summary>
    /// <remarks>
    /// Not part of <see cref="Wine"/>: Steam sets this for native Linux games too, and those
    /// have no Wine context at all. Keeping it here is what lets a native game be recognised
    /// rather than only Proton ones.
    /// </remarks>
    public string? SteamAppId { get; init; }

    /// <summary>True when the process is a kernel thread (no executable, no network).</summary>
    public bool IsKernelThread => ExecutablePathState == ExecutablePathState.None && ParentPid is 0 or 2;

    /// <summary>
    /// The name to show in the process list: the Wine target when this is a Wine process,
    /// otherwise the executable's file name, otherwise the kernel comm name.
    /// </summary>
    public string DisplayName =>
        Wine?.TargetExecutable is { Length: > 0 } wineTarget
            ? Path.GetFileName(wineTarget)
            : ExecutablePath is { Length: > 0 } exe
                ? Path.GetFileName(exe)
                : Name;
}
