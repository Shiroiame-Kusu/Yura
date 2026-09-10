namespace Yura.Core.Processes;

/// <summary>
/// Identifies one concrete running process instance.
/// </summary>
/// <remarks>
/// A bare PID is not an identity: the kernel reuses PIDs, and a rule written against a
/// PID alone would silently transfer to an unrelated process once the number came round
/// again. <see cref="StartTicks"/> (field 22 of <c>/proc/[pid]/stat</c>, the process start
/// time in clock ticks since boot) makes the pair unique for the lifetime of a boot, and
/// <see cref="BootId"/> makes it unique across boots so that persisted diagnostics can
/// never be misread after a restart.
///
/// Every consumer that acts on an instance rule must re-verify the identity immediately
/// before acting. See <see cref="Matches"/>.
/// </remarks>
public sealed record ProcessIdentity
{
    /// <summary>Process id as reported by the kernel.</summary>
    public required int Pid { get; init; }

    /// <summary>
    /// Process start time in clock ticks since boot (<c>/proc/[pid]/stat</c> field 22).
    /// Together with <see cref="Pid"/> and <see cref="BootId"/> this is the instance key.
    /// </summary>
    public required ulong StartTicks { get; init; }

    /// <summary>Real user id owning the process. Part of the identity, never rewritten.</summary>
    public required uint Uid { get; init; }

    /// <summary>
    /// Contents of <c>/proc/sys/kernel/random/boot_id</c> at the time the identity was
    /// captured. Guards against a persisted identity being matched after a reboot.
    /// </summary>
    public required string BootId { get; init; }

    /// <summary>
    /// True when <paramref name="other"/> describes the same process instance.
    /// </summary>
    /// <remarks>
    /// This is the single place PID reuse is defended against. Callers must use it rather
    /// than comparing PIDs, and must call it against freshly read <c>/proc</c> data rather
    /// than against a cached snapshot.
    /// </remarks>
    public bool Matches(ProcessIdentity other) =>
        Pid == other.Pid &&
        StartTicks == other.StartTicks &&
        Uid == other.Uid &&
        string.Equals(BootId, other.BootId, StringComparison.Ordinal);

    /// <summary>Stable short form for logs and rule explanations, e.g. <c>4821@193847231</c>.</summary>
    public string ToShortString() => $"{Pid}@{StartTicks}";

    public override string ToString() => $"pid {Pid} (start {StartTicks}, uid {Uid})";
}
