using System.Globalization;
using Yura.Core.Processes;

namespace Yura.Daemon.Linux;

/// <summary>Why a migration attempt did not happen.</summary>
public enum MigrationOutcome
{
    Migrated,

    /// <summary>The process exited between selection and the write.</summary>
    ProcessGone,

    /// <summary>
    /// The pid still exists but is no longer the instance we were asked about: the start
    /// time changed, so the kernel handed the number to something else.
    /// </summary>
    IdentityChanged,

    /// <summary>The kernel refused the write.</summary>
    Refused,
}

public sealed record MigrationResult(MigrationOutcome Outcome, string? Detail = null)
{
    public bool Succeeded => Outcome == MigrationOutcome.Migrated;
}

/// <summary>
/// Owns Yura's cgroup v2 subtree and the live migration of processes into it.
/// </summary>
/// <remarks>
/// This is the piece that makes running-process selection possible at all: writing a pid to
/// <c>cgroup.procs</c> moves an already-running process with no restart, no wrapper and no
/// change to the user it runs as.
///
/// Every cgroup here is a direct child of <see cref="Root"/>, which is a top-level cgroup
/// that systemd does not manage. Nesting under the process's existing slice would keep
/// systemd's accounting intact, but collides with cgroup v2's "no internal processes" rule
/// once controllers are enabled on the parent. The trade-off is documented rather than
/// hidden: a migrated process leaves its systemd scope, so `systemctl --user stop` no longer
/// reaches it by cgroup.
/// </remarks>
public sealed class CgroupManager
{
    /// <summary>Top-level cgroup that holds one child per active rule slot.</summary>
    public const string Root = "/sys/fs/cgroup/yura";

    private const string CgroupMount = "/sys/fs/cgroup";

    private readonly Action<string> _log;
    private readonly ProcProcessSource _processes;

    public CgroupManager(Action<string> log, ProcProcessSource processes)
    {
        _log = log;
        _processes = processes;
    }

    /// <summary>Path of the cgroup backing a slot, e.g. <c>/sys/fs/cgroup/yura/s01</c>.</summary>
    public static string PathFor(string slotName) => $"{Root}/{slotName}";

    /// <summary>
    /// Path relative to the cgroup mount, which is the form nftables wants.
    /// </summary>
    public static string RelativePathFor(string slotName) => $"yura/{slotName}";

    /// <summary>Depth of <see cref="RelativePathFor"/>, for nftables' <c>level</c> argument.</summary>
    public const int Level = 2;

    public static bool IsCgroup2Available() =>
        Directory.Exists(CgroupMount) && File.Exists($"{CgroupMount}/cgroup.controllers");

    public void EnsureRoot()
    {
        if (!Directory.Exists(Root))
        {
            Directory.CreateDirectory(Root);
            _log($"created cgroup root {Root}");
        }
    }

    public void CreateSlot(string slotName)
    {
        EnsureRoot();
        var path = PathFor(slotName);
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
            _log($"created cgroup {path}");
        }
    }

    /// <summary>
    /// Removes a slot's cgroup, returning any remaining members to the root cgroup first.
    /// </summary>
    /// <remarks>
    /// A non-empty cgroup cannot be removed, and leaving one behind is worse than it looks:
    /// nftables resolved its path to a cgroup id at rule-load time, so a stale directory that
    /// is later recreated will not match the installed rules.
    /// </remarks>
    public void RemoveSlot(string slotName)
    {
        var path = PathFor(slotName);
        if (!Directory.Exists(path))
        {
            return;
        }

        foreach (var pid in ReadMembers(slotName))
        {
            EvictToRoot(pid);
        }

        try
        {
            Directory.Delete(path);
            _log($"removed cgroup {path}");
        }
        catch (IOException e)
        {
            _log($"could not remove cgroup {path}: {e.Message}");
        }
    }

    public IReadOnlyList<int> ReadMembers(string slotName)
    {
        var file = $"{PathFor(slotName)}/cgroup.procs";
        try
        {
            return File.ReadAllLines(file)
                .Where(line => line.Length > 0)
                .Select(line => int.TryParse(line, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) ? pid : -1)
                .Where(pid => pid > 0)
                .ToArray();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>
    /// Moves a running process into a slot, but only if it is still the instance we were
    /// asked about.
    /// </summary>
    /// <remarks>
    /// The identity re-check immediately before the write is the entire PID-reuse defence.
    /// There is still a theoretical window between the check and the write; it is one
    /// syscall wide, and closing it properly needs pidfd, which is a later refinement. What
    /// matters is that the check is never skipped and never done against a cached snapshot.
    /// </remarks>
    public MigrationResult Migrate(string slotName, ProcessIdentity expected)
    {
        var current = _processes.TryRead(expected.Pid);
        if (current is null)
        {
            return new MigrationResult(MigrationOutcome.ProcessGone,
                $"pid {expected.Pid} no longer exists");
        }

        if (!expected.Matches(current.Identity))
        {
            return new MigrationResult(MigrationOutcome.IdentityChanged,
                $"pid {expected.Pid} is a different process now " +
                $"(start ticks {current.Identity.StartTicks}, expected {expected.StartTicks})");
        }

        CreateSlot(slotName);

        try
        {
            File.WriteAllText($"{PathFor(slotName)}/cgroup.procs",
                expected.Pid.ToString(CultureInfo.InvariantCulture));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // ESRCH here means the process exited during the write, which is ordinary.
            return Directory.Exists($"/proc/{expected.Pid}")
                ? new MigrationResult(MigrationOutcome.Refused, e.Message)
                : new MigrationResult(MigrationOutcome.ProcessGone, $"pid {expected.Pid} exited during migration");
        }

        _log($"migrated pid {expected.Pid} ({current.DisplayName}) into {RelativePathFor(slotName)}");
        return new MigrationResult(MigrationOutcome.Migrated);
    }

    /// <summary>Moves a process back to the root cgroup, undoing a migration.</summary>
    public bool EvictToRoot(int pid)
    {
        try
        {
            File.WriteAllText($"{CgroupMount}/cgroup.procs", pid.ToString(CultureInfo.InvariantCulture));
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The process exiting on its own is the common case and needs no reporting.
            return false;
        }
    }

    /// <summary>Removes every slot cgroup Yura created, used on shutdown.</summary>
    public void RemoveAllSlots()
    {
        if (!Directory.Exists(Root))
        {
            return;
        }

        foreach (var directory in Directory.EnumerateDirectories(Root))
        {
            RemoveSlot(Path.GetFileName(directory));
        }

        try
        {
            Directory.Delete(Root);
        }
        catch (IOException)
        {
            // Something is still in it; leaving the empty root behind is harmless.
        }
    }
}
