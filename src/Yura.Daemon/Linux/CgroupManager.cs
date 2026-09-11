using System.Collections.Concurrent;
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
/// once controllers are enabled on the parent. The compromise is to remember where every
/// process came from and put it back there when its rule goes away, so leaving Yura's tree
/// returns the process to its systemd scope rather than dumping it in the root cgroup.
/// </remarks>
public sealed class CgroupManager
{
    /// <summary>Top-level cgroup that holds one child per process group.</summary>
    public const string Root = "/sys/fs/cgroup/yura";

    private const string CgroupMount = "/sys/fs/cgroup";

    /// <summary>Depth of <see cref="RelativePathFor"/>, for nftables' <c>level</c> argument.</summary>
    public const int Level = 2;

    private readonly Action<string> _log;
    private readonly ProcProcessSource _processes;

    /// <summary>Where each migrated process lived before Yura moved it, keyed by pid.</summary>
    private readonly ConcurrentDictionary<int, string> _origins = new();

    /// <summary>Origin path to the directory it resolves to, so the fork hot path does no stat.</summary>
    private readonly ConcurrentDictionary<string, string> _resolvedOrigins = new();

    public CgroupManager(Action<string> log, ProcProcessSource processes)
    {
        _log = log;
        _processes = processes;
    }

    /// <summary>Path of the cgroup backing a group, e.g. <c>/sys/fs/cgroup/yura/g001</c>.</summary>
    public static string PathFor(string groupName) => $"{Root}/{groupName}";

    /// <summary>Path relative to the cgroup mount, which is the form nftables wants.</summary>
    public static string RelativePathFor(string groupName) => $"yura/{groupName}";

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

    public void CreateGroup(string groupName)
    {
        EnsureRoot();
        var path = PathFor(groupName);
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
            _log($"created cgroup {path}");
        }
    }

    public bool GroupExists(string groupName) => Directory.Exists(PathFor(groupName));

    /// <summary>
    /// Removes a group's cgroup, returning any remaining members to where they came from.
    /// </summary>
    /// <remarks>
    /// A non-empty cgroup cannot be removed, and leaving one behind is worse than it looks:
    /// nftables resolved its path to a cgroup id at rule-load time, so a stale directory that
    /// is later recreated will not match the installed rules.
    /// </remarks>
    public void RemoveGroup(string groupName)
    {
        var path = PathFor(groupName);
        if (!Directory.Exists(path))
        {
            return;
        }

        foreach (var pid in ReadMembers(groupName))
        {
            Restore(pid);
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

    public IReadOnlyList<int> ReadMembers(string groupName)
    {
        var file = $"{PathFor(groupName)}/cgroup.procs";
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

    /// <summary>Every group directory currently under the root.</summary>
    public IReadOnlyList<string> ListGroups()
    {
        if (!Directory.Exists(Root))
        {
            return [];
        }

        return Directory.EnumerateDirectories(Root).Select(Path.GetFileName).Where(n => n is not null).Select(n => n!).ToArray();
    }

    /// <summary>
    /// The unified-hierarchy cgroup path of a process, e.g. <c>/yura/g001</c>, or null if it
    /// cannot be read (exited, or not permitted).
    /// </summary>
    public static string? ReadCgroupOf(int pid)
    {
        try
        {
            foreach (var line in File.ReadLines($"/proc/{pid}/cgroup"))
            {
                if (line.StartsWith("0::", StringComparison.Ordinal))
                {
                    return line[3..];
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }

        return null;
    }

    /// <summary>The group name a process is currently in, or null when it is outside Yura's tree.</summary>
    public static string? GroupOf(int pid)
    {
        var path = ReadCgroupOf(pid);
        if (path is null || !path.StartsWith("/yura/", StringComparison.Ordinal))
        {
            return null;
        }

        var rest = path["/yura/".Length..];
        var slash = rest.IndexOf('/');
        return slash < 0 ? rest : rest[..slash];
    }

    /// <summary>
    /// Moves a running process into a group, but only if it is still the instance we were
    /// asked about.
    /// </summary>
    /// <remarks>
    /// The identity re-check immediately before the write is the entire PID-reuse defence.
    /// There is still a theoretical window between the check and the write; it is one
    /// syscall wide, and closing it properly needs pidfd, which is a later refinement. What
    /// matters is that the check is never skipped and never done against a cached snapshot.
    /// </remarks>
    public MigrationResult Migrate(string groupName, ProcessIdentity expected)
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

        return Move(groupName, expected.Pid, current.DisplayName);
    }

    /// <summary>
    /// Moves a process by pid alone. Only for processes the kernel just told us about (a fork
    /// or exec event), where the pid cannot have been reused yet.
    /// </summary>
    public MigrationResult Move(string groupName, int pid, string? displayName = null)
    {
        CreateGroup(groupName);

        // Remember the origin once; a process moved between Yura groups keeps its first home.
        if (!_origins.ContainsKey(pid))
        {
            var origin = ReadCgroupOf(pid);
            if (origin is not null && !origin.StartsWith("/yura/", StringComparison.Ordinal))
            {
                _origins[pid] = origin;
            }
        }

        try
        {
            File.WriteAllText($"{PathFor(groupName)}/cgroup.procs", pid.ToString(CultureInfo.InvariantCulture));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // ESRCH here means the process exited during the write, which is ordinary.
            return Directory.Exists($"/proc/{pid}")
                ? new MigrationResult(MigrationOutcome.Refused, e.Message)
                : new MigrationResult(MigrationOutcome.ProcessGone, $"pid {pid} exited during migration");
        }

        _log($"migrated pid {pid}{(displayName is null ? string.Empty : $" ({displayName})")} into {RelativePathFor(groupName)}");
        return new MigrationResult(MigrationOutcome.Migrated);
    }

    /// <summary>
    /// Writes a pid into an existing group and nothing else.
    /// </summary>
    /// <remarks>
    /// For the exec fast path, which runs on the kernel's event thread and is racing the
    /// process's first socket: a socket's cgroup is fixed when it is created, so anything this
    /// does not finish in time is a connection that leaves on the wrong route. One write, no
    /// directory creation, no <c>/proc</c> reads, no log line. The ordinary path runs a moment
    /// later and records everything properly.
    /// </remarks>
    public bool MoveFast(string groupName, int pid)
    {
        try
        {
            File.WriteAllText($"{PathFor(groupName)}/cgroup.procs", pid.ToString(CultureInfo.InvariantCulture));
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // ESRCH is the ordinary case: a program that lived for a millisecond. Nothing to
            // report, and the ordinary path will find it gone too.
            return false;
        }
    }

    /// <summary>
    /// Moves a process back to where it was before Yura touched it, falling back to the
    /// root cgroup if that place no longer exists.
    /// </summary>
    public bool Restore(int pid)
    {
        _origins.TryRemove(pid, out var origin);
        return RestoreTo(pid, origin, forget: false);
    }

    /// <summary>
    /// Moves a process to an explicit cgroup path, for a child that must leave a group it
    /// only inherited. Falls back to the root, which always accepts a write.
    /// </summary>
    public bool RestoreTo(int pid, string? origin, bool forget = true)
    {
        if (forget)
        {
            _origins.TryRemove(pid, out _);
        }

        var target = origin is not null && Directory.Exists(CgroupMount + origin)
            ? CgroupMount + origin
            : CgroupMount;

        try
        {
            File.WriteAllText($"{target}/cgroup.procs", pid.ToString(CultureInfo.InvariantCulture));
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The process exiting on its own is the common case and needs no reporting.
            // A refused write into the origin falls back to the root, which always accepts.
            if (target != CgroupMount)
            {
                try
                {
                    File.WriteAllText($"{CgroupMount}/cgroup.procs", pid.ToString(CultureInfo.InvariantCulture));
                    return true;
                }
                catch (Exception inner) when (inner is IOException or UnauthorizedAccessException)
                {
                }
            }

            return false;
        }
    }

    /// <summary>Where a process came from, when Yura moved it. Used to place excluded children.</summary>
    public string? OriginOf(int pid) => _origins.GetValueOrDefault(pid);

    /// <summary>
    /// The absolute directory a process should be returned to, resolved once.
    /// </summary>
    /// <remarks>
    /// Excluding a forked child is a race against that child creating a socket, so the hot
    /// path must not stat the filesystem. Resolving the parent's origin to a directory here,
    /// and caching it, leaves one write to do when the fork event arrives.
    /// </remarks>
    public string ResolvedOriginOf(int pid)
    {
        if (!_origins.TryGetValue(pid, out var origin))
        {
            return CgroupMount;
        }

        if (_resolvedOrigins.TryGetValue(origin, out var resolved))
        {
            return resolved;
        }

        resolved = Directory.Exists(CgroupMount + origin) ? CgroupMount + origin : CgroupMount;
        _resolvedOrigins[origin] = resolved;
        return resolved;
    }

    /// <summary>Writes a pid into an already-resolved cgroup directory, falling back to the root.</summary>
    public bool RestoreToResolved(int pid, string directory)
    {
        var text = pid.ToString(CultureInfo.InvariantCulture);
        try
        {
            File.WriteAllText($"{directory}/cgroup.procs", text);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            if (directory == CgroupMount)
            {
                return false;
            }
        }

        try
        {
            File.WriteAllText($"{CgroupMount}/cgroup.procs", text);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Records an origin explicitly, e.g. a child that inherits its parent's origin.</summary>
    public void RememberOrigin(int pid, string origin) => _origins.TryAdd(pid, origin);

    /// <summary>Drops bookkeeping for a process that has exited.</summary>
    public void Forget(int pid) => _origins.TryRemove(pid, out _);

    /// <summary>Removes every group cgroup Yura created, used on shutdown.</summary>
    public void RemoveAllGroups()
    {
        if (!Directory.Exists(Root))
        {
            return;
        }

        foreach (var directory in Directory.EnumerateDirectories(Root))
        {
            RemoveGroup(Path.GetFileName(directory));
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
