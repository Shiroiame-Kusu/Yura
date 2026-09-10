using System.Globalization;

namespace Yura.Core.Processes;

/// <summary>
/// Reads the live process table from <c>/proc</c>.
/// </summary>
/// <remarks>
/// Everything here degrades rather than throws. A desktop session contains processes owned
/// by other users and by the system, and the unprivileged app is not allowed to read all of
/// them; a process can also exit between the directory listing and any individual read.
/// Both are normal, so they produce a snapshot that says what is unknown and why, instead
/// of an exception or a blank cell.
/// </remarks>
public sealed class ProcProcessSource
{
    private const string ProcRoot = "/proc";

    private readonly string _bootId;
    private readonly Dictionary<uint, string> _userNames = [];

    public ProcProcessSource()
    {
        _bootId = ReadBootId();
    }

    /// <summary>Boot identifier used to scope instance identities to this boot.</summary>
    public string BootId => _bootId;

    /// <summary>Enumerates every process currently visible in <c>/proc</c>.</summary>
    public IReadOnlyList<ProcessSnapshot> Enumerate(bool includeKernelThreads = false)
    {
        var results = new List<ProcessSnapshot>(512);

        foreach (var directory in Directory.EnumerateDirectories(ProcRoot))
        {
            var leaf = Path.GetFileName(directory);
            if (leaf.Length == 0 || !char.IsAsciiDigit(leaf[0]) ||
                !int.TryParse(leaf, NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                continue;
            }

            var snapshot = TryRead(pid);
            if (snapshot is null)
            {
                continue;
            }

            if (!includeKernelThreads && snapshot.IsKernelThread)
            {
                continue;
            }

            results.Add(snapshot);
        }

        return results;
    }

    /// <summary>
    /// Reads one process, returning null if it has exited or is not visible.
    /// </summary>
    public ProcessSnapshot? TryRead(int pid)
    {
        var root = $"{ProcRoot}/{pid}";

        // /proc/[pid]/stat is the one file we cannot do without: it carries the start time
        // that turns a reusable pid into a stable instance identity.
        if (!TryReadStat(root, out var stat))
        {
            return null;
        }

        // The real uid comes from /proc/[pid]/status, which is world-readable. It is part of
        // the instance identity, so a process we cannot attribute is not listed at all
        // rather than listed with a guessed owner.
        if (!TryReadRealUid(root, out var uid))
        {
            return null;
        }

        var (exePath, pathState) = ResolveExecutable(root);
        var commandLine = ReadCommandLine(root);
        var comm = ReadTextOrNull($"{root}/comm")?.Trim() ?? stat.Comm;

        return new ProcessSnapshot
        {
            Identity = new ProcessIdentity
            {
                Pid = pid,
                StartTicks = stat.StartTicks,
                Uid = uid,
                BootId = _bootId,
            },
            Name = comm,
            ExecutablePath = exePath,
            ExecutablePathState = pathState,
            ParentPid = stat.ParentPid,
            UserName = ResolveUserName(uid),
            CommandLine = commandLine,
            CgroupPath = ReadCgroupPath(root),
            Wine = DetectWine(root, commandLine, exePath),
            ConnectionCount = null, // Filled in by the daemon, which owns socket ownership.
        };
    }

    // -- /proc/[pid]/stat ----------------------------------------------------

    private readonly record struct StatFields(string Comm, int ParentPid, ulong StartTicks);

    private static bool TryReadStat(string root, out StatFields fields)
    {
        fields = default;

        var text = ReadTextOrNull($"{root}/stat");
        if (text is null)
        {
            return false;
        }

        // Field 2 (comm) is wrapped in parentheses and may itself contain spaces and
        // parentheses — "(Web Content)", "(a) b". Splitting on whitespace corrupts every
        // field after it, so the only correct anchor is the LAST ')'.
        var close = text.LastIndexOf(')');
        var open = text.IndexOf('(');
        if (close < 0 || open < 0 || close < open)
        {
            return false;
        }

        var comm = text[(open + 1)..close];
        var rest = text[(close + 1)..].AsSpan().Trim();

        // 'rest' begins at field 3 (state). starttime is field 22, i.e. index 19 here.
        Span<Range> parts = stackalloc Range[24];
        var count = SplitAscii(rest, ' ', parts);
        if (count <= 19)
        {
            return false;
        }

        if (!int.TryParse(rest[parts[1]], NumberStyles.None, CultureInfo.InvariantCulture, out var ppid) ||
            !ulong.TryParse(rest[parts[19]], NumberStyles.None, CultureInfo.InvariantCulture, out var start))
        {
            return false;
        }

        fields = new StatFields(comm, ppid, start);
        return true;
    }

    private static int SplitAscii(ReadOnlySpan<char> text, char separator, Span<Range> ranges)
    {
        var count = 0;
        var start = 0;
        for (var i = 0; i <= text.Length && count < ranges.Length; i++)
        {
            if (i == text.Length || text[i] == separator)
            {
                if (i > start)
                {
                    ranges[count++] = new Range(start, i);
                }

                start = i + 1;
            }
        }

        return count;
    }

    // -- executable ----------------------------------------------------------

    private static (string? Path, ExecutablePathState State) ResolveExecutable(string root)
    {
        var link = $"{root}/exe";
        try
        {
            var target = File.ResolveLinkTarget(link, returnFinalTarget: false)?.FullName;
            if (target is null)
            {
                // Kernel threads have no exe link at all.
                return (null, ExecutablePathState.None);
            }

            // The kernel appends this marker when the backing file has been unlinked, which
            // happens routinely during package upgrades. The path is still meaningful, so we
            // keep it and flag the state rather than discarding it.
            const string DeletedSuffix = " (deleted)";
            if (target.EndsWith(DeletedSuffix, StringComparison.Ordinal))
            {
                return (target[..^DeletedSuffix.Length], ExecutablePathState.Deleted);
            }

            return (target, ExecutablePathState.Resolved);
        }
        catch (UnauthorizedAccessException)
        {
            return (null, ExecutablePathState.PermissionDenied);
        }
        catch (IOException)
        {
            return (null, ExecutablePathState.None);
        }
    }

    private static IReadOnlyList<string> ReadCommandLine(string root)
    {
        var raw = ReadTextOrNull($"{root}/cmdline");
        if (string.IsNullOrEmpty(raw))
        {
            return [];
        }

        return raw.Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }

    private static string? ReadCgroupPath(string root)
    {
        var text = ReadTextOrNull($"{root}/cgroup");
        if (text is null)
        {
            return null;
        }

        // Unified hierarchy lines look like "0::/user.slice/user-1000.slice/...".
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("0::", StringComparison.Ordinal))
            {
                return line[3..];
            }
        }

        return null;
    }

    // -- Wine / Proton -------------------------------------------------------

    private static readonly string[] WineRuntimeNames =
    [
        "wine", "wine64", "wine-preloader", "wine64-preloader", "wineserver", "proton",
    ];

    /// <summary>
    /// Recognises a Wine or Proton process and, crucially, works out which Windows
    /// executable it is actually running.
    /// </summary>
    /// <remarks>
    /// Without the target executable every Wine game on the system looks identical: they all
    /// run the same handful of runtime binaries. Rules keyed on the runtime path alone would
    /// capture unrelated games, which the specification explicitly forbids.
    /// </remarks>
    private static WineContext? DetectWine(string root, IReadOnlyList<string> commandLine, string? exePath)
    {
        var looksLikeWine =
            (exePath is not null && WineRuntimeNames.Contains(Path.GetFileName(exePath), StringComparer.Ordinal)) ||
            commandLine.Any(a => a.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

        if (!looksLikeWine)
        {
            return null;
        }

        var target = commandLine.FirstOrDefault(a => a.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

        string? prefix = null;
        string? steamAppId = null;

        // /proc/[pid]/environ is readable only for our own processes. That is fine: the
        // fields it provides are refinements, and their absence is recorded as "unknown"
        // rather than guessed.
        var environ = ReadTextOrNull($"{root}/environ");
        if (environ is not null)
        {
            foreach (var entry in environ.Split('\0', StringSplitOptions.RemoveEmptyEntries))
            {
                if (entry.StartsWith("WINEPREFIX=", StringComparison.Ordinal))
                {
                    prefix = entry["WINEPREFIX=".Length..];
                }
                else if (entry.StartsWith("SteamAppId=", StringComparison.Ordinal) ||
                         entry.StartsWith("SteamGameId=", StringComparison.Ordinal))
                {
                    steamAppId ??= entry[(entry.IndexOf('=', StringComparison.Ordinal) + 1)..];
                }
            }
        }

        if (target is null && prefix is null && steamAppId is null)
        {
            return null;
        }

        return new WineContext
        {
            TargetExecutable = target,
            Prefix = prefix,
            SteamAppId = steamAppId,
        };
    }

    // -- users ---------------------------------------------------------------

    private string ResolveUserName(uint uid)
    {
        if (_userNames.TryGetValue(uid, out var cached))
        {
            return cached;
        }

        var name = LookupPasswd(uid) ?? uid.ToString(CultureInfo.InvariantCulture);
        _userNames[uid] = name;
        return name;
    }

    private static string? LookupPasswd(uint uid)
    {
        try
        {
            foreach (var line in File.ReadLines("/etc/passwd"))
            {
                // name:passwd:uid:gid:gecos:dir:shell
                var first = line.IndexOf(':', StringComparison.Ordinal);
                if (first <= 0)
                {
                    continue;
                }

                var second = line.IndexOf(':', first + 1);
                if (second < 0)
                {
                    continue;
                }

                var third = line.IndexOf(':', second + 1);
                if (third < 0)
                {
                    continue;
                }

                if (uint.TryParse(line.AsSpan(second + 1, third - second - 1), out var parsed) && parsed == uid)
                {
                    return line[..first];
                }
            }
        }
        catch (IOException)
        {
            // Fall through to the numeric form.
        }

        return null;
    }

    /// <summary>
    /// Reads the real uid from the <c>Uid:</c> line of <c>/proc/[pid]/status</c>, which
    /// lists real, effective, saved-set and filesystem uids in that order.
    /// </summary>
    private static bool TryReadRealUid(string root, out uint uid)
    {
        uid = 0;
        var text = ReadTextOrNull($"{root}/status");
        if (text is null)
        {
            return false;
        }

        foreach (var line in text.Split('\n'))
        {
            if (!line.StartsWith("Uid:", StringComparison.Ordinal))
            {
                continue;
            }

            var fields = line.AsSpan(4).Trim();
            var end = fields.IndexOfAny(" \t".AsSpan());
            var real = end < 0 ? fields : fields[..end];
            return uint.TryParse(real, NumberStyles.None, CultureInfo.InvariantCulture, out uid);
        }

        return false;
    }

    // -- helpers -------------------------------------------------------------

    private static string? ReadTextOrNull(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Process exited, or we are not allowed to look. Both are expected.
            return null;
        }
    }

    private static string ReadBootId()
    {
        var value = ReadTextOrNull("/proc/sys/kernel/random/boot_id")?.Trim();
        return string.IsNullOrEmpty(value) ? "unknown-boot" : value;
    }
}
