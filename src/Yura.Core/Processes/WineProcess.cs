namespace Yura.Core.Processes;

/// <summary>
/// The parts of Wine that decide which cgroup a Windows program's sockets are born in.
/// </summary>
/// <remarks>
/// <para>
/// Wine opens every socket a Windows program asks for inside the wineserver of the program's
/// prefix, and hands the program a copy. The socket is the wineserver's, and so is its cgroup,
/// which is fixed when a socket is created. A rule that places only the game therefore routes
/// none of its Winsock traffic.
/// </para>
/// <para>
/// Measured on Helldivers 2 under Proton: with the game's own process in a rule's group, the
/// route carried 38 Steam relay pings, made by Steam's native library inside the game, while all
/// eight of its HTTPS connections sat in Steam's cgroup, held by the game and the wineserver alike.
/// </para>
/// </remarks>
public static class WineProcess
{
    /// <summary>The executables that run a Windows program, across Wine's old and new layouts.</summary>
    private static readonly string[] LoaderNames = ["wine", "wine64", "wine-preloader", "wine64-preloader"];

    /// <summary>The file name of the process that serves one prefix.</summary>
    public const string ServerName = "wineserver";

    /// <summary>Whether a process is running a Windows program: its executable is one of Wine's loaders.</summary>
    /// <remarks>
    /// Not the same as having a Wine context. A process gets one for any <c>.exe</c> in its
    /// arguments, which Steam's reaper and Proton's scripts have; neither opens a socket for one.
    /// </remarks>
    public static bool IsLoader(string? executablePath) =>
        executablePath is { Length: > 0 } &&
        LoaderNames.Contains(Path.GetFileName(executablePath), StringComparer.Ordinal);

    /// <summary>Whether a process is a wineserver.</summary>
    public static bool IsServer(string? executablePath) =>
        executablePath is { Length: > 0 } &&
        string.Equals(Path.GetFileName(executablePath), ServerName, StringComparison.Ordinal);

    /// <summary>
    /// The prefix a Wine process works in, as Wine decides it: <c>WINEPREFIX</c>, or
    /// <c>~/.wine</c> when that is not set.
    /// </summary>
    /// <remarks>
    /// One prefix is often written two ways. Proton sets it with a trailing slash, and Wine strips
    /// trailing slashes before it looks for the prefix's server, so they are stripped here too.
    /// </remarks>
    public static string? PrefixFrom(string? winePrefix, string? home)
    {
        var prefix = winePrefix is { Length: > 0 }
            ? winePrefix
            : home is { Length: > 0 } ? home.TrimEnd('/') + "/.wine" : null;
        if (prefix is null)
        {
            return null;
        }

        var trimmed = prefix.TrimEnd('/');
        return trimmed.Length == 0 ? "/" : trimmed;
    }

    /// <summary>The prefix in a raw <c>/proc/[pid]/environ</c>, whose entries are separated by NULs.</summary>
    public static string? PrefixFromEnvironment(string environ)
    {
        string? prefix = null;
        string? home = null;
        foreach (var entry in environ.Split('\0', StringSplitOptions.RemoveEmptyEntries))
        {
            if (entry.StartsWith("WINEPREFIX=", StringComparison.Ordinal))
            {
                prefix = entry["WINEPREFIX=".Length..];
            }
            else if (entry.StartsWith("HOME=", StringComparison.Ordinal))
            {
                home = entry["HOME=".Length..];
            }
        }

        return PrefixFrom(prefix, home);
    }
}
