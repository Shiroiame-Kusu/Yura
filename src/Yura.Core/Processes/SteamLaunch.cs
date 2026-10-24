namespace Yura.Core.Processes;

/// <summary>
/// Recognises Steam's launch of a game: the one process Steam starts every game through.
/// </summary>
/// <remarks>
/// <para>
/// Steam runs every game, native or Proton, as <c>reaper SteamLaunch AppId=&lt;id&gt; -- &lt;command&gt;</c>,
/// and everything the game runs descends from that process, Proton's wineserver included. A rule
/// on it routes the whole game from birth.
/// </para>
/// <para>
/// The app id is the one part of that command line a game's update cannot change. The command
/// after <c>--</c> names whatever Steam was told to start, and that changes: Helldivers 2 went
/// from <c>bin\helldivers2.exe</c> to Easy Anti-Cheat's <c>start_protected_game.exe</c>, and a rule
/// keyed on the executable Steam named matched nothing from that update on.
/// </para>
/// </remarks>
public static class SteamLaunch
{
    /// <summary>The file name of the program Steam launches games through.</summary>
    public const string LauncherName = "reaper";

    private const string AppIdArgument = "AppId=";

    /// <summary>The app id a command line launches, or null when it is not Steam's launch of one.</summary>
    public static string? AppIdOf(IReadOnlyList<string> commandLine)
    {
        if (commandLine.Count < 3 || !string.Equals(commandLine[1], "SteamLaunch", StringComparison.Ordinal))
        {
            return null;
        }

        // Steam's own arguments come before the "--"; everything after it is the game's, which
        // could carry anything at all.
        for (var i = 2; i < commandLine.Count && !string.Equals(commandLine[i], "--", StringComparison.Ordinal); i++)
        {
            var argument = commandLine[i];
            if (argument.StartsWith(AppIdArgument, StringComparison.Ordinal) &&
                argument.Length > AppIdArgument.Length &&
                argument.AsSpan(AppIdArgument.Length).IndexOfAnyExceptInRange('0', '9') < 0)
            {
                return argument[AppIdArgument.Length..];
            }
        }

        return null;
    }

    /// <summary>
    /// The app id in a raw <c>/proc/[pid]/cmdline</c>, whose arguments are separated by NULs.
    /// </summary>
    public static string? AppIdOf(string rawCommandLine) =>
        rawCommandLine.Contains("SteamLaunch", StringComparison.Ordinal)
            ? AppIdOf(rawCommandLine.Split('\0', StringSplitOptions.RemoveEmptyEntries))
            : null;

    /// <summary>Whether a path is Steam's launcher, which is what a launch was once remembered by.</summary>
    public static bool IsLauncher(string? executablePath) =>
        executablePath is { Length: > 0 } &&
        string.Equals(Path.GetFileName(executablePath), LauncherName, StringComparison.Ordinal);
}
