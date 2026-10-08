namespace Yura.Core.Games;

/// <summary>How Yura came to know about a game.</summary>
public enum GameSource
{
    /// <summary>Read from a Steam library's <c>appmanifest_*.acf</c>.</summary>
    Steam,

    /// <summary>Added by the user, by path or from a running process.</summary>
    Manual,
}

/// <summary>
/// A game and the route the user wants it on.
/// </summary>
/// <remarks>
/// A profile is not a rule. Starting a session turns it into one — an ordinary
/// <see cref="Rules.RoutingRule"/> with <see cref="Rules.RuleOrigin.GameProfile"/> — which is
/// what makes precedence against a manual selection explainable instead of special-cased.
/// The profile only records what the user chose; the rule records what the kernel is doing.
/// </remarks>
public sealed record GameProfile
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    /// <summary>Linux executable to match, when the game is native or the launcher is known.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Windows executable for a Wine/Proton game, which is what distinguishes two games sharing a runtime.</summary>
    public string? WineTargetExecutable { get; init; }

    public string? SteamAppId { get; init; }

    /// <summary>
    /// Where Steam installed the game, when the manifest named a directory that is there.
    /// </summary>
    /// <remarks>
    /// A fact from the manifest, not a guess at a binary: it is what lets Yura recognise the
    /// running game without the user pointing at it, which is the whole difficulty with a
    /// native Linux game that carries no Wine context to identify it by.
    /// </remarks>
    public string? InstallDirectory { get; init; }

    public required GameSource Source { get; init; }

    /// <summary>The route the user chose for this game: a proxy, or a chain.</summary>
    public Guid? RouteId { get; init; }

    public bool RouteIsChain { get; init; }

    /// <summary>
    /// Where latency is measured. A game's real server is only known once it connects, so
    /// this is set from an observed connection or typed by the user — never guessed.
    /// </summary>
    public string? MeasurementHost { get; init; }

    public ushort MeasurementPort { get; init; }

    /// <summary>True when enough is known to install a rule for this game.</summary>
    public bool IsRoutable => ExecutablePath is { Length: > 0 } || WineTargetExecutable is { Length: > 0 };

    /// <summary>
    /// Whether an executable path lies inside this game's install directory.
    /// </summary>
    /// <remarks>
    /// Containment is evidence rather than a guess: a binary under
    /// <c>steamapps/common/&lt;this game&gt;</c> belongs to this game and to nothing else. Windows
    /// paths from a Wine process are translated first, and the whole remaining path still has to
    /// match, so a wrong game cannot be picked up. Proton has two drives for the same files:
    /// <c>Z:</c> is the filesystem root, so <c>Z:\mnt\games\...\game.exe</c> is
    /// <c>/mnt/games/...</c>; and <c>S:</c> is the Steam library the game is in, so a game runs as
    /// <c>S:\steamapps\common\&lt;game&gt;\game.exe</c>. Taking every drive for the root, as this
    /// once did, recognised no Proton game by its own process at all.
    /// </remarks>
    public bool MatchesInstalledPath(string? executablePath)
    {
        if (InstallDirectory is not { Length: > 0 } directory || executablePath is not { Length: > 0 } path)
        {
            return false;
        }

        var prefix = directory.EndsWith('/') ? directory : directory + '/';
        if (!path.Contains('\\', StringComparison.Ordinal))
        {
            return path.StartsWith(prefix, StringComparison.Ordinal);
        }

        path = path.Replace('\\', '/');
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':')
        {
            return false;
        }

        // A Windows path is resolved case-insensitively, so it is compared that way.
        var rest = path[2..];
        if (char.ToLowerInvariant(path[0]) == 'z')
        {
            return rest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        // Any other drive is some directory of its own; inside a Steam library, the part of the
        // install directory from steamapps on is what a path on it has to start with.
        var library = prefix.IndexOf("/steamapps/", StringComparison.Ordinal);
        return library >= 0 && rest.StartsWith(prefix[library..], StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when a latency comparison can be run.</summary>
    public bool IsMeasurable => MeasurementHost is { Length: > 0 } && MeasurementPort > 0;
}
