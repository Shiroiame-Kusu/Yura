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

    /// <summary>True when a latency comparison can be run.</summary>
    public bool IsMeasurable => MeasurementHost is { Length: > 0 } && MeasurementPort > 0;
}
