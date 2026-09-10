namespace Yura.Core.Rules;

/// <summary>Where a rule came from. Shown in the UI so precedence is explainable.</summary>
public enum RuleOrigin
{
    /// <summary>Created by the user on the Rules page or from a connection.</summary>
    Manual,

    /// <summary>Created by the user selecting a process on the Processes page.</summary>
    ProcessSelection,

    /// <summary>Installed by an active game acceleration session.</summary>
    GameProfile,

    /// <summary>
    /// Installed by Yura itself and not user-editable: loop prevention for the daemon's own
    /// sockets, the configured proxy endpoints, and control traffic.
    /// </summary>
    System,
}

/// <summary>How long a rule survives.</summary>
public enum RuleLifetime
{
    /// <summary>Stored in the configuration file and reapplied on every start.</summary>
    Persistent,

    /// <summary>
    /// Bound to one process instance. The daemon removes it when that instance exits, so a
    /// later process that happens to reuse the pid can never inherit it.
    /// </summary>
    Instance,

    /// <summary>Lives until the daemon restarts. Used by game sessions.</summary>
    Session,
}

/// <summary>
/// One entry in the single, ordered rule list that both workflows share.
/// </summary>
/// <remarks>
/// Manual process selections and game profiles are the same kind of object; they differ
/// only in <see cref="Origin"/> and <see cref="Lifetime"/>. That is what makes precedence
/// between them explainable instead of emergent.
/// </remarks>
public sealed record RoutingRule
{
    public required Guid Id { get; init; }

    /// <summary>
    /// Position in the ordered list. Lower evaluates first. Ties are broken by
    /// <see cref="CreatedAtUtc"/> so evaluation is always deterministic.
    /// </summary>
    public required int Order { get; init; }

    public required string Name { get; init; }

    public bool Enabled { get; init; } = true;

    public required RuleOrigin Origin { get; init; }

    public required RuleLifetime Lifetime { get; init; }

    public ProcessSelector Process { get; init; } = ProcessSelector.Any;

    public DestinationSelector Destination { get; init; } = DestinationSelector.Any;

    public required RuleAction Action { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    /// <summary>
    /// When the daemon confirmed the rule was installed in the kernel. Null while the rule
    /// is still pending, which the UI shows as a distinct state from "active".
    /// </summary>
    public DateTimeOffset? AppliedAtUtc { get; init; }

    /// <summary>Free-text note shown in the rule inspector.</summary>
    public string? Notes { get; init; }

    /// <summary>True when the user may edit or delete this rule.</summary>
    public bool IsUserEditable => Origin != RuleOrigin.System;

    /// <summary>
    /// True when this is a temporary override that the UI must surface as removable.
    /// </summary>
    public bool IsTemporaryOverride => Lifetime is RuleLifetime.Instance or RuleLifetime.Session &&
                                       Origin != RuleOrigin.System;

    public string Describe() => $"{Process.Describe()} → {Destination.Describe()} ⇒ {Action}";
}
