using System.Net;
using Yura.Core.Processes;
using Yura.Core.Rules;

namespace Yura.Core.Connections;

/// <summary>Transport-level lifecycle of a tracked connection.</summary>
public enum ConnectionState
{
    /// <summary>Yura has accepted the flow but the upstream leg is not up yet.</summary>
    Establishing,

    /// <summary>Both legs are up and carrying data.</summary>
    Established,

    /// <summary>One side has closed; the other is draining.</summary>
    Closing,

    Closed,

    /// <summary>Setup failed. <see cref="ConnectionRecord.FailureReason"/> says why.</summary>
    Failed,
}

/// <summary>
/// What we actually know about the path a connection is taking.
/// </summary>
/// <remarks>
/// This is the type that keeps the Connections page honest. A rule being installed is not
/// evidence that a given connection obeys it, so "a rule exists" and "this flow is going
/// through the proxy" are different values here and are rendered differently.
/// </remarks>
public enum RouteObservation
{
    /// <summary>Ownership or route could not be determined. Rendered as "Unknown".</summary>
    Unknown,

    /// <summary>A rule applies but no socket has been observed yet. Rendered as "Pending".</summary>
    Pending,

    /// <summary>
    /// The connection existed before the rule was applied and is still on its previous
    /// route. Rendered as "Previous route (pre-existing)" with an explanation of what a
    /// reconnect would change.
    /// </summary>
    PreExistingPreviousRoute,

    /// <summary>The flow was never claimed by the classifier and left through the normal route.</summary>
    ConfirmedDirect,

    /// <summary>
    /// Yura is forwarding this flow itself: it holds both the accepted socket and the
    /// upstream socket to the proxy. This is the only value that may be shown as "Proxied".
    /// </summary>
    ConfirmedProxied,

    /// <summary>The flow was refused by a Block rule and the refusal was delivered.</summary>
    ConfirmedBlocked,
}

/// <summary>One row of the Connections page.</summary>
public sealed record ConnectionRecord
{
    public required long Id { get; init; }

    /// <summary>Owning process, or null when ownership could not be established.</summary>
    public ProcessIdentity? Process { get; init; }

    /// <summary>Cached display name so the row survives the process exiting.</summary>
    public string? ProcessDisplayName { get; init; }

    public required IPEndPoint Local { get; init; }

    public required IPEndPoint Remote { get; init; }

    /// <summary>Name learned from DNS or SNI, when one was observed.</summary>
    public string? RemoteHost { get; init; }

    public required TransportProtocol Protocol { get; init; }

    public required ConnectionState State { get; init; }

    public required RouteObservation Route { get; init; }

    /// <summary>The rule that decided this flow, or null when the default applied.</summary>
    public Guid? MatchedRuleId { get; init; }

    public string? MatchedRuleName { get; init; }

    /// <summary>
    /// Display name of the proxy actually carrying the flow. Only set when
    /// <see cref="Route"/> is <see cref="RouteObservation.ConfirmedProxied"/>.
    /// </summary>
    public string? ProxyName { get; init; }

    public long BytesUp { get; init; }

    public long BytesDown { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    /// <summary>Operator-facing reason for <see cref="ConnectionState.Failed"/>.</summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// The route label to render. Never claims "Proxied" without a confirmed observation.
    /// </summary>
    public string RouteLabel => Route switch
    {
        RouteObservation.ConfirmedProxied => ProxyName is { Length: > 0 } p ? p : "Proxied",
        RouteObservation.ConfirmedDirect => "Direct",
        RouteObservation.ConfirmedBlocked => "Blocked",
        RouteObservation.PreExistingPreviousRoute => "Previous route",
        RouteObservation.Pending => "Pending",
        _ => "Unknown",
    };
}
