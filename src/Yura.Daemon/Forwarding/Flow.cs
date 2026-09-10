using System.Net;
using Yura.Core.Connections;
using Yura.Core.Rules;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// One captured connection, from acceptance to close.
/// </summary>
/// <remarks>
/// This is the daemon-side source of truth for the Connections page. A flow only exists
/// here because the daemon holds the application's socket, and its <see cref="Route"/>
/// records what the daemon then did with it — which is exactly the evidence
/// <see cref="RouteObservation.ConfirmedProxied"/> demands.
/// </remarks>
public sealed class Flow
{
    private static long _nextId;
    private long _bytesUp;
    private long _bytesDown;

    public Flow(IPEndPoint client, IPEndPoint originalDestination, TransportProtocol protocol, Guid slotRuleId)
    {
        Id = Interlocked.Increment(ref _nextId);
        Client = client;
        OriginalDestination = originalDestination;
        Protocol = protocol;
        RuleId = slotRuleId;
        CreatedAtUtc = DateTimeOffset.UtcNow;
        State = ConnectionState.Establishing;
        Route = RouteObservation.Pending;
    }

    public long Id { get; }

    /// <summary>The application's side: its source address and port. What attribution keys on.</summary>
    public IPEndPoint Client { get; }

    /// <summary>Where the application was actually trying to go.</summary>
    public IPEndPoint OriginalDestination { get; }

    public TransportProtocol Protocol { get; }

    /// <summary>The rule that decided the flow. Starts as the capturing slot's rule.</summary>
    public Guid? RuleId { get; private set; }

    public string? RuleName { get; private set; }

    /// <summary>Display name of the proxy or chain carrying the flow, when proxied.</summary>
    public string? ProxyName { get; private set; }

    public int? OwnerPid { get; private set; }

    public string? ProcessName { get; private set; }

    /// <summary>Destination name from SNI, an HTTP Host header or a DNS answer.</summary>
    public string? Host { get; private set; }

    public RouteObservation Route { get; private set; }

    public DateTimeOffset CreatedAtUtc { get; }

    public ConnectionState State { get; private set; }

    public string? FailureReason { get; private set; }

    /// <summary>Bytes from the application towards the destination.</summary>
    public long BytesUp => Interlocked.Read(ref _bytesUp);

    /// <summary>Bytes from the destination back to the application.</summary>
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    public void AddUp(long bytes) => Interlocked.Add(ref _bytesUp, bytes);

    public void AddDown(long bytes) => Interlocked.Add(ref _bytesDown, bytes);

    /// <summary>Records the per-flow decision. The route stays Pending until the leg is up.</summary>
    public void Describe(FlowPlan plan)
    {
        RuleId = plan.RuleId;
        RuleName = plan.RuleName;
        OwnerPid = plan.OwnerPid;
        ProcessName = plan.ProcessName;
        Host = plan.Host;
        ProxyName = plan.Kind == FlowPlanKind.Proxy ? plan.RouteName : null;
    }

    public void MarkEstablished(RouteObservation route)
    {
        State = ConnectionState.Established;
        Route = route;
    }

    public void MarkBlocked()
    {
        State = ConnectionState.Closed;
        Route = RouteObservation.ConfirmedBlocked;
    }

    public void MarkClosing() => State = ConnectionState.Closing;

    public void MarkClosed() => State = ConnectionState.Closed;

    public void MarkFailed(string reason)
    {
        State = ConnectionState.Failed;
        Route = RouteObservation.Unknown;
        FailureReason = reason;
    }
}
