using System.Net;
using Yura.Core.Connections;
using Yura.Core.Rules;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// One captured connection, from acceptance to close.
/// </summary>
/// <remarks>
/// This is the daemon-side source of truth for the Connections page. A flow only exists
/// here because the daemon holds both its sockets, which is exactly the evidence
/// <see cref="RouteObservation.ConfirmedProxied"/> demands.
/// </remarks>
public sealed class Flow
{
    private static long _nextId;
    private long _bytesUp;
    private long _bytesDown;

    public Flow(IPEndPoint client, IPEndPoint originalDestination, TransportProtocol protocol, Guid ruleId, string proxyName)
    {
        Id = Interlocked.Increment(ref _nextId);
        Client = client;
        OriginalDestination = originalDestination;
        Protocol = protocol;
        RuleId = ruleId;
        ProxyName = proxyName;
        CreatedAtUtc = DateTimeOffset.UtcNow;
        State = ConnectionState.Establishing;
    }

    public long Id { get; }

    /// <summary>The application's side: its source address and port. What attribution keys on.</summary>
    public IPEndPoint Client { get; }

    /// <summary>Where the application was actually trying to go.</summary>
    public IPEndPoint OriginalDestination { get; }

    public TransportProtocol Protocol { get; }

    public Guid RuleId { get; }

    public string ProxyName { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public ConnectionState State { get; private set; }

    public string? FailureReason { get; private set; }

    /// <summary>Bytes from the application towards the destination.</summary>
    public long BytesUp => Interlocked.Read(ref _bytesUp);

    /// <summary>Bytes from the destination back to the application.</summary>
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    public void AddUp(long bytes) => Interlocked.Add(ref _bytesUp, bytes);

    public void AddDown(long bytes) => Interlocked.Add(ref _bytesDown, bytes);

    public void MarkEstablished() => State = ConnectionState.Established;

    public void MarkClosing() => State = ConnectionState.Closing;

    public void MarkClosed() => State = ConnectionState.Closed;

    public void MarkFailed(string reason)
    {
        State = ConnectionState.Failed;
        FailureReason = reason;
    }
}
