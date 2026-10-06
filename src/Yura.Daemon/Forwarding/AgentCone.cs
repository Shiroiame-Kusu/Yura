using System.Collections.Concurrent;
using System.Net;
using Yura.Core.Agent;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>Where a full-cone channel's datagrams from one address go: the flow that talks to it.</summary>
internal interface IConeRoute
{
    /// <summary>Hands one datagram from the far end to the application.</summary>
    void Answer(ReadOnlyMemory<byte> payload);
}

/// <summary>
/// One application socket's channel on a full-cone agent session: every destination it sends to,
/// and everyone who sends to it, through one socket at the agent.
/// </summary>
/// <remarks>
/// <para>
/// The flows stay one per (socket, peer), as the Connections page lists them; what they share is
/// this channel, and with it the one address every peer sees — which is what makes the route an
/// Open NAT for a peer-to-peer game instead of a Strict one. Datagrams from the agent are routed
/// by who sent them: to the flow that sends there, or, for a peer the application has never sent
/// to — the case all of this exists for — to whoever accepts unsolicited ones.
/// </para>
/// <para>
/// It outlives its flows: the address the game told its peers has to stay the same while they
/// are still on their way, as a NAT's mapping would, so it is kept until the application has
/// sent nothing on it for a while. Only the application's own traffic counts, here as at the
/// agent.
/// </para>
/// </remarks>
internal sealed class AgentCone
{
    private readonly ConcurrentDictionary<IPEndPoint, IConeRoute> _routes = new();
    private readonly Func<IPEndPoint, ReadOnlyMemory<byte>, CancellationToken, Task> _send;
    private readonly Action _close;
    private readonly Func<bool> _alive;
    private readonly Action<AgentCone, IPEndPoint, ReadOnlyMemory<byte>> _unsolicited;
    private long _lastSentTicks;
    private int _closed;

    internal AgentCone(
        object owner,
        IPEndPoint client,
        FlowPlan? plan,
        Func<IPEndPoint, ReadOnlyMemory<byte>, CancellationToken, Task> send,
        Action close,
        Func<bool> alive,
        Action<AgentCone, IPEndPoint, ReadOnlyMemory<byte>> unsolicited,
        TimeProvider? time = null)
    {
        Owner = owner;
        Client = client;
        Plan = plan;
        _send = send;
        _close = close;
        _alive = alive;
        _unsolicited = unsolicited;
        Time = time ?? TimeProvider.System;
        _lastSentTicks = Time.GetTimestamp();
    }

    /// <summary>Opens a channel for one application socket on a full-cone agent session.</summary>
    /// <param name="unsolicited">Given what arrives from an address no flow sends to.</param>
    public static AgentCone Open(
        AgentSession agent, IPEndPoint client, FlowPlan plan, Action<AgentCone, IPEndPoint, ReadOnlyMemory<byte>> unsolicited)
    {
        AgentCone? cone = null;

        // Nothing can arrive on the channel before the first datagram is sent on it — the agent
        // only opens its socket then — so the handler never runs before the cone exists.
        var channel = agent.OpenChannel((from, payload) => cone?.Receive(from, payload), fullCone: true);
        cone = new AgentCone(
            agent,
            client,
            plan,
            (target, payload, ct) => agent.SendDatagramAsync(channel, target, payload, ct),
            () => agent.CloseChannel(channel),
            () => agent.IsOpen,
            unsolicited);
        return cone;
    }

    /// <summary>The agent session the channel belongs to: a cone from any other one is stale.</summary>
    public object Owner { get; }

    /// <summary>The application socket this channel stands for.</summary>
    public IPEndPoint Client { get; }

    /// <summary>How the first flow was routed, which every flow a peer opens is routed the same way.</summary>
    public FlowPlan? Plan { get; }

    public TimeProvider Time { get; }

    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    /// <summary>False once the agent session the channel belongs to has gone.</summary>
    public bool IsAlive => !IsClosed && _alive();

    public int RouteCount => _routes.Count;

    /// <summary>The flows using the channel, for retiring them with it.</summary>
    public IReadOnlyCollection<IConeRoute> Routes => _routes.Values.ToArray();

    /// <summary>How long since the application last sent on the channel.</summary>
    public TimeSpan SinceLastSent => Time.GetElapsedTime(Interlocked.Read(ref _lastSentTicks));

    /// <summary>Routes what arrives from <paramref name="target"/> to <paramref name="route"/>.</summary>
    public void Attach(IPEndPoint target, IConeRoute route) => _routes[target] = route;

    /// <summary>Takes the route away, unless another flow has since taken the address over.</summary>
    public void Detach(IPEndPoint target, IConeRoute route) =>
        _routes.TryRemove(KeyValuePair.Create(target, route));

    /// <summary>One datagram from the agent, from <paramref name="from"/>.</summary>
    public void Receive(IPEndPoint from, ReadOnlyMemory<byte> payload)
    {
        if (IsClosed)
        {
            return;
        }

        if (_routes.TryGetValue(from, out var route))
        {
            route.Answer(payload);
            return;
        }

        _unsolicited(this, from, payload);
    }

    public Task SendAsync(IPEndPoint target, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        Interlocked.Exchange(ref _lastSentTicks, Time.GetTimestamp());
        return _send(target, payload, ct);
    }

    /// <summary>Gives the channel up. Safe to call more than once.</summary>
    public void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) == 0)
        {
            _close();
        }
    }
}
