using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Yura.Core.Agent;
using Yura.Core.Connections;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Relays the UDP datagrams TPROXY redirects to one slot according to the per-flow decision.
/// </summary>
/// <remarks>
/// UDP under TPROXY differs from TCP in two ways that shape this class:
/// <list type="bullet">
/// <item>The original destination is not on the socket; it arrives out of band in an
/// <c>IP_ORIGDSTADDR</c> control message, which .NET does not surface. Receiving is done
/// through a direct <c>recvmsg</c> call on the socket's file descriptor.</item>
/// <item>Replies must appear to come from the address the application sent to, so each
/// session owns a transparent socket bound to that foreign address.</item>
/// </list>
/// Sessions are keyed on (client, original destination). Each is one of: a SOCKS5 UDP
/// association, a direct relay, a channel through a Yura agent, DNS carried over TCP for routes
/// that cannot relay UDP, or a deliberate drop. All are dropped after a period of silence.
///
/// Through an agent that grants full cone, the sessions of one application socket share one
/// channel — an <see cref="AgentCone"/> — so every peer sees the same address, and a peer the
/// application never sent to can open a session of its own by sending to it.
/// </remarks>
public sealed class TransparentUdpListener : IAsyncDisposable
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// How long a full-cone channel outlives the last datagram the application sent on it.
    /// </summary>
    /// <remarks>
    /// The address its peers were told stays the same that long, as a NAT's mapping would.
    /// A minute inside the agent's own lifetime for it, so this side always lets go first:
    /// sending on a channel the agent had already closed would quietly open a new socket there,
    /// with a new port, under an address the peers still hold.
    /// </remarks>
    internal static readonly TimeSpan ConeIdleTimeout = AgentProtocol.ConeMappingLifetime - TimeSpan.FromMinutes(1);

    private readonly RuleSlot _slot;
    private readonly int _port;
    private readonly IRouteDecider _decider;
    private readonly FlowRegistry _flows;
    private readonly Action<string> _log;
    // Lazy, so a session is opened once however many datagrams for it arrive together: the
    // dictionary may run a factory twice, and a second session opened that way was never closed.
    private readonly ConcurrentDictionary<(IPEndPoint Client, IPEndPoint Destination), Lazy<Task<UdpSession>>> _sessions = new();
    private readonly ConcurrentDictionary<IPEndPoint, AgentCone> _cones = new();
    private readonly Lock _coneGate = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly ReplySocketPool _replies;
    private Socket? _socket;
    private Thread? _receiveThread;

    public TransparentUdpListener(RuleSlot slot, int port, IRouteDecider decider, FlowRegistry flows, Action<string> log)
    {
        _slot = slot;
        _port = port;
        _decider = decider;
        _flows = flows;
        _log = log;
        // The pool's own sockets are a second way datagrams reach us; route them through the
        // same dispatch so a destination that already has a session keeps working.
        _replies = new ReplySocketPool((client, original, datagram) => DispatchAsync(client, original, datagram), log);
    }

    public void Start()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.SetTransparent();
        socket.SetRawSocketOption(0 /* SOL_IP */, 20 /* IP_RECVORIGDSTADDR */, BitConverter.GetBytes(1));
        socket.Bind(new IPEndPoint(IPAddress.Any, _port));
        _socket = socket;

        _receiveThread = new Thread(() => ReceiveLoop(socket))
        {
            IsBackground = true,
            Name = $"yura-udp-{_slot.Name}",
        };
        _receiveThread.Start();
        _ = ExpireConesAsync();
        _log($"slot {_slot.Name}: udp listener on :{_port} for '{_slot.Rule.Name}'");
    }

    private unsafe void ReceiveLoop(Socket socket)
    {
        var fd = (int)socket.Handle;
        var payload = new byte[65535];
        var control = new byte[256];
        var name = new byte[16]; // sockaddr_in

        while (!_stopping.IsCancellationRequested)
        {
            int received;
            IPEndPoint? client;
            IPEndPoint? original;

            fixed (byte* payloadPtr = payload)
            fixed (byte* controlPtr = control)
            fixed (byte* namePtr = name)
            {
                var iov = new IoVec { Base = payloadPtr, Length = (nuint)payload.Length };
                var header = new MsgHdr
                {
                    Name = namePtr,
                    NameLength = (uint)name.Length,
                    Iov = &iov,
                    IovLength = 1,
                    Control = controlPtr,
                    ControlLength = (nuint)control.Length,
                };

                received = (int)recvmsg(fd, &header, 0);
                if (received < 0)
                {
                    var errno = Marshal.GetLastPInvokeError();
                    if (errno == 4 /* EINTR */)
                    {
                        continue;
                    }

                    break; // EBADF on shutdown, or something we cannot recover from.
                }

                client = ParseSockaddrIn(name);
                original = ParseOriginalDestination(control, (int)header.ControlLength);
            }

            if (client is null || original is null)
            {
                _log($"slot {_slot.Name}: udp datagram without original destination; dropped");
                continue;
            }

            var datagram = payload.AsMemory(0, received).ToArray();
            _ = DispatchAsync(client, original, datagram);
        }
    }

    private async Task DispatchAsync(IPEndPoint client, IPEndPoint original, byte[] datagram)
    {
        var key = (client, original);
        var sessionTask = _sessions.GetOrAdd(key, _ => new Lazy<Task<UdpSession>>(() => OpenSessionAsync(client, original))).Value;

        UdpSession session;
        try
        {
            session = await sessionTask.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // OpenSessionAsync records the failure on the flow; a failed session is kept in
            // the table briefly so every datagram does not retry the handshake.
            return;
        }

        await session.SendAsync(datagram).ConfigureAwait(false);
    }

    private async Task<UdpSession> OpenSessionAsync(IPEndPoint client, IPEndPoint original)
    {
        var flow = new Flow(client, original, TransportProtocol.Udp, _slot.Rule.Id);
        _flows.Add(flow);
        _ = ExpireWhenIdleAsync((client, original));
        var learn = original.Port == 53 ? _decider.Dns : null;

        try
        {
            var plan = _decider.Decide(_slot, client, original, TransportProtocol.Udp, null);
            flow.Describe(plan);

            switch (plan.Kind)
            {
                case FlowPlanKind.Block:
                    flow.MarkBlocked();
                    return new DropSession(flow);

                case FlowPlanKind.Fail:
                    flow.MarkFailed(plan.FailureReason ?? "The rule could not be carried out.");
                    return new DropSession(flow);

                case FlowPlanKind.Direct:
                {
                    var session = await DirectUdpSession.OpenAsync(_replies, client, original, flow, learn, _stopping.Token).ConfigureAwait(false);
                    flow.MarkEstablished(RouteObservation.ConfirmedDirect);
                    return session;
                }

                default:
                {
                    if (plan.Hops.Count == 1 && plan.Hops[0].Tunnel is { } tunnel)
                    {
                        // A WireGuard exit relays UDP the way a direct route does, from inside the
                        // tunnel: same session, different mark and source.
                        var target = plan.DialDestination ?? original;
                        var source = tunnel.SourceFor(target.AddressFamily);
                        if (source is null)
                        {
                            var why = $"WireGuard exit '{tunnel.Name}' has no {(target.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} address.";
                            flow.MarkFailed(why);
                            _log($"slot {_slot.Name}: udp {client} -> {original} dropped: {why}");
                            return new DropSession(flow);
                        }

                        var session = await DirectUdpSession.OpenAsync(_replies, client, original, flow, learn, _stopping.Token,
                            tunnel.Mark, source, target).ConfigureAwait(false);
                        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                        return session;
                    }

                    if (plan.Hops.Count == 1 && plan.Hops[0].IsAgent)
                    {
                        var hop = plan.Hops[0];
                        var agent = await _decider.Agents.GetAsync(hop.Endpoint, hop.Password, _stopping.Token)
                            .ConfigureAwait(false);
                        if (agent is null || !agent.UdpAvailable)
                        {
                            if (original.Port == 53)
                            {
                                // No datagram channel, but the agent still relays TCP, and a
                                // lookup has a TCP form. Dropping it instead left every process
                                // on this exit unable to resolve a name, so the TCP connections
                                // the warning says will be attempted never were.
                                var dns = DnsOverTcpSession.Open(
                                    _replies, plan.Hops, client, original, plan.DialDestination ?? original, flow, learn);
                                flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                                return dns;
                            }

                            var why = agent is null
                                ? $"Agent exit '{hop.Endpoint.Name}' is not answering" +
                                  $"{(_decider.Agents.FailureFor(hop.Endpoint.Id) is { } detail ? $": {detail}" : ".")}"
                                : $"Agent exit '{hop.Endpoint.Name}' was started without UDP relaying.";
                            flow.MarkFailed(why);
                            _log($"slot {_slot.Name}: udp {client} -> {original} dropped: {why}");
                            return new DropSession(flow);
                        }

                        // Not for a name lookup: it comes from a fresh socket every time, nobody
                        // sends to it unasked, and a channel kept open minutes after it would
                        // only use up the agent's ports.
                        if (agent.FullCone && original.Port != 53)
                        {
                            var cone = ConeFor(client, agent, plan);
                            var coneSession = AgentConeUdpSession.Open(
                                _replies, cone, client, original, plan.DialDestination ?? original, flow, learn);
                            flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                            return coneSession;
                        }

                        var session = AgentUdpSession.Open(
                            _replies, agent, client, original, plan.DialDestination ?? original, flow, learn);
                        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                        return session;
                    }

                    if (plan.Hops.Count == 1 && plan.Hops[0].Endpoint.Protocol == ProxyProtocol.Socks5)
                    {
                        var session = await Socks5UdpSession.OpenAsync(_replies, plan.Hops[0], client, original, flow, learn, _stopping.Token)
                            .ConfigureAwait(false);
                        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                        return session;
                    }

                    if (original.Port == 53)
                    {
                        // The route cannot carry UDP, but DNS has a TCP form. Using it keeps
                        // name resolution working for processes behind HTTP proxies and chains.
                        var session = DnsOverTcpSession.Open(
                            _replies, plan.Hops, client, original, plan.DialDestination ?? original, flow, learn);
                        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                        return session;
                    }

                    var reason = plan.Hops.Count > 1
                        ? "A proxy chain cannot relay UDP."
                        : $"{plan.RouteName} is an {plan.Hops[0].Endpoint.ProtocolDisplay} proxy and cannot relay UDP.";
                    flow.MarkFailed(reason);
                    _log($"slot {_slot.Name}: udp {client} -> {original} dropped: {reason}");
                    return new DropSession(flow);
                }
            }
        }
        catch (Exception e) when (e is ProxyHandshakeException or SocketException)
        {
            flow.MarkFailed(e.Message);
            _log($"slot {_slot.Name}: udp {client} -> {original} failed: {e.Message}");
            return new DropSession(flow);
        }
        catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
        {
            flow.MarkClosed();
            return new DropSession(flow);
        }
        catch (Exception e)
        {
            // Whatever else went wrong, the flow still ends with a reason. Left to escape, it
            // faulted the session without a word and the flow stayed "being established" in
            // the list for as long as the daemon ran.
            flow.MarkFailed(e.Message);
            _log($"slot {_slot.Name}: udp {client} -> {original} failed: {e}");
            return new DropSession(flow);
        }
    }

    private async Task ExpireWhenIdleAsync((IPEndPoint, IPEndPoint) key)
    {
        while (!_stopping.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(IdleTimeout, _stopping.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (!_sessions.TryGetValue(key, out var entry) || !entry.Value.IsCompletedSuccessfully)
            {
                _sessions.TryRemove(key, out _);
                return;
            }

            if (DateTimeOffset.UtcNow - entry.Value.Result.LastActivityUtc >= IdleTimeout)
            {
                if (_sessions.TryRemove(key, out var removed) && removed.Value.IsCompletedSuccessfully)
                {
                    await removed.Value.Result.DisposeAsync().ConfigureAwait(false);
                }

                return;
            }
        }
    }

    // -- full cone ---------------------------------------------------------------

    /// <summary>
    /// The full-cone channel for one application socket, opened on first use.
    /// </summary>
    /// <remarks>
    /// One per socket, whatever it sends to — that is the whole of endpoint-independent mapping.
    /// A channel left over from an agent session that has since gone is replaced, and the flows
    /// on it retired, so they reopen on the new one rather than sending into nothing.
    /// </remarks>
    private AgentCone ConeFor(IPEndPoint client, AgentSession agent, FlowPlan plan)
    {
        AgentCone? stale = null;
        AgentCone cone;
        lock (_coneGate)
        {
            // One gone quiet past its time is as good as expired: the sweep may retire it any
            // moment, taking whatever has just been put on it along.
            if (_cones.TryGetValue(client, out var existing) &&
                ReferenceEquals(existing.Owner, agent) && existing.IsAlive &&
                existing.SinceLastSent < ConeIdleTimeout)
            {
                return existing;
            }

            stale = existing;
            cone = AgentCone.Open(agent, client, plan, OnUnsolicited);
            _cones[client] = cone;
        }

        if (stale is not null)
        {
            _ = RetireConeAsync(stale);
        }

        return cone;
    }

    /// <summary>
    /// Something arrived on a full-cone channel from an address no flow sends to: a peer
    /// reaching the game, which is what the channel is open for.
    /// </summary>
    private void OnUnsolicited(AgentCone cone, IPEndPoint from, ReadOnlyMemory<byte> payload) =>
        _ = AcceptAsync(cone, from, payload);

    private async Task AcceptAsync(AgentCone cone, IPEndPoint from, ReadOnlyMemory<byte> payload)
    {
        if (_stopping.IsCancellationRequested || !cone.IsAlive || !Admits(from))
        {
            return;
        }

        var key = (cone.Client, from);
        var entry = _sessions.GetOrAdd(key, _ => new Lazy<Task<UdpSession>>(() => OpenInboundTask(cone, from)));

        UdpSession session;
        try
        {
            session = await entry.Value.ConfigureAwait(false);
        }
        catch (Exception)
        {
            return;
        }

        // The same peer may have been reached a moment ago by the application itself, through
        // the same channel: that flow answers. Anything else — a session on another route, or a
        // failed one — has no business with what came through this channel.
        if (session is AgentConeUdpSession routed && ReferenceEquals(routed.Cone, cone))
        {
            routed.Answer(payload);
        }
    }

    /// <summary>
    /// Whether a peer may open a flow by sending to the game.
    /// </summary>
    /// <remarks>
    /// Only one the rule would route the game's answer to: anywhere else, the answer would leave
    /// by another route, from another address, and the peer would never hear it.
    /// </remarks>
    private bool Admits(IPEndPoint from) =>
        _slot.Rule.Destination.MatchesDestination(
            from.Address, (ushort)from.Port, TransportProtocol.Udp, _decider.Dns.Lookup(from.Address));

    /// <summary>
    /// <see cref="OpenInbound"/> as a task, faulted rather than thrown.
    /// </summary>
    /// <remarks>
    /// A Lazy keeps an exception its factory threw and throws it again on every read, so the
    /// entry could never be expired; a faulted task is one the expiry recognises and removes.
    /// </remarks>
    private Task<UdpSession> OpenInboundTask(AgentCone cone, IPEndPoint from)
    {
        try
        {
            return Task.FromResult(OpenInbound(cone, from));
        }
        catch (Exception e)
        {
            _log($"slot {_slot.Name}: udp {from} -> {cone.Client} could not be accepted: {e.Message}");
            return Task.FromException<UdpSession>(e);
        }
    }

    /// <summary>A flow the peer opened, routed the way the socket's first flow was.</summary>
    private UdpSession OpenInbound(AgentCone cone, IPEndPoint from)
    {
        var flow = new Flow(cone.Client, from, TransportProtocol.Udp, _slot.Rule.Id);
        _flows.Add(flow);
        _ = ExpireWhenIdleAsync((cone.Client, from));

        if (cone.Plan is { } plan)
        {
            // The first flow's host and dial target were that flow's own; this one has neither.
            flow.Describe(plan with { Host = _decider.Dns.Lookup(from.Address), DialDestination = null });
        }

        flow.Annotate("Opened by the peer, through the full-cone channel at the agent.");
        var session = AgentConeUdpSession.Open(_replies, cone, cone.Client, from, from, flow, learn: null);
        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
        return session;
    }

    /// <summary>
    /// Lets go of channels the application has stopped sending on, and of channels whose agent
    /// session has gone.
    /// </summary>
    private async Task ExpireConesAsync()
    {
        while (!_stopping.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), _stopping.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            foreach (var (client, cone) in _cones)
            {
                // The flows on it end with it, even ones a peer is still sending on: past this
                // point the agent lets the port go too, so what they would send next would leave
                // from somewhere new. A new flow opens a new channel instead, and says so.
                if (cone.IsAlive && cone.SinceLastSent < ConeIdleTimeout)
                {
                    continue;
                }

                if (_cones.TryRemove(KeyValuePair.Create(client, cone)))
                {
                    await RetireConeAsync(cone).ConfigureAwait(false);
                }
            }
        }
    }

    private async Task RetireConeAsync(AgentCone cone)
    {
        cone.Close();
        foreach (var route in cone.Routes)
        {
            if (route is not AgentConeUdpSession session)
            {
                continue;
            }

            // Out of the table only if the entry there is this very session, so a flow that has
            // already reopened on a new channel is left alone.
            if (_sessions.TryGetValue(session.Key, out var entry) && entry.IsValueCreated &&
                entry.Value.IsCompletedSuccessfully && ReferenceEquals(entry.Value.Result, session))
            {
                _sessions.TryRemove(KeyValuePair.Create(session.Key, entry));
            }

            await session.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stopping.Cancel();
        _socket?.Dispose(); // Unblocks recvmsg with EBADF.
        _receiveThread?.Join(TimeSpan.FromSeconds(2));

        foreach (var entry in _sessions.Values)
        {
            if (entry.IsValueCreated && entry.Value.IsCompletedSuccessfully)
            {
                await entry.Value.Result.DisposeAsync().ConfigureAwait(false);
            }
        }

        _sessions.Clear();

        foreach (var cone in _cones.Values)
        {
            cone.Close();
        }

        _cones.Clear();
        await _replies.DisposeAsync().ConfigureAwait(false);
        _stopping.Dispose();
    }

    // -- recvmsg -------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct IoVec
    {
        public byte* Base;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct MsgHdr
    {
        public byte* Name;
        public uint NameLength;
        public IoVec* Iov;
        public nuint IovLength;
        public byte* Control;
        public nuint ControlLength;
        public int Flags;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern unsafe nint recvmsg(int fd, MsgHdr* message, int flags);

    private static IPEndPoint? ParseSockaddrIn(ReadOnlySpan<byte> raw)
    {
        // sockaddr_in: family(2) port(2, network order) addr(4) zero(8)
        if (raw.Length < 8 || BinaryPrimitives.ReadUInt16LittleEndian(raw) != 2 /* AF_INET */)
        {
            return null;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(raw[2..]);
        return new IPEndPoint(new IPAddress(raw.Slice(4, 4)), port);
    }

    /// <summary>Walks the control buffer for IP_ORIGDSTADDR (level SOL_IP, type 20).</summary>
    private static IPEndPoint? ParseOriginalDestination(ReadOnlySpan<byte> control, int length)
    {
        const int CmsgHeader = 16; // size_t len + int level + int type
        var offset = 0;
        while (offset + CmsgHeader <= length)
        {
            var cmsgLength = (int)BinaryPrimitives.ReadUInt64LittleEndian(control[offset..]);
            var level = BinaryPrimitives.ReadInt32LittleEndian(control[(offset + 8)..]);
            var type = BinaryPrimitives.ReadInt32LittleEndian(control[(offset + 12)..]);
            if (cmsgLength < CmsgHeader)
            {
                break;
            }

            if (level == 0 && type == 20)
            {
                return ParseSockaddrIn(control.Slice(offset + CmsgHeader, cmsgLength - CmsgHeader));
            }

            // CMSG_ALIGN to 8 on x86_64/arm64.
            offset += (cmsgLength + 7) & ~7;
        }

        return null;
    }
}

/// <summary>One UDP flow, however it is being carried.</summary>
/// <remarks>
/// A session that answers the application holds a reservation on the reply socket for the
/// address it answers as, and gives it back when it ends — which is what lets the pool close a
/// destination's socket once nothing talks to it any more.
/// </remarks>
internal abstract class UdpSession : IAsyncDisposable
{
    private readonly ReplySocketPool? _replies;
    private readonly IPEndPoint? _answeringAs;
    private int _disposed;

    protected UdpSession(Flow flow) => Flow = flow;

    protected UdpSession(Flow flow, ReplySocketPool replies, IPEndPoint answeringAs)
        : this(flow)
    {
        if (replies.Reserve(answeringAs))
        {
            _replies = replies;
            _answeringAs = answeringAs;
        }
    }

    public Flow Flow { get; }

    public DateTimeOffset LastActivityUtc { get; protected set; } = DateTimeOffset.UtcNow;

    public abstract Task SendAsync(byte[] datagram);

    /// <summary>Ends the session. Safe to call twice: the idle expiry and a listener shutdown can both get here.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await CloseAsync().ConfigureAwait(false);
        if (_replies is not null)
        {
            _replies.Release(_answeringAs!);
        }
    }

    protected abstract ValueTask CloseAsync();
}

/// <summary>Blocked, failed or unroutable: every datagram is discarded, and the flow says why.</summary>
internal sealed class DropSession : UdpSession
{
    public DropSession(Flow flow) : base(flow)
    {
    }

    public override Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        return Task.CompletedTask;
    }

    protected override ValueTask CloseAsync() => ValueTask.CompletedTask;
}

/// <summary>Relays datagrams straight to the destination from a bypass-marked socket.</summary>
internal sealed class DirectUdpSession : UdpSession
{
    private readonly ReplySocketPool _replies;
    private readonly Socket _relay;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly DnsCache? _learn;
    private readonly CancellationTokenSource _closing = new();

    private DirectUdpSession(
        ReplySocketPool replies, Socket relay, IPEndPoint client, IPEndPoint original, Flow flow, DnsCache? learn)
        : base(flow, replies, original)
    {
        _replies = replies;
        _relay = relay;
        _client = client;
        _original = original;
        _learn = learn;
        _ = PumpRepliesAsync(_closing.Token);
    }

    /// <param name="mark">The bypass mark, or a WireGuard tunnel's mark.</param>
    /// <param name="bindTo">A tunnel address to originate from, or null for the kernel's choice.</param>
    /// <param name="target">Where to send, when that differs from the original destination.</param>
    public static Task<DirectUdpSession> OpenAsync(
        ReplySocketPool replies, IPEndPoint client, IPEndPoint original, Flow flow, DnsCache? learn, CancellationToken ct,
        uint mark = PolicyRouting.BypassMark, IPAddress? bindTo = null, IPEndPoint? target = null)
    {
        target ??= original;
        var relay = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            relay.SetMark(mark);
            if (bindTo is not null)
            {
                relay.Bind(new IPEndPoint(bindTo, 0));
            }

            relay.Connect(target);
        }
        catch
        {
            relay.Dispose();
            throw;
        }

        return Task.FromResult(new DirectUdpSession(replies, relay, client, original, flow, learn));
    }

    public override async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        try
        {
            await _relay.SendAsync(datagram, _closing.Token).ConfigureAwait(false);
            Flow.AddUp(datagram.Length);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    private async Task PumpRepliesAsync(CancellationToken ct)
    {
        var buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await _relay.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            LastActivityUtc = DateTimeOffset.UtcNow;
            _learn?.Learn(buffer.AsSpan(0, received));
            await _replies.SendAsync(_original, _client, buffer.AsMemory(0, received)).ConfigureAwait(false);
            Flow.AddDown(received);
        }
    }

    protected override ValueTask CloseAsync()
    {
        _closing.Cancel();
        Flow.MarkClosed();
        _relay.Dispose();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// One UDP flow carried on an agent's datagram channel.
/// </summary>
/// <remarks>
/// The channel is this flow's own, for as long as the flow lasts, which is what keeps the
/// source port the game appears to come from stable at the far end. Answers arrive on the
/// session's socket and are handed here by channel, so nothing has to be matched by address.
/// </remarks>
internal sealed class AgentUdpSession : UdpSession
{
    private readonly ReplySocketPool _replies;
    private readonly AgentSession _agent;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly IPEndPoint _target;
    private readonly DnsCache? _learn;
    private readonly CancellationTokenSource _closing = new();
    private ushort _channel;
    private bool _reported;

    private AgentUdpSession(
        ReplySocketPool replies, AgentSession agent, IPEndPoint client, IPEndPoint original, IPEndPoint target,
        Flow flow, DnsCache? learn)
        : base(flow, replies, original)
    {
        _replies = replies;
        _agent = agent;
        _client = client;
        _original = original;
        _target = target;
        _learn = learn;
    }

    public static AgentUdpSession Open(
        ReplySocketPool replies, AgentSession agent, IPEndPoint client, IPEndPoint original, IPEndPoint target,
        Flow flow, DnsCache? learn)
    {
        var session = new AgentUdpSession(replies, agent, client, original, target, flow, learn);
        try
        {
            session._channel = agent.OpenChannel((from, payload) => session.OnAnswer(from, payload));
        }
        catch
        {
            _ = session.DisposeAsync();
            throw;
        }

        return session;
    }

    /// <summary>
    /// An answer from the agent, on the session's socket, for this flow's channel.
    /// </summary>
    /// <remarks>
    /// The source is ignored on purpose: the channel is bound to one destination at the agent,
    /// so an answer on this channel came from that destination and the reply must appear to
    /// come from the address the application sent to — which is what the flow already records.
    /// </remarks>
    private void OnAnswer(IPEndPoint from, ReadOnlyMemory<byte> payload) => _ = OnAnswerAsync(payload);

    private async Task OnAnswerAsync(ReadOnlyMemory<byte> payload)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        _learn?.Learn(payload.Span);
        try
        {
            await _replies.SendAsync(_original, _client, payload).ConfigureAwait(false);
            Flow.AddDown(payload.Length);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    public override async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        try
        {
            await _agent.SendDatagramAsync(_channel, _target, datagram, _closing.Token).ConfigureAwait(false);
            Flow.AddUp(datagram.Length);
        }
        catch (AgentProtocolException e)
        {
            // Almost always a datagram over the agent's size limit. Said once, on the flow,
            // rather than silently dropped or repeated for every packet.
            if (!_reported)
            {
                _reported = true;
                Flow.MarkFailed(e.Message);
            }
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    protected override ValueTask CloseAsync()
    {
        _closing.Cancel();
        _agent.CloseChannel(_channel);
        Flow.MarkClosed();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// One UDP flow on a full-cone agent channel: one application socket and one peer.
/// </summary>
/// <remarks>
/// The channel is the socket's, shared with every other flow from it (see <see cref="AgentCone"/>),
/// so the peer sees the address every other peer sees. What arrives from the peer is handed here
/// by the channel, by source address; a flow the peer opened is no different from one the
/// application did.
/// </remarks>
internal sealed class AgentConeUdpSession : UdpSession, IConeRoute
{
    private readonly ReplySocketPool _replies;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly IPEndPoint _target;
    private readonly DnsCache? _learn;
    private readonly CancellationTokenSource _closing = new();
    private bool _reported;

    private AgentConeUdpSession(
        ReplySocketPool replies, AgentCone cone, IPEndPoint client, IPEndPoint original, IPEndPoint target,
        Flow flow, DnsCache? learn)
        : base(flow, replies, original)
    {
        _replies = replies;
        Cone = cone;
        _client = client;
        _original = original;
        _target = target;
        _learn = learn;
    }

    /// <param name="original">The address the application sent to, which answers appear to come from.</param>
    /// <param name="target">Where the agent sends, which is where answers arrive from.</param>
    public static AgentConeUdpSession Open(
        ReplySocketPool replies, AgentCone cone, IPEndPoint client, IPEndPoint original, IPEndPoint target,
        Flow flow, DnsCache? learn)
    {
        var session = new AgentConeUdpSession(replies, cone, client, original, target, flow, learn);
        cone.Attach(target, session);
        return session;
    }

    public AgentCone Cone { get; }

    /// <summary>Where the listener keeps this session.</summary>
    public (IPEndPoint Client, IPEndPoint Destination) Key => (_client, _original);

    public void Answer(ReadOnlyMemory<byte> payload) => _ = AnswerAsync(payload);

    private async Task AnswerAsync(ReadOnlyMemory<byte> payload)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        _learn?.Learn(payload.Span);
        try
        {
            await _replies.SendAsync(_original, _client, payload).ConfigureAwait(false);
            Flow.AddDown(payload.Length);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    public override async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        try
        {
            await Cone.SendAsync(_target, datagram, _closing.Token).ConfigureAwait(false);
            Flow.AddUp(datagram.Length);
        }
        catch (AgentProtocolException e)
        {
            // Almost always a datagram over the agent's size limit. Said once, on the flow,
            // rather than silently dropped or repeated for every packet.
            if (!_reported)
            {
                _reported = true;
                Flow.MarkFailed(e.Message);
            }
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    protected override ValueTask CloseAsync()
    {
        _closing.Cancel();
        Cone.Detach(_target, this);
        Flow.MarkClosed();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>One UDP flow relayed through a SOCKS5 UDP association.</summary>
internal sealed class Socks5UdpSession : UdpSession
{
    private readonly ReplySocketPool _replies;
    private readonly Socket _control;
    private readonly Socket _relay;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly DnsCache? _learn;
    private readonly byte[] _header;
    private readonly CancellationTokenSource _closing = new();

    private Socks5UdpSession(
        ReplySocketPool replies, Socket control, Socket relay, IPEndPoint client, IPEndPoint original, Flow flow, DnsCache? learn)
        : base(flow, replies, original)
    {
        _replies = replies;
        _control = control;
        _relay = relay;
        _client = client;
        _original = original;
        _learn = learn;

        // SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT — built once per session.
        var address = original.Address.GetAddressBytes();
        _header = new byte[4 + address.Length + 2];
        _header[3] = original.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
        address.CopyTo(_header, 4);
        BinaryPrimitives.WriteUInt16BigEndian(_header.AsSpan(4 + address.Length), (ushort)original.Port);

        _ = PumpRepliesAsync(_closing.Token);
    }

    public static async Task<Socks5UdpSession> OpenAsync(
        ReplySocketPool replies, ProxyHop hop, IPEndPoint client, IPEndPoint original, Flow flow, DnsCache? learn,
        CancellationToken ct)
    {
        var proxyAddress = await ProxyDialer.ResolveAsync(hop.Endpoint.Host, ct).ConfigureAwait(false);

        // The association lives as long as this TCP control connection.
        var control = await ProxyDialer.ConnectWithBypassAsync(hop.Endpoint.Host, hop.Endpoint.Port, ct).ConfigureAwait(false);
        IPEndPoint relayEndpoint;
        try
        {
            using var stream = new NetworkStream(control, ownsSocket: false);
            relayEndpoint = await AssociateAsync(stream, hop, proxyAddress, ct).ConfigureAwait(false);
        }
        catch
        {
            control.Dispose();
            throw;
        }

        var relay = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            relay.SetMark(PolicyRouting.BypassMark);
            await relay.ConnectAsync(relayEndpoint, ct).ConfigureAwait(false);
        }
        catch
        {
            relay.Dispose();
            control.Dispose();
            throw;
        }

        return new Socks5UdpSession(replies, control, relay, client, original, flow, learn);
    }

    private static async Task<IPEndPoint> AssociateAsync(Stream control, ProxyHop hop, IPAddress proxyAddress, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var token = timeout.Token;

        await ProxyDialer.Socks5GreetAsync(control, hop.Endpoint.Username, hop.Password, token).ConfigureAwait(false);

        // UDP ASSOCIATE with an unspecified client address: we will send from whatever
        // port the relay socket gets.
        await control.WriteAsync(ProxyDialer.BuildSocks5Request(0x03, "0.0.0.0", 0), token).ConfigureAwait(false);
        await control.FlushAsync(token).ConfigureAwait(false);
        var reply = await ProxyDialer.ReadExactlyAsync(control, 4, token).ConfigureAwait(false);
        if (reply[1] != 0)
        {
            throw new ProxyHandshakeException(reply[1] == 7
                ? "This proxy does not support UDP."
                : $"The proxy refused UDP ASSOCIATE (reply {reply[1]:#x}).");
        }

        var bound = await ProxyDialer.DrainSocks5AddressAsync(control, reply[3], token).ConfigureAwait(false)
                    ?? throw new ProxyHandshakeException("The proxy returned a named relay address, which is not supported.");
        if (bound.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ProxyHandshakeException("The proxy returned a non-IPv4 relay address, which is not supported yet.");
        }

        // 0.0.0.0 means "same host as the control connection".
        return bound.Address.Equals(IPAddress.Any) ? new IPEndPoint(proxyAddress, bound.Port) : bound;
    }

    public override async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        var framed = new byte[_header.Length + datagram.Length];
        _header.CopyTo(framed, 0);
        datagram.CopyTo(framed, _header.Length);
        try
        {
            await _relay.SendAsync(framed, _closing.Token).ConfigureAwait(false);
            Flow.AddUp(datagram.Length);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    private async Task PumpRepliesAsync(CancellationToken ct)
    {
        var buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await _relay.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            // Strip the SOCKS5 UDP header.
            if (received < 4 || buffer[2] != 0)
            {
                continue;
            }

            var offset = buffer[3] switch
            {
                1 => 4 + 4 + 2,
                4 => 4 + 16 + 2,
                3 => 4 + 1 + buffer[4] + 2,
                _ => -1,
            };
            if (offset < 0 || offset > received)
            {
                continue;
            }

            LastActivityUtc = DateTimeOffset.UtcNow;
            _learn?.Learn(buffer.AsSpan(offset, received - offset));
            await _replies.SendAsync(_original, _client, buffer.AsMemory(offset, received - offset)).ConfigureAwait(false);
            Flow.AddDown(received - offset);
        }
    }

    protected override ValueTask CloseAsync()
    {
        _closing.Cancel();
        Flow.MarkClosed();
        _relay.Dispose();
        _control.Dispose();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Carries DNS for a route that cannot relay UDP by sending each query over a TCP tunnel
/// (RFC 1035 §4.2.2: two-byte length prefix) and returning the answer as a datagram.
/// </summary>
internal sealed class DnsOverTcpSession : UdpSession
{
    /// <summary>
    /// How long one query may take end to end. A resolver retries on its own schedule, so an
    /// answer later than this is one nobody is waiting for — and without a limit, a hop that
    /// never answers kept a connection open per query until the session ended.
    /// </summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(15);

    private readonly ReplySocketPool _replies;
    private readonly IReadOnlyList<ProxyHop> _hops;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly IPEndPoint _dial;
    private readonly DnsCache? _learn;
    private readonly CancellationTokenSource _closing = new();

    private DnsOverTcpSession(
        ReplySocketPool replies, IReadOnlyList<ProxyHop> hops, IPEndPoint client, IPEndPoint original, IPEndPoint dial,
        Flow flow, DnsCache? learn)
        : base(flow, replies, original)
    {
        _replies = replies;
        _hops = hops;
        _client = client;
        _original = original;
        _dial = dial;
        _learn = learn;
    }

    /// <param name="dial">
    /// Where the queries go: the application's resolver, or the route's own resolver in its place.
    /// The answers still appear to come from <paramref name="original"/>.
    /// </param>
    public static DnsOverTcpSession Open(
        ReplySocketPool replies, IReadOnlyList<ProxyHop> hops, IPEndPoint client, IPEndPoint original, IPEndPoint dial,
        Flow flow, DnsCache? learn) =>
        new(replies, hops, client, original, dial, flow, learn);

    public override async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        try
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(_closing.Token);
            limit.CancelAfter(QueryTimeout);
            var ct = limit.Token;

            await using var leg = await ProxyDialer.OpenAsync(_hops, _dial, ct).ConfigureAwait(false);
            var framed = new byte[2 + datagram.Length];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)datagram.Length);
            datagram.CopyTo(framed, 2);
            await leg.Stream.WriteAsync(framed, ct).ConfigureAwait(false);
            await leg.Stream.FlushAsync(ct).ConfigureAwait(false);
            Flow.AddUp(datagram.Length);

            var length = await ProxyDialer.ReadExactlyAsync(leg.Stream, 2, ct).ConfigureAwait(false);
            var answer = await ProxyDialer.ReadExactlyAsync(leg.Stream, BinaryPrimitives.ReadUInt16BigEndian(length), ct).ConfigureAwait(false);
            _learn?.Learn(answer);
            await _replies.SendAsync(_original, _client, answer).ConfigureAwait(false);
            Flow.AddDown(answer.Length);
        }
        catch (Exception e) when (e is ProxyHandshakeException or SocketException or IOException or ObjectDisposedException
                                     or OperationCanceledException or AgentProtocolException)
        {
            // The resolver retries; one lost answer is what UDP DNS expects anyway.
        }
    }

    protected override ValueTask CloseAsync()
    {
        _closing.Cancel();
        Flow.MarkClosed();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}
