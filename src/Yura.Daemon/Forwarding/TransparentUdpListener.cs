using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
/// association, a direct relay, DNS carried over TCP for routes that cannot relay UDP, or a
/// deliberate drop. All are dropped after a period of silence.
/// </remarks>
public sealed class TransparentUdpListener : IAsyncDisposable
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);

    private readonly RuleSlot _slot;
    private readonly int _port;
    private readonly IRouteDecider _decider;
    private readonly FlowRegistry _flows;
    private readonly Action<string> _log;
    private readonly ConcurrentDictionary<(IPEndPoint Client, IPEndPoint Destination), Task<UdpSession>> _sessions = new();
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
        var sessionTask = _sessions.GetOrAdd(key, _ => OpenSessionAsync(client, original));

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

        var plan = _decider.Decide(_slot, client, original, TransportProtocol.Udp, null);
        flow.Describe(plan);
        var learn = original.Port == 53 ? _decider.Dns : null;

        try
        {
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
                        var session = DnsOverTcpSession.Open(_replies, plan.Hops, client, original, flow, learn, _stopping.Token);
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

            if (!_sessions.TryGetValue(key, out var task) || !task.IsCompletedSuccessfully)
            {
                _sessions.TryRemove(key, out _);
                return;
            }

            if (DateTimeOffset.UtcNow - task.Result.LastActivityUtc >= IdleTimeout)
            {
                if (_sessions.TryRemove(key, out var removed) && removed.IsCompletedSuccessfully)
                {
                    await removed.Result.DisposeAsync().ConfigureAwait(false);
                }

                return;
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stopping.Cancel();
        _socket?.Dispose(); // Unblocks recvmsg with EBADF.
        _receiveThread?.Join(TimeSpan.FromSeconds(2));

        foreach (var task in _sessions.Values)
        {
            if (task.IsCompletedSuccessfully)
            {
                await task.Result.DisposeAsync().ConfigureAwait(false);
            }
        }

        _sessions.Clear();
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
internal abstract class UdpSession : IAsyncDisposable
{
    protected UdpSession(Flow flow) => Flow = flow;

    public Flow Flow { get; }

    public DateTimeOffset LastActivityUtc { get; protected set; } = DateTimeOffset.UtcNow;

    public abstract Task SendAsync(byte[] datagram);

    public abstract ValueTask DisposeAsync();
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

    public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
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
        : base(flow)
    {
        _replies = replies;
        _relay = relay;
        _client = client;
        _original = original;
        _learn = learn;
        _ = PumpRepliesAsync(_closing.Token);
    }

    public static Task<DirectUdpSession> OpenAsync(
        ReplySocketPool replies, IPEndPoint client, IPEndPoint original, Flow flow, DnsCache? learn, CancellationToken ct)
    {
        var relay = new Socket(original.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        relay.SetMark(PolicyRouting.BypassMark);
        relay.Connect(original);
        replies.Reserve(original);
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

    public override ValueTask DisposeAsync()
    {
        _closing.Cancel();
        Flow.MarkClosed();
        _relay.Dispose();
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
        : base(flow)
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
        relay.SetMark(PolicyRouting.BypassMark);
        await relay.ConnectAsync(relayEndpoint, ct).ConfigureAwait(false);

        replies.Reserve(original);
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

    public override ValueTask DisposeAsync()
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
    private readonly ReplySocketPool _replies;
    private readonly IReadOnlyList<ProxyHop> _hops;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly DnsCache? _learn;
    private readonly CancellationTokenSource _closing = new();

    private DnsOverTcpSession(
        ReplySocketPool replies, IReadOnlyList<ProxyHop> hops, IPEndPoint client, IPEndPoint original, Flow flow, DnsCache? learn)
        : base(flow)
    {
        _replies = replies;
        _hops = hops;
        _client = client;
        _original = original;
        _learn = learn;
    }

    public static DnsOverTcpSession Open(
        ReplySocketPool replies, IReadOnlyList<ProxyHop> hops, IPEndPoint client, IPEndPoint original, Flow flow,
        DnsCache? learn, CancellationToken ct)
    {
        replies.Reserve(original);
        return new DnsOverTcpSession(replies, hops, client, original, flow, learn);
    }

    public override async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        try
        {
            await using var leg = await ProxyDialer.OpenAsync(_hops, _original, _closing.Token).ConfigureAwait(false);
            var framed = new byte[2 + datagram.Length];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)datagram.Length);
            datagram.CopyTo(framed, 2);
            await leg.Stream.WriteAsync(framed, _closing.Token).ConfigureAwait(false);
            await leg.Stream.FlushAsync(_closing.Token).ConfigureAwait(false);
            Flow.AddUp(datagram.Length);

            var length = await ProxyDialer.ReadExactlyAsync(leg.Stream, 2, _closing.Token).ConfigureAwait(false);
            var answer = await ProxyDialer.ReadExactlyAsync(leg.Stream, BinaryPrimitives.ReadUInt16BigEndian(length), _closing.Token).ConfigureAwait(false);
            _learn?.Learn(answer);
            await _replies.SendAsync(_original, _client, answer).ConfigureAwait(false);
            Flow.AddDown(answer.Length);
        }
        catch (Exception e) when (e is ProxyHandshakeException or SocketException or IOException or ObjectDisposedException or OperationCanceledException)
        {
            // The resolver retries; one lost answer is what UDP DNS expects anyway.
        }
    }

    public override ValueTask DisposeAsync()
    {
        _closing.Cancel();
        Flow.MarkClosed();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}
