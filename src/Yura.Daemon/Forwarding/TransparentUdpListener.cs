using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Relays the UDP datagrams TPROXY redirects to one slot through that slot's SOCKS5 proxy.
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
/// Sessions are keyed on (client, original destination). Each holds one SOCKS5 UDP
/// association and is dropped after a period of silence.
/// </remarks>
public sealed class TransparentUdpListener : IAsyncDisposable
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);

    private readonly RuleSlot _slot;
    private readonly ProxyEndpoint _proxy;
    private readonly string? _password;
    private readonly FlowRegistry _flows;
    private readonly Action<string> _log;
    private readonly ConcurrentDictionary<(IPEndPoint Client, IPEndPoint Destination), UdpSession> _sessions = new();
    private readonly CancellationTokenSource _stopping = new();
    private Socket? _socket;
    private Thread? _receiveThread;

    public TransparentUdpListener(
        RuleSlot slot, ProxyEndpoint proxy, string? password, FlowRegistry flows, Action<string> log)
    {
        _slot = slot;
        _proxy = proxy;
        _password = password;
        _flows = flows;
        _log = log;
    }

    public Guid ProxyId => _proxy.Id;

    public void Start()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.SetTransparent();
        socket.SetRawSocketOption(0 /* SOL_IP */, 20 /* IP_RECVORIGDSTADDR */, BitConverter.GetBytes(1));
        socket.Bind(new IPEndPoint(IPAddress.Any, _slot.Port));
        _socket = socket;

        _receiveThread = new Thread(() => ReceiveLoop(socket))
        {
            IsBackground = true,
            Name = $"yura-udp-{_slot.Name}",
        };
        _receiveThread.Start();
        _log($"slot {_slot.Name}: udp listener on :{_slot.Port} -> {_proxy}");
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
        if (!_sessions.TryGetValue(key, out var session))
        {
            var flow = new Flow(client, original, TransportProtocol.Udp, _slot.Rule.Id, _proxy.Name);
            _flows.Add(flow);

            try
            {
                session = await UdpSession.OpenAsync(_proxy, _password, client, original, flow, _log, _stopping.Token)
                    .ConfigureAwait(false);
            }
            catch (Exception e) when (e is ProxyHandshakeException or SocketException)
            {
                flow.MarkFailed(e.Message);
                _log($"slot {_slot.Name}: udp {client} -> {original} failed: {e.Message}");
                return;
            }

            if (!_sessions.TryAdd(key, session))
            {
                // Lost a race with a concurrent datagram for the same pair; keep the winner.
                await session.DisposeAsync().ConfigureAwait(false);
                session = _sessions[key];
            }
            else
            {
                _ = ExpireWhenIdleAsync(key, session);
            }
        }

        await session.SendAsync(datagram).ConfigureAwait(false);
    }

    private async Task ExpireWhenIdleAsync((IPEndPoint, IPEndPoint) key, UdpSession session)
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

            if (DateTimeOffset.UtcNow - session.LastActivityUtc >= IdleTimeout)
            {
                if (_sessions.TryRemove(key, out var removed))
                {
                    await removed.DisposeAsync().ConfigureAwait(false);
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

        foreach (var session in _sessions.Values)
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }

        _sessions.Clear();
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

/// <summary>One UDP flow relayed through a SOCKS5 UDP association.</summary>
internal sealed class UdpSession : IAsyncDisposable
{
    private readonly Socket _control;
    private readonly Socket _relay;
    private readonly Socket _reply;
    private readonly IPEndPoint _client;
    private readonly IPEndPoint _original;
    private readonly Flow _flow;
    private readonly byte[] _header;
    private readonly CancellationTokenSource _closing = new();

    private UdpSession(Socket control, Socket relay, Socket reply, IPEndPoint client, IPEndPoint original, Flow flow)
    {
        _control = control;
        _relay = relay;
        _reply = reply;
        _client = client;
        _original = original;
        _flow = flow;
        LastActivityUtc = DateTimeOffset.UtcNow;

        // SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT — built once per session.
        var address = original.Address.GetAddressBytes();
        _header = new byte[4 + address.Length + 2];
        _header[3] = original.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
        address.CopyTo(_header, 4);
        BinaryPrimitives.WriteUInt16BigEndian(_header.AsSpan(4 + address.Length), (ushort)original.Port);

        _ = PumpRepliesAsync(_closing.Token);
    }

    public DateTimeOffset LastActivityUtc { get; private set; }

    public static async Task<UdpSession> OpenAsync(
        ProxyEndpoint proxy, string? password, IPEndPoint client, IPEndPoint original, Flow flow,
        Action<string> log, CancellationToken ct)
    {
        IPAddress proxyAddress;
        if (!IPAddress.TryParse(proxy.Host, out proxyAddress!))
        {
            var addresses = await Dns.GetHostAddressesAsync(proxy.Host, ct).ConfigureAwait(false);
            proxyAddress = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                           ?? throw new SocketException((int)SocketError.HostNotFound);
        }

        // The association lives as long as this TCP control connection.
        var control = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        control.SetMark(PolicyRouting.BypassMark);
        await control.ConnectAsync(new IPEndPoint(proxyAddress, proxy.Port), ct).ConfigureAwait(false);

        var relayEndpoint = await Socks5UdpAssociateAsync(control, proxy.Username, password, proxyAddress, ct)
            .ConfigureAwait(false);

        var relay = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        relay.SetMark(PolicyRouting.BypassMark);
        await relay.ConnectAsync(relayEndpoint, ct).ConfigureAwait(false);

        // Replies must come FROM the address the application addressed. Binding a
        // transparent socket to a foreign address is exactly what IP_TRANSPARENT permits.
        var reply = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        reply.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        reply.SetTransparent();
        reply.SetMark(PolicyRouting.BypassMark);
        reply.Bind(original);

        flow.MarkEstablished();
        return new UdpSession(control, relay, reply, client, original, flow);
    }

    private static async Task<IPEndPoint> Socks5UdpAssociateAsync(
        Socket control, string? username, string? password, IPAddress proxyAddress, CancellationToken ct)
    {
        // Reuse the CONNECT client's negotiation by speaking the greeting ourselves; the
        // only difference from CONNECT is the command byte and the meaning of the reply.
        var wantsAuth = !string.IsNullOrEmpty(username);
        await control.SendAsync(wantsAuth ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, ct).ConfigureAwait(false);
        var choice = await ReadExactlyAsync(control, 2, ct).ConfigureAwait(false);
        if (choice[0] != 5)
        {
            throw new ProxyHandshakeException("The proxy did not answer as SOCKS5.");
        }

        if (choice[1] == 2 && wantsAuth)
        {
            var user = System.Text.Encoding.UTF8.GetBytes(username!);
            var pass = System.Text.Encoding.UTF8.GetBytes(password ?? string.Empty);
            var frame = new byte[3 + user.Length + pass.Length];
            frame[0] = 1;
            frame[1] = (byte)user.Length;
            user.CopyTo(frame, 2);
            frame[2 + user.Length] = (byte)pass.Length;
            pass.CopyTo(frame, 3 + user.Length);
            await control.SendAsync(frame, ct).ConfigureAwait(false);
            var auth = await ReadExactlyAsync(control, 2, ct).ConfigureAwait(false);
            if (auth[1] != 0)
            {
                throw new ProxyHandshakeException("The proxy rejected the username or password.");
            }
        }
        else if (choice[1] != 0)
        {
            throw new ProxyHandshakeException("The proxy requires authentication for UDP.");
        }

        // UDP ASSOCIATE with an unspecified client address: we will send from whatever
        // port the relay socket gets.
        await control.SendAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, ct).ConfigureAwait(false);
        var reply = await ReadExactlyAsync(control, 4, ct).ConfigureAwait(false);
        if (reply[1] != 0)
        {
            throw new ProxyHandshakeException(reply[1] == 7
                ? "This proxy does not support UDP."
                : $"The proxy refused UDP ASSOCIATE (reply {reply[1]:#x}).");
        }

        if (reply[3] != 1)
        {
            throw new ProxyHandshakeException("The proxy returned a non-IPv4 relay address, which is not supported yet.");
        }

        var bound = await ReadExactlyAsync(control, 6, ct).ConfigureAwait(false);
        var relayAddress = new IPAddress(bound.AsSpan(0, 4));
        var relayPort = BinaryPrimitives.ReadUInt16BigEndian(bound.AsSpan(4));

        // 0.0.0.0 means "same host as the control connection".
        if (relayAddress.Equals(IPAddress.Any))
        {
            relayAddress = proxyAddress;
        }

        return new IPEndPoint(relayAddress, relayPort);
    }

    public async Task SendAsync(byte[] datagram)
    {
        LastActivityUtc = DateTimeOffset.UtcNow;
        var framed = new byte[_header.Length + datagram.Length];
        _header.CopyTo(framed, 0);
        datagram.CopyTo(framed, _header.Length);
        try
        {
            await _relay.SendAsync(framed, _closing.Token).ConfigureAwait(false);
            _flow.AddUp(datagram.Length);
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
            try
            {
                await _reply.SendToAsync(buffer.AsMemory(offset, received - offset), _client, ct).ConfigureAwait(false);
                _flow.AddDown(received - offset);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }
        }
    }

    private static async Task<byte[]> ReadExactlyAsync(Socket socket, int count, CancellationToken ct)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new ProxyHandshakeException("The proxy closed the connection during UDP ASSOCIATE.");
            }

            offset += read;
        }

        return buffer;
    }

    public ValueTask DisposeAsync()
    {
        _closing.Cancel();
        _flow.MarkClosed();
        _relay.Dispose();
        _reply.Dispose();
        _control.Dispose();
        _closing.Dispose();
        return ValueTask.CompletedTask;
    }
}
