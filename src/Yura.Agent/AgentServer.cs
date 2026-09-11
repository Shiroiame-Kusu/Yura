using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Authentication;
using Yura.Core.Agent;

namespace Yura.Agent;

/// <summary>How the agent was asked to run.</summary>
public sealed record AgentOptions
{
    public IPAddress Listen { get; init; } = IPAddress.IPv6Any;

    public ushort Port { get; init; } = AgentProtocol.DefaultPort;

    /// <summary>The datagram port. Zero means the same number as <see cref="Port"/>.</summary>
    public ushort UdpPort { get; init; }

    /// <summary>Whether to relay UDP at all. On by default: games need it.</summary>
    public bool Udp { get; init; } = true;

    public int MaxSessions { get; init; } = 64;

    public int MaxStreams { get; init; } = 512;

    public int MaxChannelsPerSession { get; init; } = 256;

    public TimeSpan ChannelIdleTimeout { get; init; } = TimeSpan.FromSeconds(90);

    /// <summary>How long the control connection may be silent before it is dropped.</summary>
    public TimeSpan ControlIdleTimeout { get; init; } = TimeSpan.FromSeconds(180);

    public DestinationPolicy Policy { get; init; } = DestinationPolicy.Default;
}

/// <summary>
/// The server half of the Yura agent protocol.
/// </summary>
/// <remarks>
/// <para>
/// One TLS connection per relayed TCP flow, plus one long-lived control connection per
/// client, plus one shared UDP socket for every client's datagrams. Streams are separate
/// connections rather than multiplexed over one, deliberately: multiplexing would put every
/// flow behind the slowest one, and the kernel already does flow control per connection
/// better than a userspace window would.
/// </para>
/// <para>
/// Nothing is relayed before the client's token has been verified, and nothing is relayed to
/// a destination <see cref="DestinationPolicy"/> refuses. Those two checks are the agent's
/// entire security posture, so they happen in one place each and before anything else.
/// </para>
/// </remarks>
public sealed class AgentServer : IAsyncDisposable
{
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    private readonly AgentOptions _options;
    private readonly AgentIdentity _identity;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _stopping = new();
    private readonly ConcurrentDictionary<ulong, Session> _sessions = new();
    private readonly ConcurrentDictionary<IPAddress, int> _authFailures = new();
    private readonly Stopwatch _uptime = Stopwatch.StartNew();

    private Socket? _listener;
    private Socket? _datagrams;
    private DestinationPolicy _policy = DestinationPolicy.Default;
    private IPAddress? _resolver;
    private long _streams;
    private long _bytesUp;
    private long _bytesDown;
    private long _rejected;

    public AgentServer(AgentOptions options, AgentIdentity identity, Action<string> log)
    {
        _options = options;
        _identity = identity;
        _log = log;
    }

    /// <summary>The port actually bound, which differs from the request when it asked for zero.</summary>
    public ushort Port { get; private set; }

    public ushort DatagramPort { get; private set; }

    public bool UdpAvailable => _datagrams is not null;

    private AgentProtocol.Features Features =>
        AgentProtocol.Features.Probe | AgentProtocol.Features.Resolve |
        (UdpAvailable ? AgentProtocol.Features.Udp : AgentProtocol.Features.None);

    public void Start()
    {
        // Read once, at startup: the resolver is advertised to every client and is the one
        // address the policy lets through on port 53, so it must not change under a session.
        _resolver = _options.Policy.Resolver ?? ReadResolver();
        _policy = _options.Policy with { Resolver = _resolver };

        var family = _options.Listen.AddressFamily;
        _listener = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        if (family == AddressFamily.InterNetworkV6)
        {
            // One socket for both families, so an agent reached over IPv4 and IPv6 is one
            // deployment rather than two.
            _listener.DualMode = true;
        }

        _listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Bind(new IPEndPoint(_options.Listen, _options.Port));
        _listener.Listen(128);
        Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;

        if (_options.Udp)
        {
            // The port as asked for, not as resolved: "--port 0" means both ports are the
            // kernel's choice, and the datagram port is advertised in the welcome anyway.
            var wanted = _options.UdpPort != 0 ? _options.UdpPort : _options.Port;
            _datagrams = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            if (family == AddressFamily.InterNetworkV6)
            {
                _datagrams.DualMode = true;
            }

            _datagrams.Bind(new IPEndPoint(_options.Listen, wanted));
            DatagramPort = (ushort)((IPEndPoint)_datagrams.LocalEndPoint!).Port;
        }

        _log($"listening on {_options.Listen}:{Port} (tcp)" +
             (UdpAvailable ? $" and :{DatagramPort} (udp)" : ", udp relaying disabled"));
        _log($"identity {_identity.Name}, key SHA256:{_identity.Fingerprint}");
        _log($"policy: {_policy.Describe()}");

        _ = AcceptLoopAsync(_stopping.Token);
        if (_datagrams is not null)
        {
            _ = DatagramLoopAsync(_datagrams, _stopping.Token);
        }

        _ = ExpireChannelsAsync(_stopping.Token);
    }

    public AgentStats Snapshot() => new(
        (uint)_sessions.Count,
        (uint)Interlocked.Read(ref _streams),
        (uint)_sessions.Values.Sum(s => s.Channels.Count),
        (ulong)Interlocked.Read(ref _bytesUp),
        (ulong)Interlocked.Read(ref _bytesDown),
        (ulong)_uptime.Elapsed.TotalSeconds,
        (uint)Interlocked.Read(ref _rejected));

    // -- connections -----------------------------------------------------------

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is { } listener)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            _ = HandleConnectionAsync(socket, ct);
        }
    }

    private async Task HandleConnectionAsync(Socket socket, CancellationToken ct)
    {
        var peer = (socket.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.None;
        socket.NoDelay = true;

        var tls = new SslStream(new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false);
        try
        {
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
            handshake.CancelAfter(HandshakeTimeout);

            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = _identity.Certificate,
                ClientCertificateRequired = false,
                // The system default, then checked below: this fails clearly on a platform
                // without TLS 1.3 instead of quietly negotiating something older.
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            }, handshake.Token).ConfigureAwait(false);

            if (tls.SslProtocol < SslProtocols.Tls13)
            {
                await RejectAsync(tls, AgentRejection.UnsupportedVersion,
                    "This agent requires TLS 1.3.", ct).ConfigureAwait(false);
                return;
            }

            var (kind, payload) = await AgentProtocol.ReadFrameAsync(tls, handshake.Token).ConfigureAwait(false);
            if (kind != AgentFrameKind.Hello)
            {
                await RejectAsync(tls, AgentRejection.Malformed, "Expected a hello frame.", ct).ConfigureAwait(false);
                return;
            }

            var hello = AgentHello.Decode(payload);
            if (!Authorised(hello.Token))
            {
                Interlocked.Increment(ref _rejected);
                if (_authFailures.Count > 1024)
                {
                    // Being scanned from many addresses must not turn this table into a leak.
                    _authFailures.Clear();
                }

                var failures = _authFailures.AddOrUpdate(peer, 1, (_, count) => count + 1);
                _log($"{peer}: rejected, token did not match ({failures} failure(s) from this address)");
                // A little slower each time. The token is 256 bits, so this is about keeping
                // the log readable rather than about brute force being feasible.
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(failures * 250, 2000)), ct).ConfigureAwait(false);
                await RejectAsync(tls, AgentRejection.Unauthorised, "Not authorised.", ct).ConfigureAwait(false);
                return;
            }

            _authFailures.TryRemove(peer, out _);

            if (hello.Role == AgentRole.Control)
            {
                await RunControlAsync(tls, hello, peer, ct).ConfigureAwait(false);
            }
            else
            {
                await RunStreamAsync(tls, peer, ct).ConfigureAwait(false);
            }
        }
        catch (AgentProtocolException e)
        {
            _log($"{peer}: {e.Message}");
        }
        catch (Exception e) when (e is IOException or SocketException or AuthenticationException
                                      or OperationCanceledException or ObjectDisposedException)
        {
            // Ordinary: a client went away, a scanner connected, a handshake timed out.
        }
        finally
        {
            tls.Dispose();
            socket.Dispose();
        }
    }

    /// <summary>Constant-time comparison: a token check must not leak how much of it matched.</summary>
    private bool Authorised(byte[] token) =>
        token.Length == _identity.Token.Length &&
        CryptographicOperations.FixedTimeEquals(token, _identity.Token);

    private static async Task RejectAsync(Stream stream, AgentRejection code, string message, CancellationToken ct)
    {
        try
        {
            await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Reject,
                new AgentReject(code, message).Encode(), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException
                                      or AgentProtocolException)
        {
            // The refusal is best effort; the close is what matters.
        }
    }

    // -- the control session ---------------------------------------------------

    private async Task RunControlAsync(Stream stream, AgentHello hello, IPAddress peer, CancellationToken ct)
    {
        if (_sessions.Count >= _options.MaxSessions)
        {
            await RejectAsync(stream, AgentRejection.TooMany, "The agent has too many sessions.", ct)
                .ConfigureAwait(false);
            return;
        }

        if (hello.Wanted.HasFlag(AgentProtocol.Features.Udp) && !UdpAvailable)
        {
            // Not a refusal: the client is told UDP is absent in the welcome and decides for
            // itself. Refusing would deny it the TCP relaying it can still use.
            _log($"{peer}: client asked for udp, which this agent was started without");
        }

        var session = Session.Create(peer, hello.Label);
        if (!_sessions.TryAdd(session.Key, session))
        {
            await RejectAsync(stream, AgentRejection.TooMany, "Session id collision.", ct).ConfigureAwait(false);
            return;
        }

        _log($"session {session.Key:x16} up for {peer} ({Describe(hello.Label)})");

        try
        {
            var welcome = new AgentWelcome(
                session.Id,
                session.Master,
                DatagramPort,
                AgentProtocol.MaxDatagramPayload,
                Features,
                typeof(AgentServer).Assembly.GetName().Version?.ToString(3) ?? "0",
                _identity.Name,
                _resolver?.ToString() ?? string.Empty);

            await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Welcome, welcome.Encode(), ct)
                .ConfigureAwait(false);

            while (!ct.IsCancellationRequested)
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
                idle.CancelAfter(_options.ControlIdleTimeout);

                var (kind, payload) = await AgentProtocol.ReadFrameAsync(stream, idle.Token).ConfigureAwait(false);
                switch (kind)
                {
                    case AgentFrameKind.Ping:
                        // Echoed unchanged: the client is timing its own round trip, and the
                        // agent's clock has nothing to do with it.
                        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Pong, payload, ct)
                            .ConfigureAwait(false);
                        break;

                    case AgentFrameKind.Probe:
                        var reply = await MeasureAsync(AgentProbeRequest.Decode(payload), ct).ConfigureAwait(false);
                        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Probed, reply.Encode(), ct)
                            .ConfigureAwait(false);
                        break;

                    case AgentFrameKind.Stats:
                        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.StatsReply,
                            Snapshot().Encode(), ct).ConfigureAwait(false);
                        break;

                    default:
                        throw new AgentProtocolException($"a {kind} frame does not belong on a control connection");
                }
            }
        }
        finally
        {
            _sessions.TryRemove(session.Key, out _);
            await session.DisposeAsync().ConfigureAwait(false);
            _log($"session {session.Key:x16} down for {peer}");
        }
    }

    /// <summary>
    /// Measures the round trip from the agent to a destination.
    /// </summary>
    /// <remarks>
    /// A TCP connect, the same measurement the daemon makes directly, so the two figures can
    /// be subtracted: what the client measures through the agent, minus this, is what the
    /// agent adds. That is the difference between "this route is faster" and knowing why.
    /// </remarks>
    private async Task<AgentProbeReply> MeasureAsync(AgentProbeRequest request, CancellationToken ct)
    {
        IPAddress address;
        try
        {
            address = IPAddress.TryParse(request.Target.Host, out var literal)
                ? literal
                : (await Dns.GetHostAddressesAsync(request.Target.Host, ct).ConfigureAwait(false))
                  .FirstOrDefault() ?? throw new SocketException((int)SocketError.HostNotFound);
        }
        catch (Exception e) when (e is SocketException or ArgumentException)
        {
            return new AgentProbeReply(request.RequestId, request.Target.Host, [], $"Could not resolve: {e.Message}");
        }

        var target = new IPEndPoint(address, request.Target.Port);
        if (_policy.Refuse(target) is { } refusal)
        {
            return new AgentProbeReply(request.RequestId, target.ToString(), [], refusal);
        }

        var count = Math.Clamp((int)request.Samples, 1, 10);
        var samples = new List<uint>(count);
        string? failure = null;
        for (var i = 0; i < count; i++)
        {
            using var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            var clock = Stopwatch.StartNew();
            try
            {
                await socket.ConnectAsync(target, timeout.Token).ConfigureAwait(false);
                samples.Add((uint)Math.Min(clock.Elapsed.TotalMicroseconds, uint.MaxValue));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                failure = "timed out";
            }
            catch (SocketException e)
            {
                failure = e.SocketErrorCode.ToString();
            }

            if (i + 1 < count)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(80), ct).ConfigureAwait(false);
            }
        }

        return new AgentProbeReply(request.RequestId, target.ToString(), samples.ToArray(),
            samples.Count > 0 ? null : failure);
    }

    // -- one relayed TCP flow --------------------------------------------------

    /// <remarks>
    /// Takes the TLS stream itself, not a <see cref="Stream"/>: signalling the end of the
    /// reply needs <c>close_notify</c>, which only TLS can send without ending the connection.
    /// </remarks>
    private async Task RunStreamAsync(SslStream stream, IPAddress peer, CancellationToken ct)
    {
        if (Interlocked.Read(ref _streams) >= _options.MaxStreams)
        {
            await RejectAsync(stream, AgentRejection.TooMany, "The agent has too many open streams.", ct)
                .ConfigureAwait(false);
            return;
        }

        using var handshake = CancellationTokenSource.CreateLinkedTokenSource(ct);
        handshake.CancelAfter(HandshakeTimeout);
        var (kind, payload) = await AgentProtocol.ReadFrameAsync(stream, handshake.Token).ConfigureAwait(false);
        if (kind != AgentFrameKind.Open)
        {
            await RejectAsync(stream, AgentRejection.Malformed, "Expected an open frame.", ct).ConfigureAwait(false);
            return;
        }

        var open = AgentOpen.Decode(payload);
        IPEndPoint target;
        try
        {
            target = open.Target.AsEndPoint() ?? new IPEndPoint(
                (await Dns.GetHostAddressesAsync(open.Target.Host, handshake.Token).ConfigureAwait(false))
                .FirstOrDefault() ?? throw new SocketException((int)SocketError.HostNotFound),
                open.Target.Port);
        }
        catch (Exception e) when (e is SocketException or ArgumentException)
        {
            await RejectAsync(stream, AgentRejection.ConnectFailed,
                $"Could not resolve {open.Target.Host}.", ct).ConfigureAwait(false);
            _log($"{peer}: resolve {open.Target} failed: {e.Message}");
            return;
        }

        if (_policy.Refuse(target) is { } refusal)
        {
            Interlocked.Increment(ref _rejected);
            await RejectAsync(stream, AgentRejection.DestinationRefused, refusal, ct).ConfigureAwait(false);
            _log($"{peer}: refused tcp to {target}: {refusal}");
            return;
        }

        using var upstream = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };

        var clock = Stopwatch.StartNew();
        try
        {
            using var connecting = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connecting.CancelAfter(ConnectTimeout);
            await upstream.ConnectAsync(target, connecting.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            var why = e is SocketException socketError
                ? $"The destination could not be reached ({socketError.SocketErrorCode})."
                : "The destination did not answer in time.";
            await RejectAsync(stream, AgentRejection.ConnectFailed, why, ct).ConfigureAwait(false);
            _log($"{peer}: tcp to {target} failed: {why}");
            return;
        }

        var connect = (uint)Math.Min(clock.Elapsed.TotalMicroseconds, uint.MaxValue);
        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Opened,
            new AgentOpened(upstream.LocalEndPoint?.ToString() ?? string.Empty, connect).Encode(), ct)
            .ConfigureAwait(false);

        Interlocked.Increment(ref _streams);
        _log($"{peer}: tcp to {target} open in {connect / 1000.0:0.#} ms");
        try
        {
            // From here the connection is the tunnel: no framing, so the relay is a copy and
            // there is nothing per-chunk to get wrong.
            await using var upstreamStream = new NetworkStream(upstream, ownsSocket: false);

            // Each direction tells the other side when its data has ended. Both halves need
            // it: an application that says everything and waits, and a server that answers
            // and closes, are the two commonest shapes there are.
            var toDestination = PumpAsync(stream, upstreamStream, up: true, ct, () =>
            {
                try
                {
                    upstream.Shutdown(SocketShutdown.Send);
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException)
                {
                }

                return Task.CompletedTask;
            });

            var toClient = PumpAsync(upstreamStream, stream, up: false, ct, async () =>
            {
                try
                {
                    // close_notify only: the client can still send, and the connection stays
                    // open for it. Without this the client waits for an end that never comes.
                    await stream.ShutdownAsync().ConfigureAwait(false);
                }
                catch (Exception e) when (e is IOException or ObjectDisposedException
                                             or InvalidOperationException or SocketException)
                {
                }
            });

            await Task.WhenAll(toDestination, toClient).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _streams);
        }
    }

    /// <summary>
    /// Copies one direction until it ends, then signals the end of data downstream.
    /// </summary>
    /// <remarks>
    /// Signalling the end is not optional in either direction. A client that says everything
    /// and then waits — HTTP without keepalive, a login handshake — hangs forever if its
    /// shutdown is not carried on to the destination; and a server that answers and closes
    /// leaves the client waiting for an end that never arrives. TLS 1.3 can carry it as
    /// <c>close_notify</c> without ending the connection, so both halves have a way to say it.
    /// </remarks>
    private async Task PumpAsync(Stream from, Stream to, bool up, CancellationToken ct, Func<Task> signalEnd)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            while (true)
            {
                int read;
                try
                {
                    read = await from.ReadAsync(buffer, ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException
                                             or OperationCanceledException)
                {
                    return;
                }

                if (read == 0)
                {
                    break;
                }

                try
                {
                    await to.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException
                                             or OperationCanceledException)
                {
                    return;
                }

                Interlocked.Add(ref up ? ref _bytesUp : ref _bytesDown, read);
            }

            await signalEnd().ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // -- datagrams -------------------------------------------------------------

    private async Task DatagramLoopAsync(Socket socket, CancellationToken ct)
    {
        var buffer = new byte[AgentDatagram.MaxPacketBytes];
        var plaintext = new byte[AgentDatagram.MaxPacketBytes];
        var from = new IPEndPoint(
            socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, from, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            if (received.ReceivedBytes < AgentProtocol.DatagramOverheadBytes ||
                received.RemoteEndPoint is not IPEndPoint sender)
            {
                continue;
            }

            var key = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(buffer);
            if (!_sessions.TryGetValue(key, out var session) ||
                !session.Crypto.TryOpen(buffer.AsSpan(0, received.ReceivedBytes), plaintext, out var length))
            {
                // Unknown session, forged, or replayed. Dropped without an answer: a reply
                // would tell an unauthenticated sender that the port is a Yura agent.
                continue;
            }

            // The datagram was authenticated, so its source is the session's client — even if
            // that address has changed, which is what happens when a NAT rebinds or a laptop
            // moves between networks.
            session.Peer = sender;
            session.Touch();

            try
            {
                await DispatchAsync(socket, session, plaintext.AsMemory(0, length), ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
            }
        }
    }

    private async Task DispatchAsync(Socket socket, Session session, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        switch (AgentDatagram.KindOf(body.Span))
        {
            case AgentDatagramKind.Keepalive:
                return;

            case AgentDatagramKind.Echo:
            {
                // The round trip that proves the datagram path works end to end, without
                // needing any third party to bounce off.
                var payload = body.Span[1..];
                var plain = new byte[1 + payload.Length];
                AgentDatagram.WriteSimple(plain, AgentDatagramKind.EchoReply, payload);
                await SendSealedAsync(socket, session, plain, ct).ConfigureAwait(false);
                return;
            }

            case AgentDatagramKind.Relay:
            {
                // Read out of the span before anything is awaited: a span cannot survive an
                // await, and copying the payload is what the send needs anyway.
                ushort channelId;
                IPEndPoint? target;
                byte[] payload;
                {
                    if (!AgentDatagram.TryReadRelay(body.Span, out channelId, out target, out var raw) ||
                        target is null || raw.Length > AgentProtocol.MaxDatagramPayload)
                    {
                        return;
                    }

                    payload = raw.ToArray();
                }

                var channel = await ChannelForAsync(socket, session, channelId, target, ct).ConfigureAwait(false);
                if (channel is null)
                {
                    return;
                }

                if (!channel.Target.Equals(target))
                {
                    // A channel is one destination for its lifetime; its socket is connected to
                    // that destination, which is what stops anything else being injected into it.
                    _log($"session {session.Key:x16}: channel {channelId} is bound to {channel.Target}, " +
                         $"not {target}; datagram dropped");
                    return;
                }

                await channel.SendAsync(payload, ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesUp, payload.Length);
                return;
            }

            default:
                return;
        }
    }

    private async Task<Channel?> ChannelForAsync(
        Socket socket, Session session, ushort id, IPEndPoint target, CancellationToken ct)
    {
        if (session.Channels.TryGetValue(id, out var existing))
        {
            return existing;
        }

        if (session.Channels.Count >= _options.MaxChannelsPerSession)
        {
            _log($"session {session.Key:x16}: at the channel limit; {target} refused");
            return null;
        }

        if (_policy.Refuse(target) is { } refusal)
        {
            Interlocked.Increment(ref _rejected);
            _log($"session {session.Key:x16}: refused udp to {target}: {refusal}");
            return null;
        }

        var channel = new Channel(id, target);
        if (!session.Channels.TryAdd(id, channel))
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            return session.Channels.GetValueOrDefault(id);
        }

        _ = PumpChannelAsync(socket, session, channel, ct);
        return channel;
    }

    /// <summary>Carries one channel's answers back to the client, sealed and labelled.</summary>
    private async Task PumpChannelAsync(Socket socket, Session session, Channel channel, CancellationToken ct)
    {
        var buffer = new byte[AgentProtocol.MaxDatagramPayload];
        var plain = new byte[AgentDatagram.MaxRelayHeaderBytes + AgentProtocol.MaxDatagramPayload];

        while (!ct.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await channel.Socket.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            channel.Touch();
            session.Touch();
            var length = AgentDatagram.WriteRelay(plain, channel.Id, channel.Target, buffer.AsSpan(0, received));
            try
            {
                await SendSealedAsync(socket, session, plain.AsMemory(0, length), ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesDown, received);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }
        }
    }

    private static async Task SendSealedAsync(
        Socket socket, Session session, ReadOnlyMemory<byte> plain, CancellationToken ct)
    {
        if (session.Peer is not { } peer)
        {
            return;
        }

        var packet = new byte[AgentDatagramCrypto.SealedSize(plain.Length)];
        var length = session.Crypto.Seal(plain.Span, packet);
        await socket.SendToAsync(packet.AsMemory(0, length), SocketFlags.None, peer, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Drops channels nothing has used for a while, so a long session does not accumulate
    /// sockets for every server a game ever spoke to.
    /// </summary>
    private async Task ExpireChannelsAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            var cutoff = DateTimeOffset.UtcNow - _options.ChannelIdleTimeout;
            foreach (var session in _sessions.Values)
            {
                foreach (var (id, channel) in session.Channels)
                {
                    if (channel.LastActivityUtc <= cutoff && session.Channels.TryRemove(id, out var removed))
                    {
                        await removed.DisposeAsync().ConfigureAwait(false);
                    }
                }
            }
        }
    }

    private static string Describe(string label) => label.Length == 0 ? "no label" : label;

    /// <summary>
    /// The first nameserver in <c>/etc/resolv.conf</c>, or null when there is none to offer.
    /// </summary>
    /// <remarks>
    /// Read from the file rather than asked of the system because what is wanted is an address
    /// a client can be told to send queries to, and .NET has no way to ask for that.
    /// </remarks>
    private static IPAddress? ReadResolver()
    {
        try
        {
            foreach (var line in File.ReadLines("/etc/resolv.conf"))
            {
                var text = line.AsSpan().Trim();
                if (text.StartsWith("#") || text.StartsWith(";") ||
                    !text.StartsWith("nameserver", StringComparison.Ordinal))
                {
                    continue;
                }

                // "nameserver 127.0.0.53" — and sometimes with a %scope on IPv6.
                var value = text["nameserver".Length..].Trim();
                var scope = value.IndexOf('%');
                if (scope >= 0)
                {
                    value = value[..scope];
                }

                if (IPAddress.TryParse(value, out var address))
                {
                    return address;
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }

        return null;
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _listener?.Dispose();
        _datagrams?.Dispose();

        foreach (var session in _sessions.Values)
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }

        _sessions.Clear();
        _stopping.Dispose();
    }

    // -- state -----------------------------------------------------------------

    /// <summary>One client: its keys, where its datagrams come from, and its channels.</summary>
    private sealed class Session : IAsyncDisposable
    {
        private Session(ulong key, byte[] id, byte[] master, IPAddress control, string label)
        {
            Key = key;
            Id = id;
            Master = master;
            Control = control;
            Label = label;
            Crypto = AgentDatagramCrypto.ForAgent(id, master);
        }

        public static Session Create(IPAddress control, string label)
        {
            var id = RandomNumberGenerator.GetBytes(AgentProtocol.SessionIdBytes);
            return new Session(
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(id),
                id,
                RandomNumberGenerator.GetBytes(AgentProtocol.KeyBytes),
                control,
                label);
        }

        public ulong Key { get; }

        public byte[] Id { get; }

        /// <summary>The datagram key, handed to the client inside TLS and never anywhere else.</summary>
        public byte[] Master { get; }

        public AgentDatagramCrypto Crypto { get; }

        public IPAddress Control { get; }

        public string Label { get; }

        /// <summary>Where this session's datagrams are answered: learned, and re-learned on roaming.</summary>
        public IPEndPoint? Peer { get; set; }

        public DateTimeOffset LastActivityUtc { get; private set; } = DateTimeOffset.UtcNow;

        public ConcurrentDictionary<ushort, Channel> Channels { get; } = new();

        public void Touch() => LastActivityUtc = DateTimeOffset.UtcNow;

        public async ValueTask DisposeAsync()
        {
            foreach (var channel in Channels.Values)
            {
                await channel.DisposeAsync().ConfigureAwait(false);
            }

            Channels.Clear();
            Crypto.Dispose();
        }
    }

    /// <summary>
    /// One UDP conversation: a socket of its own, connected to the destination.
    /// </summary>
    /// <remarks>
    /// A socket per channel rather than one shared socket, for two reasons. The source port a
    /// game sees stays the same for as long as it is playing, which some game servers care
    /// about; and connecting the socket makes the kernel drop anything that did not come from
    /// that destination, so nothing else can be injected into the channel.
    /// </remarks>
    private sealed class Channel : IAsyncDisposable
    {
        public Channel(ushort id, IPEndPoint target)
        {
            Id = id;
            Target = target;
            Socket = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            Socket.Connect(target);
        }

        public ushort Id { get; }

        public IPEndPoint Target { get; }

        public Socket Socket { get; }

        public DateTimeOffset LastActivityUtc { get; private set; } = DateTimeOffset.UtcNow;

        public void Touch() => LastActivityUtc = DateTimeOffset.UtcNow;

        public async Task SendAsync(byte[] payload, CancellationToken ct)
        {
            Touch();
            try
            {
                await Socket.SendAsync(payload, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                // A refused datagram is what UDP does; the game retries.
            }
        }

        public ValueTask DisposeAsync()
        {
            Socket.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
