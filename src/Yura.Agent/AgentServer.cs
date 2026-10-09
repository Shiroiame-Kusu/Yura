using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Authentication;
using Yura.Core.Agent;
using Yura.Core.Net;

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

    /// <summary>
    /// Whether a client may have full-cone UDP. On by default: it is what makes a peer-to-peer
    /// game reachable through the agent. See <see cref="AgentProtocol.Features.FullCone"/>.
    /// </summary>
    public bool FullCone { get; init; } = true;

    /// <summary>
    /// The ports full-cone channels are given, which is what a firewall in front of the agent
    /// has to let in for peers to reach a game. When every one is taken, a channel gets a port
    /// the kernel chooses instead.
    /// </summary>
    public PortRange ConePorts { get; init; } = DefaultConePorts;

    public static readonly PortRange DefaultConePorts = new(40000, 40999);

    /// <summary>
    /// How long a full-cone channel keeps its port after the client last sent on it.
    /// </summary>
    /// <remarks>
    /// The mapping a game advertises to its peers, so not the ninety seconds an ordinary channel
    /// gets; see <see cref="AgentProtocol.ConeMappingLifetime"/>. Only the client's own traffic
    /// counts, so nobody else can hold the port open.
    /// </remarks>
    public TimeSpan ConeIdleTimeout { get; init; } = AgentProtocol.ConeMappingLifetime;

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

    // Replaced, never mutated: the machine's own addresses are refreshed while it runs.
    private volatile DestinationPolicy _policy = DestinationPolicy.Default;
    private IPAddress? _resolver;
    private long _streams;
    private long _bytesUp;
    private long _bytesDown;
    private long _rejected;
    private long _oversize;

    /// <summary>
    /// The largest datagram there is, which is what the sockets facing the internet read into:
    /// a smaller buffer cuts a larger datagram short without a word, and a DTLS handshake given
    /// a truncated certificate simply never finishes.
    /// </summary>
    private const int MaxReceivedDatagram = 65535;

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
        RefreshLocalAddresses();

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

    /// <summary>Datagrams from the far side dropped as too large for their client to take.</summary>
    public long OversizeDropped => Interlocked.Read(ref _oversize);

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

        // Granted per session, and used per channel: the client still chooses, for each one,
        // whether it stands for a socket or for one destination.
        var cone = hello.Wanted.HasFlag(AgentProtocol.Features.FullCone) && _options.FullCone && UdpAvailable;

        // Granted to whoever asks: this agent can always put pieces back together, and a client
        // that did not ask is one that cannot, so it is never sent any.
        var fragments = hello.Wanted.HasFlag(AgentProtocol.Features.Fragments) && UdpAvailable;
        var session = Session.Create(peer, hello.Label, cone, fragments);
        if (!_sessions.TryAdd(session.Key, session))
        {
            await RejectAsync(stream, AgentRejection.TooMany, "Session id collision.", ct).ConfigureAwait(false);
            return;
        }

        _log($"session {session.Key:x16} up for {peer} ({Describe(hello.Label)})" +
             (cone ? $", full-cone udp on ports {_options.ConePorts}" : string.Empty));

        // Frames go out from two places — this loop, and the task measuring probes — and must
        // not interleave on the wire.
        using var writing = new SemaphoreSlim(1, 1);

        // Probes are measured off this loop, one at a time and so answered in the order they
        // were asked. A measurement takes seconds per sample, and measured here it held every
        // ping behind it: the client's ping timed out and closed the session, and every UDP
        // flow on it with the session.
        var probes = System.Threading.Channels.Channel.CreateBounded<AgentProbeRequest>(
            new System.Threading.Channels.BoundedChannelOptions(8) { SingleReader = true, SingleWriter = true });
        using var ending = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var prober = AnswerProbesAsync(stream, probes.Reader, writing, ending.Token);

        try
        {
            var welcome = new AgentWelcome(
                session.Id,
                session.Master,
                DatagramPort,
                AgentProtocol.MaxDatagramPayload,
                Features | (session.Cone ? AgentProtocol.Features.FullCone : AgentProtocol.Features.None)
                         | (session.Fragments ? AgentProtocol.Features.Fragments : AgentProtocol.Features.None),
                typeof(AgentServer).Assembly.GetName().Version?.ToString(3) ?? "0",
                _identity.Name,
                _resolver?.ToString() ?? string.Empty);

            await WriteFrameAsync(stream, writing, AgentFrameKind.Welcome, welcome.Encode(), ct).ConfigureAwait(false);

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
                        await WriteFrameAsync(stream, writing, AgentFrameKind.Pong, payload, ct).ConfigureAwait(false);
                        break;

                    case AgentFrameKind.Probe:
                        await probes.Writer.WriteAsync(AgentProbeRequest.Decode(payload), idle.Token).ConfigureAwait(false);
                        break;

                    case AgentFrameKind.Stats:
                        await WriteFrameAsync(stream, writing, AgentFrameKind.StatsReply, Snapshot().Encode(), ct)
                            .ConfigureAwait(false);
                        break;

                    default:
                        throw new AgentProtocolException($"a {kind} frame does not belong on a control connection");
                }
            }
        }
        finally
        {
            probes.Writer.TryComplete();
            await ending.CancelAsync().ConfigureAwait(false);
            try
            {
                await prober.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Its failures are the connection's, which is ending anyway.
            }

            _sessions.TryRemove(session.Key, out _);
            await session.DisposeAsync().ConfigureAwait(false);
            _log($"session {session.Key:x16} down for {peer}");
        }
    }

    /// <summary>Measures each probe in turn and sends its answer, for as long as the session lasts.</summary>
    private async Task AnswerProbesAsync(
        Stream stream, System.Threading.Channels.ChannelReader<AgentProbeRequest> requests, SemaphoreSlim writing,
        CancellationToken ct)
    {
        try
        {
            await foreach (var request in requests.ReadAllAsync(ct).ConfigureAwait(false))
            {
                var reply = await MeasureAsync(request, ct).ConfigureAwait(false);
                await WriteFrameAsync(stream, writing, AgentFrameKind.Probed, reply.Encode(), ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException
                                     or AgentProtocolException or SocketException)
        {
            // The connection is going; the read loop reports that.
        }
    }

    private static async Task WriteFrameAsync(
        Stream stream, SemaphoreSlim writing, AgentFrameKind kind, byte[] payload, CancellationToken ct)
    {
        await writing.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await AgentProtocol.WriteFrameAsync(stream, kind, payload, ct).ConfigureAwait(false);
        }
        finally
        {
            writing.Release();
        }
    }

    /// <summary>
    /// Measures the round trip from the agent to a destination.
    /// </summary>
    /// <remarks>
    /// A TCP connect, the same measurement the daemon makes directly, so the two figures can
    /// be subtracted: what the client measures through the agent, minus this, is what the
    /// agent adds. That is the difference between "this route is faster" and knowing why. A
    /// refusal counts as an answer, as it does in the daemon: it comes from the destination,
    /// and a game server that listens only on UDP refuses every TCP connect.
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
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
            {
                // Refused by the destination itself, one round trip away: an answer. A game server
                // listening only on UDP refuses every TCP connect, and is no less there for it.
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
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            // Said as such: a refusal is the destination answering, and a measurement counts it.
            await RejectAsync(stream, AgentRejection.ConnectionRefused, "The destination refused the connection.", ct)
                .ConfigureAwait(false);
            _log($"{peer}: tcp to {target} refused");
            return;
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

            case AgentDatagramKind.Relay or AgentDatagramKind.ConeRelay:
            {
                var wantsCone = AgentDatagram.KindOf(body.Span) == AgentDatagramKind.ConeRelay;

                // Read out of the span before anything is awaited: a span cannot survive an
                // await, and copying the payload is what the send needs anyway.
                ushort channelId;
                IPEndPoint? target;
                byte[] payload;
                {
                    var largest = session.Fragments ? AgentProtocol.MaxFragmentedPayload : AgentProtocol.MaxDatagramPayload;
                    if (!AgentDatagram.TryReadRelay(body.Span, out channelId, out target, out var raw) ||
                        target is null || raw.Length > largest)
                    {
                        return;
                    }

                    payload = raw.ToArray();
                }

                var channel = await ChannelForAsync(socket, session, channelId, target, wantsCone, ct).ConfigureAwait(false);
                if (channel is not null && channel is ConeChannel != wantsCone)
                {
                    // A channel is what its first datagram made it. One of the other kind with
                    // the same number is a client confused about its own channels, and is
                    // dropped rather than guessed at.
                    _log($"session {session.Key:x16}: channel {channelId} is " +
                         $"{(channel is ConeChannel ? "full-cone" : "bound to one destination")}; " +
                         "a datagram of the other kind on it was dropped");
                    return;
                }

                switch (channel)
                {
                    case ConeChannel cone:
                        // A full-cone channel may send anywhere the policy allows, decided once
                        // per destination.
                        if (!cone.MaySendTo(target, _policy, out var refusal))
                        {
                            if (refusal is not null)
                            {
                                Interlocked.Increment(ref _rejected);
                                _log($"session {session.Key:x16}: refused udp to {target}: {refusal}");
                            }

                            return;
                        }

                        await cone.SendAsync(target, payload, ct).ConfigureAwait(false);
                        break;

                    case DestinationChannel fixedChannel:
                        if (!fixedChannel.Target.Equals(target))
                        {
                            // A channel is one destination for its lifetime; its socket is
                            // connected to that destination, which is what stops anything else
                            // being injected into it.
                            _log($"session {session.Key:x16}: channel {channelId} is bound to {fixedChannel.Target}, " +
                                 $"not {target}; datagram dropped");
                            return;
                        }

                        await fixedChannel.SendAsync(payload, ct).ConfigureAwait(false);
                        break;

                    default:
                        return;
                }

                Interlocked.Add(ref _bytesUp, payload.Length);
                return;
            }

            case AgentDatagramKind.Fragment:
            {
                // A piece of a datagram too large for one packet. What the pieces make up is
                // handled as if it had arrived whole, provided it is a relayed datagram; anything
                // else they claim to be is dropped.
                if (session.Fragments && session.Assembler.Add(body.Span) is { } whole &&
                    AgentDatagram.KindOf(whole) is AgentDatagramKind.Relay or AgentDatagramKind.ConeRelay)
                {
                    await DispatchAsync(socket, session, whole, ct).ConfigureAwait(false);
                }

                return;
            }

            default:
                return;
        }
    }

    private async Task<Channel?> ChannelForAsync(
        Socket socket, Session session, ushort id, IPEndPoint target, bool cone, CancellationToken ct)
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

        Channel channel;
        if (cone)
        {
            if (!session.Cone)
            {
                // Not granted — this agent was started with --no-full-cone, or the client did
                // not ask — so the client should not be sending these.
                _log($"session {session.Key:x16}: full-cone channel {id} refused: not granted to this session");
                return null;
            }

            // Every destination is checked as it is sent to, not only the first.
            var opened = ConeChannel.Open(id, _options);
            if (!opened.InRange)
            {
                _log($"session {session.Key:x16}: every full-cone port in {_options.ConePorts} is in use; " +
                     $"channel {id} is on port {opened.Port}, which a firewall that opens only the range will keep peers from");
            }

            channel = opened;
        }
        else
        {
            if (_policy.Refuse(target) is { } refusal)
            {
                Interlocked.Increment(ref _rejected);
                _log($"session {session.Key:x16}: refused udp to {target}: {refusal}");
                return null;
            }

            channel = new DestinationChannel(id, target);
        }

        if (!session.Channels.TryAdd(id, channel))
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            return session.Channels.GetValueOrDefault(id);
        }

        _ = channel is ConeChannel coneChannel
            ? PumpConeAsync(socket, session, coneChannel, ct)
            : PumpChannelAsync(socket, session, (DestinationChannel)channel, ct);
        return channel;
    }

    /// <summary>Carries one channel's answers back to the client, sealed and labelled.</summary>
    private async Task PumpChannelAsync(Socket socket, Session session, DestinationChannel channel, CancellationToken ct)
    {
        var buffer = new byte[MaxReceivedDatagram];
        var plain = new byte[AgentDatagram.MaxRelayHeaderBytes + MaxReceivedDatagram];

        while (!ct.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await channel.Socket.ReceiveAsync(buffer, ct).ConfigureAwait(false);
            }
            catch (SocketException e) when (IsPassing(e))
            {
                continue;
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            channel.Touch();
            session.Touch();
            if (!Deliverable(session, channel, received))
            {
                continue;
            }

            var length = AgentDatagram.WriteRelay(plain, channel.Id, channel.Target, buffer.AsSpan(0, received));
            if (!await RelayToClientAsync(socket, session, plain.AsMemory(0, length), received, ct).ConfigureAwait(false))
            {
                return;
            }
        }
    }

    /// <summary>
    /// Carries everything a full-cone channel hears back to the client, labelled with who sent it.
    /// </summary>
    /// <remarks>
    /// The sender is checked against the same policy as a destination, so the agent's own
    /// network cannot write into a client's game; and receiving does not keep the channel, so
    /// whoever is sending cannot hold its port open once the client has gone quiet.
    /// </remarks>
    private async Task PumpConeAsync(Socket socket, Session session, ConeChannel channel, CancellationToken ct)
    {
        var buffer = new byte[MaxReceivedDatagram];
        var plain = new byte[AgentDatagram.MaxRelayHeaderBytes + MaxReceivedDatagram];
        var any = new IPEndPoint(
            channel.Socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await channel.Socket.ReceiveFromAsync(buffer, SocketFlags.None, any, ct).ConfigureAwait(false);
            }
            catch (SocketException e) when (IsPassing(e))
            {
                continue;
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            if (received.RemoteEndPoint is not IPEndPoint raw)
            {
                continue;
            }

            // A dual-stack socket reports an IPv4 sender as ::ffff:a.b.c.d; the client sent to,
            // and expects to hear from, the plain IPv4 address.
            var from = raw.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(raw.Address.MapToIPv4(), raw.Port) : raw;
            if (!channel.MayHearFrom(from, _policy) || !Deliverable(session, channel, received.ReceivedBytes))
            {
                continue;
            }

            var length = AgentDatagram.WriteRelay(
                plain, channel.Id, from, buffer.AsSpan(0, received.ReceivedBytes), cone: true);
            if (!await RelayToClientAsync(socket, session, plain.AsMemory(0, length), received.ReceivedBytes, ct)
                    .ConfigureAwait(false))
            {
                return;
            }
        }
    }

    /// <summary>
    /// Whether a datagram from the far side can go to the client at all: in one packet, or in
    /// pieces to a client that takes them.
    /// </summary>
    /// <remarks>
    /// Said in the log once per channel when it cannot, because a datagram that silently never
    /// arrives is the hardest thing there is to find.
    /// </remarks>
    private bool Deliverable(Session session, Channel channel, int length)
    {
        var largest = session.Fragments ? AgentProtocol.MaxFragmentedPayload : AgentProtocol.MaxDatagramPayload;
        if (length <= largest)
        {
            return true;
        }

        Interlocked.Increment(ref _oversize);
        if (channel.FirstOversize())
        {
            _log($"session {session.Key:x16}: channel {channel.Id} dropped a {length}-byte datagram, over the limit of {largest}" +
                 (session.Fragments ? string.Empty : "; this client cannot take one in pieces, and updating it would let it"));
        }

        return false;
    }

    /// <summary>
    /// Seals one relayed datagram to the client, in pieces when it is too large for one packet;
    /// false once there is nobody to send to.
    /// </summary>
    private async Task<bool> RelayToClientAsync(
        Socket socket, Session session, ReadOnlyMemory<byte> plain, int payloadBytes, CancellationToken ct)
    {
        try
        {
            if (plain.Length <= AgentDatagram.MaxBodyBytes)
            {
                await SendSealedAsync(socket, session, plain, ct).ConfigureAwait(false);
            }
            else
            {
                foreach (var fragment in AgentDatagram.Split(plain.Span, session.NewFragmentId()))
                {
                    await SendSealedAsync(socket, session, fragment, ct).ConfigureAwait(false);
                }
            }

            Interlocked.Add(ref _bytesDown, payloadBytes);
            return true;
        }
        catch (SocketException)
        {
            // One datagram lost on the way to the client — a full send buffer, a route that
            // flapped. UDP is allowed to lose it; the channel is not worth ending over it.
            return true;
        }
        catch (Exception e) when (e is ObjectDisposedException or OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>
    /// An error a UDP socket reports and then carries on from: an ICMP answer to something it
    /// sent earlier.
    /// </summary>
    /// <remarks>
    /// Ending the channel's pump on one meant a game server that restarted — answering "port
    /// unreachable" for a second — left the channel deaf for the rest of the session.
    /// </remarks>
    private static bool IsPassing(SocketException e) => e.SocketErrorCode is SocketError.ConnectionRefused
        or SocketError.ConnectionReset or SocketError.HostUnreachable or SocketError.NetworkUnreachable
        or SocketError.TimedOut;

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
        var rounds = 0;
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

            // A minute is soon enough to notice an address the machine gained or lost.
            if (++rounds % 4 == 0)
            {
                RefreshLocalAddresses();
            }

            var now = DateTimeOffset.UtcNow;
            foreach (var session in _sessions.Values)
            {
                foreach (var (id, channel) in session.Channels)
                {
                    var idle = channel is ConeChannel ? _options.ConeIdleTimeout : _options.ChannelIdleTimeout;
                    if (channel.LastActivityUtc <= now - idle && session.Channels.TryRemove(id, out var removed))
                    {
                        await removed.DisposeAsync().ConfigureAwait(false);
                    }
                }
            }
        }
    }

    private static string Describe(string label) => label.Length == 0 ? "no label" : label;

    /// <summary>
    /// Re-reads the machine's own addresses into the policy, unless the operator gave a list.
    /// </summary>
    private void RefreshLocalAddresses()
    {
        if (_options.Policy.LocalAddresses.Count == 0)
        {
            _policy = _policy with { LocalAddresses = DestinationPolicy.ReadLocalAddresses() };
        }
    }

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
        private int _nextFragmentId;

        private Session(ulong key, byte[] id, byte[] master, IPAddress control, string label, bool cone, bool fragments)
        {
            Key = key;
            Id = id;
            Master = master;
            Control = control;
            Label = label;
            Cone = cone;
            Fragments = fragments;
            Crypto = AgentDatagramCrypto.ForAgent(id, master);
        }

        public static Session Create(IPAddress control, string label, bool cone, bool fragments)
        {
            var id = RandomNumberGenerator.GetBytes(AgentProtocol.SessionIdBytes);
            return new Session(
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(id),
                id,
                RandomNumberGenerator.GetBytes(AgentProtocol.KeyBytes),
                control,
                label,
                cone,
                fragments);
        }

        /// <summary>True when the session was granted full-cone UDP: its channels are the client's sockets.</summary>
        public bool Cone { get; }

        /// <summary>True when datagrams too large for one packet travel in pieces, both ways.</summary>
        public bool Fragments { get; }

        /// <summary>Where the client's pieces are put back together.</summary>
        public AgentFragmentAssembler Assembler { get; } = new();

        public uint NewFragmentId() => (uint)Interlocked.Increment(ref _nextFragmentId);

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

    /// <summary>One datagram channel's socket at the agent, and when it was last used.</summary>
    private abstract class Channel(ushort id, Socket socket) : IAsyncDisposable
    {
        public ushort Id { get; } = id;

        public Socket Socket { get; } = socket;

        public DateTimeOffset LastActivityUtc { get; private set; } = DateTimeOffset.UtcNow;

        private int _oversizeReported;

        public void Touch() => LastActivityUtc = DateTimeOffset.UtcNow;

        /// <summary>True the first time only: an oversized datagram is said once per channel.</summary>
        public bool FirstOversize() => Interlocked.Exchange(ref _oversizeReported, 1) == 0;

        public ValueTask DisposeAsync()
        {
            Socket.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// One UDP conversation: a socket of its own, connected to the destination.
    /// </summary>
    /// <remarks>
    /// A socket per channel rather than one shared socket, for two reasons. The source port a
    /// game sees stays the same for as long as it is playing, which some game servers care
    /// about; and connecting the socket makes the kernel drop anything that did not come from
    /// that destination, so nothing else can be injected into the channel. What it costs is
    /// peer-to-peer: each peer sees a different port, which a game calls a Strict NAT. A
    /// session that asked for full cone gets <see cref="ConeChannel"/> instead.
    /// </remarks>
    private sealed class DestinationChannel(ushort id, IPEndPoint target) : Channel(id, Connected(target))
    {
        public IPEndPoint Target { get; } = target;

        private static Socket Connected(IPEndPoint target)
        {
            var socket = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Connect(target);
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            return socket;
        }

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
    }

    /// <summary>
    /// One of a client's sockets, in a full-cone session: one address here for every peer it
    /// sends to, open to anyone who sends to that address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// That is what a peer-to-peer game needs. The address its matchmaking server sees is the
    /// address every other player is told, and a player the game has never sent to can still
    /// get through — what a game calls an Open NAT, where a socket per destination is a Strict
    /// one. Whether strangers really can get through is up to the firewall in front of the
    /// agent: one that lets in <see cref="AgentOptions.ConePorts"/> makes it Open, and a
    /// stateful one that does not still leaves it Moderate, which hole punching copes with.
    /// </para>
    /// <para>
    /// The agent's policy holds both ways, decided once per address: for each destination a
    /// client sends to, and for each sender a client hears from. And only the client's own
    /// traffic keeps the port, so nobody else can hold it open after the client goes quiet.
    /// </para>
    /// </remarks>
    private sealed class ConeChannel : Channel
    {
        /// <summary>Decisions kept per channel before they are made afresh, so a crowd cannot grow it.</summary>
        private const int MaxRemembered = 4096;

        // Each touched by one task only — destinations by the datagram loop, senders by this
        // channel's pump — so neither needs a lock.
        private readonly Dictionary<IPEndPoint, bool> _destinations = [];
        private readonly Dictionary<IPEndPoint, bool> _senders = [];
        private DestinationPolicy? _destinationsUnder;
        private DestinationPolicy? _sendersUnder;

        private ConeChannel(ushort id, Socket socket, bool inRange)
            : base(id, socket) => InRange = inRange;

        /// <summary>
        /// False when every port in the configured range was taken and the kernel chose one: it
        /// relays the same, but a firewall that opens only the range keeps peers from it.
        /// </summary>
        public bool InRange { get; }

        public int Port => ((IPEndPoint)Socket.LocalEndPoint!).Port;

        public static ConeChannel Open(ushort id, AgentOptions options)
        {
            var range = options.ConePorts;
            var count = Math.Max(0, range.To - range.From + 1);
            var start = count == 0 ? 0 : Random.Shared.Next(count);
            for (var i = 0; i < count; i++)
            {
                var socket = NewSocket(options.Listen);
                try
                {
                    socket.Bind(new IPEndPoint(options.Listen, range.From + (start + i) % count));
                    return new ConeChannel(id, socket, inRange: true);
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse)
                {
                    socket.Dispose();
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }

            var fallback = NewSocket(options.Listen);
            try
            {
                fallback.Bind(new IPEndPoint(options.Listen, 0));
            }
            catch
            {
                fallback.Dispose();
                throw;
            }

            return new ConeChannel(id, fallback, inRange: false);
        }

        private static Socket NewSocket(IPAddress listen)
        {
            var socket = new Socket(listen.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (listen.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // Peers of either family on one port, as the agent's own sockets are.
                socket.DualMode = true;
            }

            return socket;
        }

        /// <summary>Whether this channel may send there.</summary>
        /// <param name="refusal">Why not, the first time only, so a refusal is logged once.</param>
        public bool MaySendTo(IPEndPoint destination, DestinationPolicy policy, out string? refusal) =>
            Decide(_destinations, ref _destinationsUnder, policy, destination, out refusal);

        /// <summary>Whether what this sender sent may be passed to the client.</summary>
        public bool MayHearFrom(IPEndPoint sender, DestinationPolicy policy) =>
            Decide(_senders, ref _sendersUnder, policy, sender, out _);

        private static bool Decide(
            Dictionary<IPEndPoint, bool> decided, ref DestinationPolicy? decidedUnder, DestinationPolicy policy,
            IPEndPoint endpoint, out string? refusal)
        {
            refusal = null;
            if (!ReferenceEquals(decidedUnder, policy) || decided.Count >= MaxRemembered)
            {
                // The policy changed — the machine's addresses are re-read every minute — or the
                // channel has heard from a crowd: decide afresh.
                decided.Clear();
                decidedUnder = policy;
            }

            if (decided.TryGetValue(endpoint, out var allowed))
            {
                return allowed;
            }

            refusal = policy.Refuse(endpoint);
            decided[endpoint] = refusal is null;
            return refusal is null;
        }

        public async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
        {
            // Only the client's own traffic keeps the port.
            Touch();
            try
            {
                await Socket.SendToAsync(payload, SocketFlags.None, destination, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                // A refused datagram is what UDP does; the game retries.
            }
        }
    }
}
