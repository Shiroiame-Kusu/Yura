using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Yura.Core.Agent;

/// <summary>Raised when an agent refuses a connection, with the reason it gave.</summary>
public sealed class AgentRefusedException(AgentRejection code, string message) : Exception(message)
{
    public AgentRejection Code { get; } = code;
}

/// <summary>How to reach one agent.</summary>
public sealed record AgentClientOptions
{
    public required string Host { get; init; }

    public required ushort Port { get; init; }

    /// <summary>The shared token, base64url, as it appears in the connect string.</summary>
    public required string Token { get; init; }

    /// <summary>The agent's pinned public key, base64url SHA-256 of its SubjectPublicKeyInfo.</summary>
    public required string Fingerprint { get; init; }

    /// <summary>What to call ourselves in the agent's log.</summary>
    public string Label { get; init; } = "yura";

    /// <summary>
    /// Applied to every socket before it connects. The daemon uses it to set the bypass mark,
    /// without which its own upstream traffic would be captured by its own classifier.
    /// </summary>
    public Action<Socket>? ConfigureSocket { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Ask for full-cone UDP, so a game routed through the agent can be reached by its peers.
    /// See <see cref="AgentProtocol.Features.FullCone"/>.
    /// </summary>
    public bool FullCone { get; init; }

    /// <summary>
    /// Ask to carry datagrams too large for one packet in pieces. On unless a test needs a client
    /// from before it. See <see cref="AgentProtocol.Features.Fragments"/>.
    /// </summary>
    public bool Fragments { get; init; } = true;

    public static AgentClientOptions From(AgentConnection connection, string? label = null) => new()
    {
        Host = connection.Host,
        Port = connection.Port,
        Token = connection.Token,
        Fingerprint = connection.Fingerprint,
        Label = label ?? "yura",
    };
}

/// <summary>
/// The client half of the agent protocol: connecting, pinning, and the two kinds of
/// connection the protocol has.
/// </summary>
public static class AgentClient
{
    /// <summary>
    /// Connects and authenticates, leaving the connection at the point where its role takes
    /// over.
    /// </summary>
    /// <remarks>
    /// The agent's certificate is checked against the pinned public key and nothing else: not
    /// the name, not a certificate authority, not the expiry. That is stronger than the usual
    /// checks rather than weaker — the one key that is allowed is named in the configuration —
    /// and it is what lets an agent be a server with an IP address and no domain at all.
    /// </remarks>
    public static async Task<(Socket Socket, SslStream Stream)> ConnectAsync(
        AgentClientOptions options, AgentRole role, CancellationToken ct)
    {
        if (!AgentConnection.TryDecodeToken(options.Token, out var token))
        {
            throw new AgentProtocolException("the agent token is not a 32-byte value");
        }

        if (!AgentConnection.TryDecodeFingerprint(options.Fingerprint, out var expected))
        {
            throw new AgentProtocolException("the agent key fingerprint is not a SHA-256 value");
        }

        var address = IPAddress.TryParse(options.Host, out var literal)
            ? literal
            : (await Dns.GetHostAddressesAsync(options.Host, ct).ConfigureAwait(false)).FirstOrDefault()
              ?? throw new SocketException((int)SocketError.HostNotFound);

        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        options.ConfigureSocket?.Invoke(socket);

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(options.Timeout);
            await socket.ConnectAsync(new IPEndPoint(address, options.Port), timeout.Token).ConfigureAwait(false);

            var tls = await HandshakeAsync(
                new NetworkStream(socket, ownsSocket: false), options, role, timeout.Token).ConfigureAwait(false);
            return (socket, tls);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Authenticates over a byte stream that is already connected to the agent.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="ConnectAsync"/> because the stream is not always a socket the
    /// client opened: an agent can be a later hop of a chain, reached through a proxy that has
    /// already been asked to connect to it. TLS over whatever got us there works the same way.
    /// </remarks>
    public static async Task<SslStream> HandshakeAsync(
        Stream inner, AgentClientOptions options, AgentRole role, CancellationToken ct)
    {
        if (!AgentConnection.TryDecodeToken(options.Token, out var token))
        {
            throw new AgentProtocolException("the agent token is not a 32-byte value");
        }

        if (!AgentConnection.TryDecodeFingerprint(options.Fingerprint, out var expected))
        {
            throw new AgentProtocolException("the agent key fingerprint is not a SHA-256 value");
        }

        var tls = new SslStream(inner, leaveInnerStreamOpen: false,
            (_, certificate, _, _) => certificate is not null && Matches(certificate, expected));
        try
        {
            try
            {
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = options.Host,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, ct).ConfigureAwait(false);
            }
            catch (AuthenticationException e)
            {
                throw new AgentProtocolException(
                    "The agent's key is not the one this exit was configured with. " +
                    "Either it was reinstalled — take a new connect string from it — or this is not that agent. " +
                    $"({e.Message})");
            }

            if (tls.SslProtocol < SslProtocols.Tls13)
            {
                throw new AgentProtocolException("the agent negotiated something older than TLS 1.3");
            }

            var wanted = AgentProtocol.Features.Udp | AgentProtocol.Features.Probe | AgentProtocol.Features.Resolve;
            if (options.FullCone && role == AgentRole.Control)
            {
                // A session's property, so only the control connection that makes one asks.
                wanted |= AgentProtocol.Features.FullCone;
            }

            if (options.Fragments && role == AgentRole.Control)
            {
                wanted |= AgentProtocol.Features.Fragments;
            }

            await AgentProtocol.WriteFrameAsync(tls, AgentFrameKind.Hello,
                new AgentHello(role, token, wanted, options.Label).Encode(), ct).ConfigureAwait(false);

            return tls;
        }
        catch
        {
            tls.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Asks an authenticated stream connection to be joined to a destination.
    /// </summary>
    /// <remarks>
    /// After this returns, the stream is the tunnel: no framing, so whatever is written to it
    /// arrives unchanged. That is what lets a proxy chain carry on speaking its own protocols
    /// over an agent hop.
    /// </remarks>
    public static async Task<AgentOpened> JoinAsync(
        Stream stream, AgentAddress destination, CancellationToken ct)
    {
        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Open,
            new AgentOpen(destination).Encode(), ct).ConfigureAwait(false);

        var (kind, payload) = await AgentProtocol.ReadFrameAsync(stream, ct).ConfigureAwait(false);
        switch (kind)
        {
            case AgentFrameKind.Opened:
                return AgentOpened.Decode(payload);
            case AgentFrameKind.Reject:
                var reject = AgentReject.Decode(payload);
                throw new AgentRefusedException(reject.Code, Describe(reject, destination));
            default:
                throw new AgentProtocolException($"the agent answered an open with a {kind} frame");
        }
    }

    private static bool Matches(X509Certificate certificate, byte[] expected)
    {
        using var parsed = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        var actual = SHA256.HashData(parsed.PublicKey.ExportSubjectPublicKeyInfo());
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Opens one relayed TCP flow. The returned stream is the tunnel: everything written to it
    /// reaches the destination unchanged.
    /// </summary>
    public static async Task<AgentStream> OpenStreamAsync(
        AgentClientOptions options, AgentAddress destination, CancellationToken ct)
    {
        var (socket, tls) = await ConnectAsync(options, AgentRole.Stream, ct).ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(options.Timeout);
            return new AgentStream(socket, tls, await JoinAsync(tls, destination, timeout.Token).ConfigureAwait(false));
        }
        catch
        {
            tls.Dispose();
            socket.Dispose();
            throw;
        }
    }

    internal static string Describe(AgentReject reject, AgentAddress? destination = null) => reject.Code switch
    {
        AgentRejection.Unauthorised =>
            "The agent did not accept this exit's token. Take a fresh connect string from the agent.",
        AgentRejection.UnsupportedVersion =>
            $"The agent speaks a different version of the protocol: {reject.Message}",
        AgentRejection.DestinationRefused =>
            $"The agent will not relay to {destination}: {reject.Message}",
        AgentRejection.ConnectFailed =>
            $"The agent could not reach {destination}: {reject.Message}",
        AgentRejection.ConnectionRefused => destination is null
            ? "The destination refused the connection from the agent."
            : $"The destination {destination} refused the connection from the agent.",
        AgentRejection.TooMany => $"The agent is at its limit: {reject.Message}",
        AgentRejection.UdpDisabled => "The agent was started without UDP relaying.",
        _ => reject.Message,
    };
}

/// <summary>One relayed TCP flow: the socket, the tunnel, and what the agent reported.</summary>
public sealed class AgentStream(Socket socket, SslStream stream, AgentOpened opened) : IAsyncDisposable
{
    public Socket Socket { get; } = socket;

    public SslStream Stream { get; } = stream;

    /// <summary>What the agent said when it joined the destination: its source, and its own connect time.</summary>
    public AgentOpened Opened { get; } = opened;

    public ValueTask DisposeAsync()
    {
        try
        {
            Stream.Dispose();
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
        }

        Socket.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// A live session with one agent: the control connection and the datagram channel it keys.
/// </summary>
/// <remarks>
/// <para>
/// The session exists for the things a per-flow connection cannot do: knowing the agent is
/// there without opening a flow, measuring the agent's own distance to a game server, and
/// carrying UDP. Its control connection is read by one loop which hands each answer to
/// whoever asked — in order, because one connection answers in order.
/// </para>
/// <para>
/// It keeps itself alive: a ping on the control connection and a keepalive datagram, the
/// second of which also holds open whatever NAT is between here and the agent.
/// </para>
/// </remarks>
public sealed class AgentSession : IAsyncDisposable
{
    private static readonly TimeSpan PingInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan KeepaliveInterval = TimeSpan.FromSeconds(20);

    private readonly AgentClientOptions _options;
    private readonly Socket _controlSocket;
    private readonly SslStream _control;
    private readonly CancellationTokenSource _closing = new();
    private readonly ConcurrentDictionary<AgentFrameKind, ConcurrentQueue<TaskCompletionSource<byte[]>>> _waiting = new();
    private readonly ConcurrentDictionary<ushort, OpenChannelEntry> _channels = new();
    private readonly SemaphoreSlim _writing = new(1, 1);
    private AgentDatagramCrypto? _crypto;
    private Socket? _datagrams;
    private TaskCompletionSource<byte[]>? _echo;
    private int _nextChannel;

    private int _nextFragmentId;

    private readonly AgentFragmentAssembler _assembler = new();
    private int _probing;

    private AgentSession(AgentClientOptions options, Socket socket, SslStream control, AgentWelcome welcome)
    {
        _options = options;
        _controlSocket = socket;
        _control = control;
        Welcome = welcome;
    }

    public AgentWelcome Welcome { get; }

    public string AgentName => Welcome.AgentName;

    /// <summary>True when the agent offered the datagram channel and it has been set up.</summary>
    public bool UdpAvailable => _datagrams is not null;

    /// <summary>
    /// True when the agent granted full-cone UDP: a channel then stands for one of our sockets,
    /// may send to any destination, and hears from anyone, each answer labelled with its source.
    /// </summary>
    public bool FullCone => UdpAvailable && Welcome.Available.HasFlag(AgentProtocol.Features.FullCone);

    /// <summary>
    /// True when the agent will carry a datagram too large for one packet in pieces, either way.
    /// </summary>
    public bool Fragments => UdpAvailable && Welcome.Available.HasFlag(AgentProtocol.Features.Fragments);

    /// <summary>Null while the session is up; the reason once it is not.</summary>
    public string? Failure { get; private set; }

    public bool IsOpen => Failure is null;

    /// <summary>Raised once, when the session ends for any reason.</summary>
    public event Action<string>? Closed;

    public static async Task<AgentSession> ConnectAsync(AgentClientOptions options, CancellationToken ct)
    {
        var (socket, control) = await AgentClient.ConnectAsync(options, AgentRole.Control, ct).ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(options.Timeout);

            var (kind, payload) = await AgentProtocol.ReadFrameAsync(control, timeout.Token).ConfigureAwait(false);
            if (kind == AgentFrameKind.Reject)
            {
                var reject = AgentReject.Decode(payload);
                throw new AgentRefusedException(reject.Code, AgentClient.Describe(reject));
            }

            if (kind != AgentFrameKind.Welcome)
            {
                throw new AgentProtocolException($"the agent answered a hello with a {kind} frame");
            }

            var welcome = AgentWelcome.Decode(payload);
            var session = new AgentSession(options, socket, control, welcome);
            session.Start();
            return session;
        }
        catch
        {
            control.Dispose();
            socket.Dispose();
            throw;
        }
    }

    private void Start()
    {
        if (Welcome.Available.HasFlag(AgentProtocol.Features.Udp) && Welcome.DatagramPort != 0 &&
            AgentDatagramCrypto.IsSupported)
        {
            try
            {
                var peer = new IPEndPoint(
                    ((IPEndPoint)_controlSocket.RemoteEndPoint!).Address, Welcome.DatagramPort);
                var socket = new Socket(peer.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                _options.ConfigureSocket?.Invoke(socket);
                // Connected, so the kernel drops anything that did not come from the agent
                // before it reaches us, and so sending needs no address.
                socket.Connect(peer);
                _datagrams = socket;
                _crypto = AgentDatagramCrypto.ForClient(Welcome.SessionId, Welcome.DatagramKey);
                _ = ReceiveDatagramsAsync(socket, _closing.Token);
                _ = KeepaliveLoopAsync(_closing.Token);
            }
            catch (SocketException)
            {
                // No datagram channel; TCP still works and the probe will report it honestly.
                _datagrams = null;
                _crypto = null;
            }
        }

        _ = ReadControlAsync(_closing.Token);
        _ = PingLoopAsync(_closing.Token);
    }

    // -- control ---------------------------------------------------------------

    private async Task ReadControlAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var (kind, payload) = await AgentProtocol.ReadFrameAsync(_control, ct).ConfigureAwait(false);
                if (kind == AgentFrameKind.Bye)
                {
                    Close("The agent said it is shutting down.");
                    return;
                }

                if (_waiting.TryGetValue(kind, out var queue) && queue.TryDequeue(out var waiter))
                {
                    waiter.TrySetResult(payload);
                }
            }
        }
        catch (Exception e) when (e is AgentProtocolException or IOException or SocketException
                                     or ObjectDisposedException or OperationCanceledException)
        {
            Close(e is AgentProtocolException ? e.Message : "The connection to the agent was lost.");
        }
    }

    /// <param name="timeout">
    /// How long the answer may take, when that is not the session's usual timeout: a probe waits
    /// for the agent to finish measuring, which can take several seconds per sample.
    /// </param>
    private async Task<byte[]> RequestAsync(
        AgentFrameKind send, byte[] payload, AgentFrameKind expect, CancellationToken ct, TimeSpan? timeout = null)
    {
        if (Failure is { } failure)
        {
            throw new AgentProtocolException(failure);
        }

        var completion = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        await _writing.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Queued while holding the write lock, so the order of the queue is the order the
            // requests went out in — which is the order the agent answers them. Queued before
            // taking it, a second caller could write first and be handed the first's answer.
            _waiting.GetOrAdd(expect, _ => new ConcurrentQueue<TaskCompletionSource<byte[]>>()).Enqueue(completion);
            await AgentProtocol.WriteFrameAsync(_control, send, payload, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or AgentProtocolException
                                     or OperationCanceledException)
        {
            // Cancelled part way through a frame is as final as a broken connection: whatever
            // was written is half a frame, and nothing after it can be read correctly.
            completion.TrySetException(e);
            Close("The connection to the agent was lost.");
            throw;
        }
        finally
        {
            _writing.Release();
        }

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct, _closing.Token);
        limit.CancelAfter(timeout ?? _options.Timeout);
        await using var registration = limit.Token.Register(() =>
            completion.TrySetException(new TimeoutException($"the agent did not answer with a {expect} frame")));

        try
        {
            return await completion.Task.ConfigureAwait(false);
        }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException)
        {
            // One connection answers in order, so an answer that never came means the next
            // one would be matched to the wrong request. The session is over, not just this
            // call.
            Close("The agent stopped answering.");
            throw;
        }
    }

    /// <summary>The round trip to the agent, measured on the control connection.</summary>
    public async Task<TimeSpan> PingAsync(CancellationToken ct = default)
    {
        var token = RandomNumberGenerator.GetBytes(8);
        var clock = Stopwatch.StartNew();
        var echoed = await RequestAsync(AgentFrameKind.Ping, token, AgentFrameKind.Pong, ct).ConfigureAwait(false);
        var elapsed = clock.Elapsed;
        if (!echoed.AsSpan().SequenceEqual(token))
        {
            throw new AgentProtocolException("the agent echoed a different ping");
        }

        LastRoundTrip = elapsed;
        return elapsed;
    }

    /// <summary>The most recent ping, or null before the first one.</summary>
    public TimeSpan? LastRoundTrip { get; private set; }

    /// <summary>Asks the agent to measure a destination from where it is.</summary>
    /// <remarks>
    /// Waits as long as the measurement can take rather than the session's usual timeout. The
    /// agent gives every sample a few seconds to connect, so a destination that drops the
    /// connection attempts — a UDP-only game server, typically — takes it well past ten
    /// seconds to answer, and a timeout here closes the session that every UDP flow through
    /// the agent depends on.
    /// </remarks>
    public async Task<AgentProbeReply> ProbeAsync(AgentAddress target, byte samples, CancellationToken ct = default)
    {
        var id = (uint)Random.Shared.Next();
        Interlocked.Increment(ref _probing);
        byte[] answer;
        try
        {
            answer = await RequestAsync(
                AgentFrameKind.Probe,
                new AgentProbeRequest(id, samples, target).Encode(),
                AgentFrameKind.Probed,
                ct,
                ProbeTimeout(samples)).ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _probing);
        }

        var reply = AgentProbeReply.Decode(answer);
        if (reply.RequestId != id)
        {
            throw new AgentProtocolException("the agent answered a probe that was not the one asked");
        }

        return reply;
    }

    /// <summary>
    /// How long a probe of this many samples may take: the agent's connect timeout for each
    /// sample and the gaps between them, which it clamps to ten, plus the usual allowance.
    /// </summary>
    private TimeSpan ProbeTimeout(byte samples) =>
        TimeSpan.FromSeconds(3.5 * Math.Clamp((int)samples, 1, 10)) + _options.Timeout;

    public async Task<AgentStats> StatsAsync(CancellationToken ct = default) =>
        AgentStats.Decode(await RequestAsync(AgentFrameKind.Stats, [], AgentFrameKind.StatsReply, ct)
            .ConfigureAwait(false));

    private async Task PingLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PingInterval, ct).ConfigureAwait(false);

                // An agent that answers its control frames one at a time holds a ping behind a
                // measurement until the measurement is done, and a ping that waits that long
                // would time out and take the session with it. The probe's own answer is proof
                // enough that the agent is there.
                if (Volatile.Read(ref _probing) > 0)
                {
                    continue;
                }

                await PingAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception e) when (e is AgentProtocolException or TimeoutException or IOException
                                         or ObjectDisposedException)
            {
                Close("The agent stopped answering.");
                return;
            }
        }
    }

    // -- datagrams -------------------------------------------------------------

    /// <summary>
    /// Reserves a channel for one conversation, and says where its answers go.
    /// </summary>
    /// <remarks>
    /// The agent keeps a socket per channel, so the game's apparent source port at the far end
    /// stays put for as long as it is playing. An ordinary channel stands for one destination,
    /// and the agent drops a datagram on it for any other. A full-cone one — only in a session
    /// granted <see cref="FullCone"/> — stands for one of our sockets: it may send anywhere, and
    /// hears from anyone. The handler is given the source of every datagram either way.
    /// </remarks>
    /// <param name="fullCone">Open a full-cone channel.</param>
    public ushort OpenChannel(Action<IPEndPoint, ReadOnlyMemory<byte>> onDatagram, bool fullCone = false)
    {
        if (fullCone && !FullCone)
        {
            throw new AgentProtocolException("this agent session has no full-cone UDP");
        }

        for (var attempt = 0; attempt < 65536; attempt++)
        {
            var id = (ushort)Interlocked.Increment(ref _nextChannel);
            if (id != 0 && _channels.TryAdd(id, new OpenChannelEntry(onDatagram, fullCone)))
            {
                return id;
            }
        }

        throw new AgentProtocolException("every datagram channel is in use");
    }

    private readonly record struct OpenChannelEntry(Action<IPEndPoint, ReadOnlyMemory<byte>> Handler, bool Cone);

    public void CloseChannel(ushort channel) => _channels.TryRemove(channel, out _);

    public async Task SendDatagramAsync(
        ushort channel, IPEndPoint target, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        if (_datagrams is not { } socket || _crypto is not { } crypto)
        {
            throw new AgentProtocolException("this agent session has no datagram channel");
        }

        // One packet's worth goes as it is. More than that goes in pieces when the agent can put
        // them back together, and is refused, with a reason, when it cannot: never split for an
        // agent that would see only garbage, never cut short.
        var onePacket = Math.Min((int)Welcome.MaxDatagramPayload, AgentProtocol.MaxDatagramPayload);
        var largest = Fragments ? AgentProtocol.MaxFragmentedPayload : onePacket;
        if (payload.Length > largest)
        {
            throw new AgentProtocolException(
                $"a {payload.Length}-byte datagram is over the agent's limit of {largest}");
        }

        // A channel this session never opened, or has closed, goes out as an ordinary one: the
        // agent decides what a channel is by its first datagram, and only ours can make it cone.
        var cone = _channels.TryGetValue(channel, out var entry) && entry.Cone;
        var plain = new byte[AgentDatagram.MaxRelayHeaderBytes + payload.Length];
        var length = AgentDatagram.WriteRelay(plain, channel, target, payload.Span, cone);
        if (length <= AgentDatagram.MaxBodyBytes)
        {
            await SendSealedAsync(socket, crypto, plain.AsMemory(0, length), ct).ConfigureAwait(false);
            return;
        }

        var id = (uint)Interlocked.Increment(ref _nextFragmentId);
        foreach (var fragment in AgentDatagram.Split(plain.AsSpan(0, length), id))
        {
            await SendSealedAsync(socket, crypto, fragment, ct).ConfigureAwait(false);
        }
    }

    private static async Task SendSealedAsync(
        Socket socket, AgentDatagramCrypto crypto, ReadOnlyMemory<byte> plain, CancellationToken ct)
    {
        var packet = new byte[AgentDatagramCrypto.SealedSize(plain.Length)];
        var sealedLength = crypto.Seal(plain.Span, packet);
        await socket.SendAsync(packet.AsMemory(0, sealedLength), SocketFlags.None, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Proves the datagram path works, end to end, without needing anything else to bounce off.
    /// </summary>
    /// <returns>The round trip, or null when the agent did not answer.</returns>
    public async Task<TimeSpan?> EchoAsync(CancellationToken ct = default)
    {
        if (_datagrams is not { } socket || _crypto is not { } crypto)
        {
            return null;
        }

        var token = RandomNumberGenerator.GetBytes(8);
        var plain = new byte[1 + token.Length];
        var length = AgentDatagram.WriteSimple(plain, AgentDatagramKind.Echo, token);
        var packet = new byte[AgentDatagramCrypto.SealedSize(length)];

        var completion = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _echo = completion;
        var clock = Stopwatch.StartNew();
        await socket.SendAsync(packet.AsMemory(0, crypto.Seal(plain.AsSpan(0, length), packet)), SocketFlags.None, ct)
            .ConfigureAwait(false);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct, _closing.Token);
        timeout.CancelAfter(_options.Timeout);
        await using var registration = timeout.Token.Register(() => completion.TrySetCanceled());

        try
        {
            var answer = await completion.Task.ConfigureAwait(false);
            return answer.AsSpan().SequenceEqual(token) ? clock.Elapsed : null;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        finally
        {
            _echo = null;
        }
    }

    private async Task ReceiveDatagramsAsync(Socket socket, CancellationToken ct)
    {
        var buffer = new byte[AgentDatagram.MaxPacketBytes];
        var plaintext = new byte[AgentDatagram.MaxPacketBytes];

        while (!ct.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await socket.ReceiveAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            if (_crypto is not { } crypto ||
                !crypto.TryOpen(buffer.AsSpan(0, received), plaintext, out var length))
            {
                continue;
            }

            var body = plaintext.AsSpan(0, length);
            switch (AgentDatagram.KindOf(body))
            {
                case AgentDatagramKind.EchoReply:
                    _echo?.TrySetResult(body[1..].ToArray());
                    break;

                case AgentDatagramKind.Relay or AgentDatagramKind.ConeRelay:
                    DeliverRelay(body);
                    break;

                case AgentDatagramKind.Fragment when Fragments:
                    // The body the pieces make up is a relayed datagram, handled as if it had
                    // come in one; anything else they claim to be is dropped.
                    if (_assembler.Add(body) is { } whole &&
                        AgentDatagram.KindOf(whole) is AgentDatagramKind.Relay or AgentDatagramKind.ConeRelay)
                    {
                        DeliverRelay(whole);
                    }

                    break;
            }
        }
    }

    private void DeliverRelay(ReadOnlySpan<byte> body)
    {
        if (AgentDatagram.TryReadRelay(body, out var channel, out var from, out var payload) &&
            from is not null && _channels.TryGetValue(channel, out var entry))
        {
            entry.Handler(from, payload.ToArray());
        }
    }

    private async Task KeepaliveLoopAsync(CancellationToken ct)
    {
        var plain = new byte[1];
        plain[0] = (byte)AgentDatagramKind.Keepalive;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(KeepaliveInterval, ct).ConfigureAwait(false);
                if (_datagrams is { } socket && _crypto is { } crypto)
                {
                    var packet = new byte[AgentDatagramCrypto.SealedSize(plain.Length)];
                    await socket.SendAsync(packet.AsMemory(0, crypto.Seal(plain, packet)), SocketFlags.None, ct)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }
        }
    }

    // -- lifetime --------------------------------------------------------------

    private void Close(string reason)
    {
        if (Failure is not null)
        {
            return;
        }

        Failure = reason;
        foreach (var queue in _waiting.Values)
        {
            while (queue.TryDequeue(out var waiter))
            {
                waiter.TrySetException(new AgentProtocolException(reason));
            }
        }

        _echo?.TrySetCanceled();
        Closed?.Invoke(reason);
        _closing.Cancel();
    }

    public async ValueTask DisposeAsync()
    {
        Close("The session was closed.");
        await _closing.CancelAsync().ConfigureAwait(false);
        _crypto?.Dispose();
        _datagrams?.Dispose();
        _control.Dispose();
        _controlSocket.Dispose();
        _closing.Dispose();
        _writing.Dispose();
    }
}
