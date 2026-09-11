using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Yura.Core.Agent;
using Yura.Core.Ipc;
using Yura.Core.Net;
using Yura.Core.Proxies;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Diagnostics;

/// <summary>
/// Discovers the NAT behaviour a route gives a peer-to-peer game.
/// </summary>
/// <remarks>
/// Peer-to-peer games need each side to learn its own outside address and tell the other, so
/// what matters is not whether the route works but what the far side sees. That is a property
/// of the route, not of the machine: a game routed through a proxy has the proxy's NAT
/// behaviour, and it can be better or worse than the one it would have had directly. Both are
/// measured here, the same way, so the two verdicts are comparable — the same reason
/// <see cref="NetworkMeasurer"/> measures its target twice.
///
/// The probe is STUN over the route's own UDP path: a plain marked socket, a WireGuard exit's
/// socket, a SOCKS5 association, or an agent's datagram channel. A route that cannot carry
/// UDP at all is not a failure to report as unknown — it is a definite answer, because a game
/// whose UDP cannot leave has no peer-to-peer connectivity whatsoever.
/// </remarks>
public static class NatProbe
{
    /// <summary>
    /// Servers used when the caller names none.
    /// </summary>
    /// <remarks>
    /// Two operators rather than two names from one, because the mapping test is only
    /// meaningful between two genuinely different addresses and two names from one operator
    /// can resolve to the same one. Which servers answered is reported back, so the verdict
    /// is never attributed to a server that was silent.
    /// </remarks>
    public static readonly string[] DefaultServers =
    [
        "stun.l.google.com:19302",
        "stun.cloudflare.com:3478",
        "stun.nextcloud.com:3478",
    ];

    /// <summary>
    /// How long to wait for each attempt, in order.
    /// </summary>
    /// <remarks>
    /// RFC 5389 §7.2.1 retransmits with a growing timeout, starting near the expected round
    /// trip. The shape matters here for a second reason: a server that is simply unreachable
    /// costs the sum of these, and the test walks a list of servers, so flat two-second waits
    /// would make a dead first entry feel like a hang.
    /// </remarks>
    private static readonly TimeSpan[] Attempts =
    [
        TimeSpan.FromMilliseconds(500),
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
    ];

    public static async Task<NatReportDto> RunAsync(
        IReadOnlyList<string> servers, IReadOnlyList<ProxyHop>? route, CancellationToken ct)
    {
        var wanted = servers is { Count: > 0 } ? servers : DefaultServers;

        List<IPEndPoint> resolved;
        try
        {
            resolved = await ResolveAsync(wanted, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return Failed("The STUN servers could not be resolved in time.");
        }

        if (resolved.Count == 0)
        {
            return Failed($"None of the STUN servers could be resolved ({string.Join(", ", wanted)}).");
        }

        INatTransport transport;
        try
        {
            transport = await OpenTransportAsync(route, resolved[0], ct).ConfigureAwait(false);
        }
        catch (UdpUnsupportedException e)
        {
            // A definite answer, not a failure: this route cannot carry a game's UDP.
            return new NatReportDto
            {
                Verdict = NatVerdict.Blocked,
                Diagnostics = e.Message,
            };
        }
        catch (ProxyHandshakeException e)
        {
            return Failed(e.Message);
        }
        catch (Exception e) when (e is SocketException or IOException or AgentProtocolException
                                     or AgentRefusedException or OperationCanceledException)
        {
            return Failed($"The route could not be opened for UDP: {e.Message}");
        }

        await using (transport)
        {
            return await ProbeAsync(transport, resolved, ct).ConfigureAwait(false);
        }
    }

    private static async Task<NatReportDto> ProbeAsync(
        INatTransport transport, List<IPEndPoint> servers, CancellationToken ct)
    {
        var used = new List<string>();
        var stopwatch = Stopwatch.StartNew();

        // The first server that answers anchors everything else: its answer carries the
        // mapping, and its OTHER-ADDRESS decides whether the filtering tests are possible.
        StunMessage? first = null;
        IPEndPoint? firstServer = null;
        double? roundTrip = null;
        foreach (var server in servers)
        {
            var attempt = Stopwatch.StartNew();
            var answer = await RequestAsync(transport, server, Stun.Change.None, ct).ConfigureAwait(false);
            if (answer?.Message.MappedEndpoint is not null)
            {
                first = answer.Value.Message;
                firstServer = server;
                roundTrip = attempt.Elapsed.TotalMilliseconds;
                used.Add(server.ToString());
                break;
            }
        }

        if (first is null || firstServer is null)
        {
            return new NatReportDto
            {
                Verdict = NatVerdict.Blocked,
                Diagnostics = $"No answer from any of {servers.Count} STUN server(s) in " +
                              $"{stopwatch.Elapsed.TotalSeconds:0.#} s, so UDP is not getting out and back.",
                Servers = used,
            };
        }

        // A second, genuinely different server address on the same socket: if the mapping
        // differs between the two, the address a peer would be told is not the address it
        // would see, and no amount of hole punching helps.
        // Another address if there is one, otherwise another port of the same server, and
        // failing both, whatever second address the server advertised. The three are not
        // equally conclusive and the classifier is told which it got.
        var second = servers.FirstOrDefault(s => !s.Address.Equals(firstServer.Address))
                     ?? servers.FirstOrDefault(s => !s.Equals(firstServer))
                     ?? first.OtherAddress;
        StunMessage? secondAnswer = null;
        var distinct = false;
        var onlyPortDiffers = false;

        if (second is not null)
        {
            distinct = !second.Equals(firstServer);
            onlyPortDiffers = second.Address.Equals(firstServer.Address);
            var answer = await RequestAsync(transport, second, Stun.Change.None, ct).ConfigureAwait(false);
            if (answer?.Message.MappedEndpoint is not null)
            {
                secondAnswer = answer.Value.Message;
                used.Add(second.ToString());
            }
            else
            {
                distinct = false;
            }
        }

        // Filtering needs the server to answer from somewhere it was never sent to, which it
        // can only do if it has a second address. Most public servers do not.
        bool? fromOtherAddressAndPort = null;
        bool? fromOtherPort = null;
        if (first.OtherAddress is { } other && !other.Address.Equals(firstServer.Address))
        {
            var changed = await RequestAsync(
                transport, firstServer, Stun.Change.Address | Stun.Change.Port, ct).ConfigureAwait(false);
            fromOtherAddressAndPort = changed is not null;

            if (fromOtherAddressAndPort is false)
            {
                var port = await RequestAsync(transport, firstServer, Stun.Change.Port, ct).ConfigureAwait(false);
                fromOtherPort = port is not null;
            }
        }

        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = transport.LocalEndpoint,
            FirstMapped = first.MappedEndpoint,
            SecondMapped = secondAnswer?.MappedEndpoint,
            SecondServerDistinct = distinct,
            SecondServerDiffersOnlyByPort = onlyPortDiffers,
            AnsweredFromOtherAddressAndPort = fromOtherAddressAndPort,
            AnsweredFromOtherPort = fromOtherPort,
        });

        var detail = assessment.Diagnostics;
        if (transport.Detail is { Length: > 0 } note)
        {
            detail = $"{detail} {note}";
        }

        return new NatReportDto
        {
            Verdict = assessment.Verdict,
            Mapping = assessment.Mapping,
            Filtering = assessment.Filtering,
            MappedEndpoint = assessment.MappedEndpoint?.ToString(),
            BehindNat = assessment.BehindNat,
            Diagnostics = detail,
            Servers = used,
            RoundTripMilliseconds = roundTrip,
        };
    }

    private static NatReportDto Failed(string reason) => new()
    {
        Verdict = NatVerdict.Unknown,
        Diagnostics = reason,
    };

    /// <summary>One request, retried, and the matching answer with the address it came from.</summary>
    /// <remarks>
    /// Matched on the transaction id and never on the source address: the whole point of the
    /// filtering tests is that the answer arrives from somewhere else. Datagrams that are not
    /// this transaction's answer are discarded, because the route's socket may carry other
    /// traffic.
    /// </remarks>
    private static async Task<StunAnswer?> RequestAsync(
        INatTransport transport, IPEndPoint server, Stun.Change change, CancellationToken ct)
    {
        foreach (var wait in Attempts)
        {
            var transactionId = Stun.NewTransactionId();
            try
            {
                await transport.SendAsync(server, Stun.BuildBindingRequest(transactionId, change), ct)
                    .ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException
                                         or AgentProtocolException or IOException)
            {
                return null;
            }

            var deadline = DateTimeOffset.UtcNow + wait;
            while (DateTimeOffset.UtcNow < deadline)
            {
                var datagram = await transport
                    .ReceiveAsync(deadline - DateTimeOffset.UtcNow, ct)
                    .ConfigureAwait(false);
                if (datagram is null)
                {
                    break;
                }

                if (Stun.TryParse(datagram.Value.Payload, out var message) && message is not null &&
                    message.TransactionId.AsSpan().SequenceEqual(transactionId) &&
                    message.Kind == StunMessageKind.BindingSuccess)
                {
                    return new StunAnswer(message, datagram.Value.From);
                }
            }
        }

        return null;
    }

    private static async Task<List<IPEndPoint>> ResolveAsync(IReadOnlyList<string> servers, CancellationToken ct)
    {
        var resolved = new List<IPEndPoint>();
        foreach (var server in servers)
        {
            var colon = server.LastIndexOf(':');
            var host = colon > 0 ? server[..colon] : server;
            var port = colon > 0 && ushort.TryParse(server[(colon + 1)..], out var parsed) ? parsed : Stun.DefaultPort;

            try
            {
                var address = await ProxyDialer.ResolveAsync(host, ct).ConfigureAwait(false);
                var endpoint = new IPEndPoint(address, port);

                // IPv4 only, like the rest of the capture path; and a duplicate address would
                // make the mapping comparison look conclusive when it proves nothing.
                if (endpoint.AddressFamily == AddressFamily.InterNetwork &&
                    !resolved.Any(r => r.Equals(endpoint)))
                {
                    resolved.Add(endpoint);
                }
            }
            catch (Exception e) when (e is SocketException or ArgumentException)
            {
                // A server that cannot be resolved is simply not used.
            }
        }

        return resolved;
    }

    private static async Task<INatTransport> OpenTransportAsync(
        IReadOnlyList<ProxyHop>? route, IPEndPoint firstServer, CancellationToken ct)
    {
        if (route is not { Count: > 0 })
        {
            return SocketNatTransport.Open(PolicyRouting.BypassMark, bindTo: null, firstServer);
        }

        if (route.Count > 1)
        {
            throw new UdpUnsupportedException(
                "A proxy chain carries TCP only, so a game's UDP cannot go through it and " +
                "peer-to-peer connections will not work on this route.");
        }

        var hop = route[0];
        if (hop.Tunnel is { } tunnel)
        {
            var source = tunnel.SourceFor(AddressFamily.InterNetwork)
                         ?? throw new UdpUnsupportedException(
                             $"WireGuard exit '{tunnel.Name}' has no IPv4 address inside the tunnel.");
            return SocketNatTransport.Open(tunnel.Mark, source, firstServer);
        }

        return hop.Endpoint.Protocol switch
        {
            ProxyProtocol.Socks5 => await Socks5NatTransport.OpenAsync(hop, ct).ConfigureAwait(false),
            ProxyProtocol.YuraAgent => await AgentNatTransport.OpenAsync(hop, ct).ConfigureAwait(false),
            _ => throw new UdpUnsupportedException(
                $"'{hop.Endpoint.Name}' is an {hop.Endpoint.ProtocolDisplay} proxy, which carries TCP only. " +
                "A game's UDP cannot go through it, so peer-to-peer connections will not work on this route."),
        };
    }

    private readonly record struct StunAnswer(StunMessage Message, IPEndPoint? From);
}

/// <summary>Raised when a route cannot carry UDP at all, which is an answer rather than an error.</summary>
public sealed class UdpUnsupportedException(string message) : Exception(message);

/// <summary>A way to send datagrams the way the route would, and read what comes back.</summary>
/// <remarks>
/// Small on purpose. The forwarder's UDP sessions cannot be reused here: each of those is
/// bound to one destination and writes its answers back to an application's socket, and this
/// probe needs the opposite — several destinations on one mapping, with the answers in hand.
/// </remarks>
internal interface INatTransport : IAsyncDisposable
{
    /// <summary>
    /// The local address of the route's own socket, when there is one to read. Null for a
    /// relayed route, where the socket that faces the internet is somewhere else — and
    /// reporting our own address there would compare two unrelated things.
    /// </summary>
    IPEndPoint? LocalEndpoint { get; }

    /// <summary>Anything worth saying about the route itself, appended to the verdict's detail.</summary>
    string? Detail { get; }

    Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct);

    Task<NatDatagram?> ReceiveAsync(TimeSpan within, CancellationToken ct);
}

internal readonly record struct NatDatagram(IPEndPoint? From, byte[] Payload);

/// <summary>A plain UDP socket: the direct path, and a WireGuard exit's path.</summary>
/// <remarks>
/// Unconnected on purpose. The mapping test needs two destinations on one socket, and the
/// filtering test needs an answer from an address the socket never sent to — a connected
/// socket would drop exactly that.
/// </remarks>
internal sealed class SocketNatTransport : INatTransport
{
    private readonly Socket _socket;
    private readonly IPAddress? _source;

    private SocketNatTransport(Socket socket, IPAddress? source, string? detail)
    {
        _socket = socket;
        _source = source;
        Detail = detail;
    }

    public static SocketNatTransport Open(uint mark, IPAddress? bindTo, IPEndPoint towards)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetMark(mark);
        socket.Bind(new IPEndPoint(bindTo ?? IPAddress.Any, 0));
        return new SocketNatTransport(
            socket,
            bindTo ?? SourceTowards(mark, towards),
            bindTo is null ? null : $"Measured from inside the tunnel, source {bindTo}.");
    }

    /// <summary>
    /// The address the kernel would send from, without sending anything.
    /// </summary>
    /// <remarks>
    /// Needed because the probe socket is bound to every address — it has to be, to receive an
    /// answer from a server it never sent to — and so its own local address says nothing.
    /// Connecting a throwaway UDP socket makes the kernel pick a route and a source address
    /// and puts no packet on the wire, which is what lets "the far side sees exactly this
    /// socket" be told apart from "something translated it".
    /// </remarks>
    private static IPAddress? SourceTowards(uint mark, IPEndPoint destination)
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.SetMark(mark);
            probe.Connect(destination);
            return (probe.LocalEndPoint as IPEndPoint)?.Address;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    /// <summary>The port this socket is really on, with the address the kernel would use.</summary>
    public IPEndPoint? LocalEndpoint => _source is null || _socket.LocalEndPoint is not IPEndPoint bound
        ? null
        : new IPEndPoint(_source, bound.Port);

    public string? Detail { get; }

    public async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct) =>
        await _socket.SendToAsync(payload, SocketFlags.None, destination, ct).ConfigureAwait(false);

    public async Task<NatDatagram?> ReceiveAsync(TimeSpan within, CancellationToken ct)
    {
        if (within <= TimeSpan.Zero)
        {
            return null;
        }

        var buffer = new byte[2048];
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(within);
        try
        {
            var received = await _socket
                .ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token)
                .ConfigureAwait(false);
            return new NatDatagram(received.RemoteEndPoint as IPEndPoint, buffer[..received.ReceivedBytes]);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
            return null;
        }
    }

    public ValueTask DisposeAsync()
    {
        _socket.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>One SOCKS5 UDP association, carrying datagrams to several destinations.</summary>
/// <remarks>
/// This is what a game gets through a SOCKS5 proxy, and the mapping it reports is the
/// proxy's: an association is one relay socket, so whether that socket keeps one mapping for
/// every destination is a property of the proxy and of whatever NAT sits beyond it.
/// </remarks>
internal sealed class Socks5NatTransport : INatTransport
{
    private readonly Socket _control;
    private readonly Socket _relay;

    private Socks5NatTransport(Socket control, Socket relay, string detail)
    {
        _control = control;
        _relay = relay;
        Detail = detail;
    }

    public static async Task<Socks5NatTransport> OpenAsync(ProxyHop hop, CancellationToken ct)
    {
        var proxyAddress = await ProxyDialer.ResolveAsync(hop.Endpoint.Host, ct).ConfigureAwait(false);
        var control = await ProxyDialer
            .ConnectWithBypassAsync(hop.Endpoint.Host, hop.Endpoint.Port, ct)
            .ConfigureAwait(false);

        IPEndPoint relayEndpoint;
        try
        {
            using var stream = new NetworkStream(control, ownsSocket: false);
            await ProxyDialer.Socks5GreetAsync(stream, hop.Endpoint.Username, hop.Password, ct).ConfigureAwait(false);
            await stream.WriteAsync(ProxyDialer.BuildSocks5Request(0x03, "0.0.0.0", 0), ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);

            var reply = await ProxyDialer.ReadExactlyAsync(stream, 4, ct).ConfigureAwait(false);
            if (reply[1] != 0)
            {
                throw new UdpUnsupportedException(reply[1] == 7
                    ? $"'{hop.Endpoint.Name}' refuses UDP, so a game's peer-to-peer traffic cannot go through it."
                    : $"'{hop.Endpoint.Name}' refused UDP ASSOCIATE (reply {reply[1]:#x}).");
            }

            var bound = await ProxyDialer.DrainSocks5AddressAsync(stream, reply[3], ct).ConfigureAwait(false)
                        ?? throw new ProxyHandshakeException("The proxy returned a named relay address.");
            relayEndpoint = bound.Address.Equals(IPAddress.Any)
                ? new IPEndPoint(proxyAddress, bound.Port)
                : bound;
        }
        catch
        {
            control.Dispose();
            throw;
        }

        var relay = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        relay.SetMark(PolicyRouting.BypassMark);
        try
        {
            await relay.ConnectAsync(relayEndpoint, ct).ConfigureAwait(false);
        }
        catch
        {
            relay.Dispose();
            control.Dispose();
            throw;
        }

        return new Socks5NatTransport(
            control, relay, $"Measured through the UDP association at {relayEndpoint}.");
    }

    /// <summary>Null: the socket facing the internet is the proxy's, not ours.</summary>
    public IPEndPoint? LocalEndpoint => null;

    public string? Detail { get; }

    public async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
    {
        // SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT, then the datagram. Per
        // datagram, which is what lets one association reach two servers.
        var address = destination.Address.GetAddressBytes();
        var framed = new byte[4 + address.Length + 2 + payload.Length];
        framed[3] = destination.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
        address.CopyTo(framed, 4);
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(4 + address.Length), (ushort)destination.Port);
        payload.CopyTo(framed, 4 + address.Length + 2);

        await _relay.SendAsync(framed, ct).ConfigureAwait(false);
    }

    public async Task<NatDatagram?> ReceiveAsync(TimeSpan within, CancellationToken ct)
    {
        if (within <= TimeSpan.Zero)
        {
            return null;
        }

        var buffer = new byte[2048];
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(within);
        try
        {
            var received = await _relay.ReceiveAsync(buffer, timeout.Token).ConfigureAwait(false);
            if (received < 4 || buffer[2] != 0)
            {
                return new NatDatagram(null, []);
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
                return new NatDatagram(null, []);
            }

            // The header names who sent it, which is what the filtering test needs.
            IPEndPoint? from = buffer[3] switch
            {
                1 => new IPEndPoint(new IPAddress(buffer[4..8]), BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(8))),
                4 => new IPEndPoint(new IPAddress(buffer[4..20]), BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(20))),
                _ => null,
            };

            return new NatDatagram(from, buffer[offset..received]);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
            return null;
        }
    }

    public ValueTask DisposeAsync()
    {
        _relay.Dispose();
        _control.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// A Yura agent's datagram channels, used exactly the way a game's UDP flows use them.
/// </summary>
/// <remarks>
/// One channel per destination, because that is what the forwarder opens per flow and what
/// the agent binds a socket to. That makes this measurement report the mapping a game would
/// really get through this agent — including the consequence that two destinations are two
/// sockets at the agent, which a peer sees as two different source ports.
/// </remarks>
internal sealed class AgentNatTransport : INatTransport
{
    private readonly AgentSession _session;
    private readonly Dictionary<IPEndPoint, ushort> _channels = [];
    private readonly System.Threading.Channels.Channel<NatDatagram> _answers =
        System.Threading.Channels.Channel.CreateUnbounded<NatDatagram>();

    private AgentNatTransport(AgentSession session, string detail)
    {
        _session = session;
        Detail = detail;
    }

    public static async Task<AgentNatTransport> OpenAsync(ProxyHop hop, CancellationToken ct)
    {
        var options = ProxyDialer.AgentOptionsFor(hop, socket => socket.SetMark(PolicyRouting.BypassMark));
        var session = await AgentSession.ConnectAsync(options, ct).ConfigureAwait(false);
        if (!session.Welcome.Available.HasFlag(AgentProtocol.Features.Udp))
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw new UdpUnsupportedException(
                $"Agent '{hop.Endpoint.Name}' was started without UDP relaying, so a game's " +
                "peer-to-peer traffic cannot go through it.");
        }

        return new AgentNatTransport(
            session,
            $"Measured through agent '{session.AgentName}'. The agent gives each destination its own " +
            "socket, so a peer sees a different source port per peer.");
    }

    /// <summary>Null: the socket facing the internet is the agent's.</summary>
    public IPEndPoint? LocalEndpoint => null;

    public string? Detail { get; }

    public async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
    {
        if (!_channels.TryGetValue(destination, out var channel))
        {
            channel = _session.OpenChannel((from, data) =>
                _answers.Writer.TryWrite(new NatDatagram(from, data.ToArray())));
            _channels[destination] = channel;
        }

        await _session.SendDatagramAsync(channel, destination, payload, ct).ConfigureAwait(false);
    }

    public async Task<NatDatagram?> ReceiveAsync(TimeSpan within, CancellationToken ct)
    {
        if (within <= TimeSpan.Zero)
        {
            return null;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(within);
        try
        {
            return await _answers.Reader.ReadAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var channel in _channels.Values)
        {
            _session.CloseChannel(channel);
        }

        await _session.DisposeAsync().ConfigureAwait(false);
    }
}
