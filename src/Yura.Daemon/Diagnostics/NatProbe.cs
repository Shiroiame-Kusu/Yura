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
/// The probe is STUN over the route's own UDP path, carried exactly the way the forwarder
/// carries a game's datagrams: the direct path on one socket, like the game's own; a WireGuard
/// exit on one socket per destination, a SOCKS5 proxy on one association per destination, and
/// an agent on one channel per destination — because that is what the forwarder opens for each
/// flow. Measuring a relayed route on a single socket reported the mapping of a socket no game
/// traffic ever uses. A route that cannot carry UDP at all is not a failure to report as
/// unknown — it is a definite answer, because a game whose UDP cannot leave has no
/// peer-to-peer connectivity whatsoever.
/// </remarks>
public static class NatProbe
{
    /// <summary>
    /// Servers used when the caller names none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The first three can tell NAT2 from NAT3. Each has a second public address, names it in
    /// OTHER-ADDRESS, and on 2026-10-08 answered from it when asked, measured through a
    /// full-cone route where nothing filtered the answer out. Most public servers cannot:
    /// Google's and Cloudflare's have one address, and of 64 servers tried, a third named a
    /// second address that was private, absent or silent. Xiaomi's comes first because it is
    /// near most of the people this is for; when one turns out not to answer from its other
    /// address after all, the filtering test moves on to the next.
    /// </para>
    /// <para>
    /// Google's and Cloudflare's are there for the mapping test, which needs only a second
    /// operator, and they almost always answer. Every server is a different operator, because
    /// two names from one can resolve to one address, which would make the mapping comparison
    /// agree for the trivial reason. Which servers answered is reported back, so the verdict
    /// is never attributed to a server that was silent.
    /// </para>
    /// </remarks>
    public static readonly string[] DefaultServers =
    [
        "stun.miwifi.com:3478",
        "stun.easybell.de:3478",
        "stun.fitauto.ru:3478",
        "stun.l.google.com:19302",
        "stun.cloudflare.com:3478",
    ];

    /// <summary>How many servers the filtering test is tried against before it gives up.</summary>
    /// <remarks>
    /// A second chance for when the first turns out not to answer from its other port, without
    /// making a NAT that really does keep everything out wait through the whole list.
    /// </remarks>
    private const int FilteringServersTried = 2;

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

    /// <param name="attempts">How long to wait for each try; the tests' simulated NAT needs no retries.</param>
    internal static async Task<NatReportDto> ProbeAsync(
        INatTransport transport, IReadOnlyList<IPEndPoint> servers, CancellationToken ct,
        IReadOnlyList<TimeSpan>? attempts = null)
    {
        var session = new ProbeSession(transport, attempts ?? Attempts);
        var stopwatch = Stopwatch.StartNew();

        // The first server that answers anchors everything else: its answer carries the mapping,
        // and its OTHER-ADDRESS decides whether it can run the filtering test.
        StunMessage? first = null;
        IPEndPoint? anchor = null;
        var firstIndex = -1;
        double? roundTrip = null;
        for (var i = 0; i < servers.Count; i++)
        {
            var attempt = Stopwatch.StartNew();
            var answer = await session.BindAsync(servers[i], ct).ConfigureAwait(false);
            if (answer is not null)
            {
                first = answer;
                anchor = servers[i];
                firstIndex = i;
                roundTrip = attempt.Elapsed.TotalMilliseconds;
                session.Used(anchor);
                break;
            }
        }

        if (first is null || anchor is null)
        {
            return new NatReportDto
            {
                Verdict = NatVerdict.Blocked,
                Diagnostics = $"No answer from any of {servers.Count} STUN server(s) in " +
                              $"{stopwatch.Elapsed.TotalSeconds:0.#} s, so UDP is not getting out and back.",
                Servers = session.Answered,
            };
        }

        // The mapping: a second server on the same route. If the mapping differs between the
        // two, the address a peer would be told is not the address it would see, and no amount
        // of hole punching helps. Another address if there is one, otherwise another port of
        // the same server, and failing both, whatever second address the server advertised;
        // the three are not equally conclusive and the classifier is told which it got. Only
        // servers after the first one that answered are candidates: those before it have
        // already failed to answer once, and asking again cost the wait a second time and left
        // the mapping unknown when a later server would have answered.
        //
        // Asked in two rounds, either side of the filtering test. A NAT that admits only hosts
        // it has sent to would let an answer from the first server's other address in just
        // because the mapping test had sent there: the flattering Open, given to a Moderate NAT.
        // So anything at that address, or at the first server's own address on another port,
        // waits until the filtering is known. Everything else goes first, so that a mapping that
        // varies is known before the filtering test starts, and that test, seconds of waiting
        // for answers a filtering NAT keeps out, is skipped where it would change nothing.
        var alternate = first.OtherAddress is { } advertised && !advertised.Equals(anchor) ? advertised : null;
        var untried = servers.Skip(firstIndex + 1).ToList();
        var early = untried
            .Where(s => !s.Address.Equals(anchor.Address) && (alternate is null || !s.Address.Equals(alternate.Address)))
            .ToList();
        var late = untried.Where(s => !s.Address.Equals(anchor.Address) && !early.Contains(s))
            .Concat(untried.Where(s => s.Address.Equals(anchor.Address) && !s.Equals(anchor)))
            .ToList();
        if (alternate is not null && !untried.Contains(alternate))
        {
            late.Add(alternate);
        }

        var second = await SecondMappingAsync(session, early, anchor, ct).ConfigureAwait(false);

        // A mapping that varies is Strict whatever gets in, and an address nothing translates is
        // Open, so in either case the filtering test would change nothing.
        var varies = second is { } seen && !seen.Message.MappedEndpoint!.Equals(first.MappedEndpoint);
        var untranslated = transport.LocalEndpoint is { } local && local.Equals(first.MappedEndpoint);
        var filtering = varies || untranslated
            ? FilteringOutcome.Untested
            : await FilteringAsync(session, servers, firstIndex, ct).ConfigureAwait(false);

        second ??= await SecondMappingAsync(session, late, anchor, ct).ConfigureAwait(false);

        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = transport.LocalEndpoint,
            FirstMapped = first.MappedEndpoint,
            SecondMapped = second?.Message.MappedEndpoint,
            SecondServerDistinct = second is not null,
            SecondServerDiffersOnlyByPort = second?.OnlyPortDiffers ?? false,
            AnsweredFromOtherAddressAndPort = filtering.FromOtherAddressAndPort,
            AnsweredFromOtherPort = filtering.FromOtherPort,
            OtherPortAnswersOnceSentTo = filtering.OtherPortOnceSentTo,
        });

        var detail = assessment.Diagnostics;
        if (filtering is { Server: { } filteredBy, Other: { } otherAddress })
        {
            detail = $"{detail} Filtering was tested against {filteredBy}, which can answer from {otherAddress}.";
        }

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
            Servers = session.Answered,
            RoundTripMilliseconds = roundTrip,
        };
    }

    private static NatReportDto Failed(string reason) => new()
    {
        Verdict = NatVerdict.Unknown,
        Diagnostics = reason,
    };

    /// <summary>The first of the candidates that answers, as the second half of the mapping test.</summary>
    private static async Task<SecondMapping?> SecondMappingAsync(
        ProbeSession session, IReadOnlyList<IPEndPoint> candidates, IPEndPoint anchor, CancellationToken ct)
    {
        foreach (var candidate in candidates)
        {
            if (await session.BindAsync(candidate, ct).ConfigureAwait(false) is { } answer)
            {
                session.Used(candidate);
                return new SecondMapping(answer, candidate.Address.Equals(anchor.Address));
            }
        }

        return null;
    }

    /// <summary>
    /// Which unsolicited answers get in, asked of the first server that can answer from a second
    /// address, and of the next one if the first one's answers turn out to prove nothing.
    /// </summary>
    private static async Task<FilteringOutcome> FilteringAsync(
        ProbeSession session, IReadOnlyList<IPEndPoint> servers, int firstIndex, CancellationToken ct)
    {
        var outcome = FilteringOutcome.Untested;
        var tried = 0;
        for (var i = firstIndex; i < servers.Count && tried < FilteringServersTried; i++)
        {
            var server = servers[i];
            var answer = await session.BindAsync(server, ct).ConfigureAwait(false);
            if (answer?.OtherAddress is not { } other || other.Address.Equals(server.Address))
            {
                continue;
            }

            // Its answers prove something only while nothing has been sent to where they come
            // from: a NAT that admits whoever it has sent to would let them in for that reason.
            if (session.HasSentTo(other.Address) || session.HasSentTo(new IPEndPoint(server.Address, other.Port)))
            {
                continue;
            }

            tried++;
            session.Used(server);
            outcome = await FilterAgainstAsync(session, server, other, ct).ConfigureAwait(false);
            if (outcome.Settled)
            {
                break;
            }
        }

        return outcome;
    }

    /// <summary>
    /// RFC 5780's filtering test against one server, and a check on what its silence means.
    /// </summary>
    /// <remarks>
    /// Both requests go out together, while nothing has been sent to the server's other address
    /// or port. An answer from the other address means anyone gets in: NAT1. One from the other
    /// port alone means a host already sent to gets in from any of its ports: NAT2. When neither
    /// gets in, the route sends to that other port itself and asks again in the same breath. A
    /// NAT that admits only the exact address and port it has sent to now lets the answer in, so
    /// its arriving shows the server does answer from there and the first silence was the NAT:
    /// NAT3. Still nothing, and the silence is the server's, which is what gets reported.
    /// </remarks>
    private static async Task<FilteringOutcome> FilterAgainstAsync(
        ProbeSession session, IPEndPoint server, IPEndPoint other, CancellationToken ct)
    {
        bool FromOtherPort(IPEndPoint from) => from.Address.Equals(server.Address) && from.Port != server.Port;

        var cold = await session
            .RequestAllAsync([(server, Stun.Change.Address | Stun.Change.Port), (server, Stun.Change.Port)], ct)
            .ConfigureAwait(false);
        var fromOtherAddressAndPort = Credited(cold[0], from => !from.Address.Equals(server.Address));
        var fromOtherPort = Credited(cold[1], FromOtherPort);

        bool? onceSentTo = null;
        if (fromOtherAddressAndPort is false && fromOtherPort is false)
        {
            var warm = await session
                .RequestAllAsync([(new IPEndPoint(server.Address, other.Port), Stun.Change.None), (server, Stun.Change.Port)], ct)
                .ConfigureAwait(false);
            onceSentTo = Credited(warm[1], FromOtherPort);
        }

        return new FilteringOutcome(server, other, fromOtherAddressAndPort, fromOtherPort, onceSentTo);
    }

    /// <summary>Whether an answer came from where it was asked to come from.</summary>
    /// <returns>
    /// True when it did; false when nothing came back; null when the server answered from
    /// somewhere it was asked not to. That server ignored the request, so its answer says
    /// nothing about filtering and must not be counted as if it did.
    /// </returns>
    private static bool? Credited(StunAnswer? answer, Func<IPEndPoint, bool> expectedFrom) =>
        answer is not { } received ? false
        : received.From is not { } from || expectedFrom(from) ? true
        : null;

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
            return SocketNatTransport.Open(PolicyRouting.BypassMark, firstServer);
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
            return new PerDestinationNatTransport(tunnel.Mark, source);
        }

        return hop.Endpoint.Protocol switch
        {
            ProxyProtocol.Socks5 => await Socks5NatTransport.OpenAsync(hop, firstServer, ct).ConfigureAwait(false),
            ProxyProtocol.YuraAgent => await AgentNatTransport.OpenAsync(hop, ct).ConfigureAwait(false),
            _ => throw new UdpUnsupportedException(
                $"'{hop.Endpoint.Name}' is an {hop.Endpoint.ProtocolDisplay} proxy, which carries TCP only. " +
                "A game's UDP cannot go through it, so peer-to-peer connections will not work on this route."),
        };
    }

    private readonly record struct StunAnswer(StunMessage Message, IPEndPoint? From);

    private sealed record SecondMapping(StunMessage Message, bool OnlyPortDiffers);

    /// <summary>What the filtering test found, and which server it asked.</summary>
    private sealed record FilteringOutcome(
        IPEndPoint? Server,
        IPEndPoint? Other,
        bool? FromOtherAddressAndPort,
        bool? FromOtherPort,
        bool? OtherPortOnceSentTo)
    {
        public static readonly FilteringOutcome Untested = new(null, null, null, null, null);

        /// <summary>True when the answers settle the filtering, so no other server need be asked.</summary>
        public bool Settled => (FromOtherAddressAndPort, FromOtherPort, OtherPortOnceSentTo) switch
        {
            (true, _, _) => true,
            (false, true, _) => true,
            (false, false, true) => true,
            _ => false,
        };
    }

    /// <summary>
    /// One probe's requests over one transport: what was sent where, and what each server said to
    /// a plain binding request.
    /// </summary>
    /// <remarks>
    /// Keeping count is what keeps the filtering test honest. Its answers count only while
    /// nothing has been sent to where they come from, and with the mapping test and up to two
    /// servers' filtering tests sharing one socket, that has to be checked rather than assumed.
    /// </remarks>
    private sealed class ProbeSession(INatTransport transport, IReadOnlyList<TimeSpan> attempts)
    {
        private readonly HashSet<IPEndPoint> _sent = [];
        private readonly Dictionary<IPEndPoint, StunMessage?> _bindings = [];

        /// <summary>The servers the verdict rests on, in the order they were used.</summary>
        public List<string> Answered { get; } = [];

        public void Used(IPEndPoint server)
        {
            var name = server.ToString();
            if (!Answered.Contains(name))
            {
                Answered.Add(name);
            }
        }

        public bool HasSentTo(IPEndPoint destination) => _sent.Contains(destination);

        public bool HasSentTo(IPAddress address) => _sent.Any(sent => sent.Address.Equals(address));

        /// <summary>A plain binding request, asked once per server however many steps want its answer.</summary>
        /// <returns>The answer, or null when the server did not answer with a mapped address.</returns>
        public async Task<StunMessage?> BindAsync(IPEndPoint server, CancellationToken ct)
        {
            if (_bindings.TryGetValue(server, out var known))
            {
                return known;
            }

            var answers = await RequestAllAsync([(server, Stun.Change.None)], ct).ConfigureAwait(false);
            var message = answers[0] is { Message: { MappedEndpoint: not null } mapped } ? mapped : null;
            _bindings[server] = message;
            return message;
        }

        /// <summary>Requests sent together and retried together, each matched to its own answer.</summary>
        /// <remarks>
        /// Matched on the transaction id and never on the source address: the whole point of the
        /// filtering tests is that the answer arrives from somewhere else. Datagrams that are not
        /// an answer to one of these are discarded, because the route's socket may carry other
        /// traffic. Every retransmission carries the same transaction id, as RFC 5389 §7.2.1 has
        /// it, so an answer to the first send that arrives during the second wait is still the
        /// answer; a fresh id per attempt threw exactly those away, turning a slow route into a
        /// silent one. Sent together because each request the NAT keeps the answer out of costs
        /// the whole retransmission schedule, and waiting for two at once costs the time of one.
        /// </remarks>
        public async Task<StunAnswer?[]> RequestAllAsync(
            IReadOnlyList<(IPEndPoint Server, Stun.Change Change)> requests, CancellationToken ct)
        {
            var ids = new byte[requests.Count][];
            var messages = new byte[requests.Count][];
            for (var i = 0; i < requests.Count; i++)
            {
                ids[i] = Stun.NewTransactionId();
                messages[i] = Stun.BuildBindingRequest(ids[i], requests[i].Change);
            }

            var answers = new StunAnswer?[requests.Count];
            var unreachable = new bool[requests.Count];
            bool Waiting()
            {
                for (var i = 0; i < answers.Length; i++)
                {
                    if (answers[i] is null && !unreachable[i])
                    {
                        return true;
                    }
                }

                return false;
            }

            foreach (var wait in attempts)
            {
                for (var i = 0; i < requests.Count; i++)
                {
                    if (answers[i] is not null || unreachable[i])
                    {
                        continue;
                    }

                    try
                    {
                        await transport.SendAsync(requests[i].Server, messages[i], ct).ConfigureAwait(false);
                        _sent.Add(requests[i].Server);
                    }
                    catch (Exception e) when (e is SocketException or ObjectDisposedException or AgentProtocolException
                                                 or IOException or ProxyHandshakeException or UdpUnsupportedException)
                    {
                        // The route would not carry a datagram to this server: as far as the test
                        // is concerned, the server did not answer.
                        unreachable[i] = true;
                    }
                }

                var deadline = DateTimeOffset.UtcNow + wait;
                while (Waiting() && DateTimeOffset.UtcNow < deadline)
                {
                    var datagram = await transport
                        .ReceiveAsync(deadline - DateTimeOffset.UtcNow, ct)
                        .ConfigureAwait(false);
                    if (datagram is null)
                    {
                        break;
                    }

                    if (Stun.TryParse(datagram.Value.Payload, out var message) &&
                        message is { Kind: StunMessageKind.BindingSuccess })
                    {
                        var index = Array.FindIndex(ids, id => id.AsSpan().SequenceEqual(message.TransactionId));
                        if (index >= 0)
                        {
                            answers[index] ??= new StunAnswer(message, datagram.Value.From);
                        }
                    }
                }

                if (!Waiting())
                {
                    break;
                }
            }

            return answers;
        }
    }
}

/// <summary>Raised when a route cannot carry UDP at all, which is an answer rather than an error.</summary>
public sealed class UdpUnsupportedException(string message) : Exception(message);

/// <summary>A way to send datagrams the way the route would, and read what comes back.</summary>
/// <remarks>
/// Small on purpose. The forwarder's UDP sessions cannot be reused here: each of those writes
/// its answers back to an application's socket, and this probe needs the answers in hand. What
/// the transports do reproduce is how the forwarder spreads destinations over sockets, because
/// that is what decides the mapping a peer sees.
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

/// <summary>A plain UDP socket: the direct path, which is the game's own socket.</summary>
/// <remarks>
/// Unconnected on purpose. The mapping test needs two destinations on one socket, and the
/// filtering test needs an answer from an address the socket never sent to — a connected
/// socket would drop exactly that.
/// </remarks>
internal sealed class SocketNatTransport : INatTransport
{
    private readonly Socket _socket;
    private readonly IPAddress? _source;

    private SocketNatTransport(Socket socket, IPAddress? source)
    {
        _socket = socket;
        _source = source;
    }

    public static SocketNatTransport Open(uint mark, IPEndPoint towards)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetMark(mark);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        return new SocketNatTransport(socket, SourceTowards(mark, towards));
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

    public string? Detail => null;

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

/// <summary>
/// Answers from several per-destination sockets or associations, collected in one queue.
/// </summary>
internal abstract class FannedInNatTransport : INatTransport
{
    private readonly System.Threading.Channels.Channel<NatDatagram> _answers =
        System.Threading.Channels.Channel.CreateUnbounded<NatDatagram>();

    protected CancellationTokenSource Closing { get; } = new();

    public abstract IPEndPoint? LocalEndpoint { get; }

    public abstract string? Detail { get; }

    public abstract Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct);

    protected void Deliver(NatDatagram datagram) => _answers.Writer.TryWrite(datagram);

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
        await Closing.CancelAsync().ConfigureAwait(false);
        await CloseAsync().ConfigureAwait(false);
        Closing.Dispose();
    }

    protected abstract ValueTask CloseAsync();
}

/// <summary>
/// One socket per destination, connected to it: how the forwarder relays a flow from inside a
/// WireGuard exit.
/// </summary>
/// <remarks>
/// The forwarder gives every (application socket, destination) flow a socket of its own, bound
/// to the tunnel address and connected to the destination. So a game talking to two peers
/// leaves by two source ports, and a datagram from anyone but the peer a socket is connected to
/// never reaches the game. Measuring that on one shared socket reported a mapping, and a
/// filter, that no routed game traffic ever has.
/// </remarks>
internal sealed class PerDestinationNatTransport : FannedInNatTransport
{
    private readonly uint _mark;
    private readonly IPAddress _source;
    private readonly Dictionary<IPEndPoint, Socket> _sockets = [];

    public PerDestinationNatTransport(uint mark, IPAddress source)
    {
        _mark = mark;
        _source = source;
    }

    /// <summary>The first socket's address: the tunnel's, which the far side sees translated or not.</summary>
    public override IPEndPoint? LocalEndpoint => _sockets.Values.FirstOrDefault()?.LocalEndPoint as IPEndPoint;

    public override string Detail =>
        $"Measured from inside the tunnel, source {_source}, with one socket per destination as the " +
        "forwarder relays a game's UDP — so each peer sees its own source port, and only the peer a " +
        "socket was opened for can answer it.";

    public override async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
    {
        if (!_sockets.TryGetValue(destination, out var socket))
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.SetMark(_mark);
                socket.Bind(new IPEndPoint(_source, 0));
                socket.Connect(destination);
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            _sockets[destination] = socket;
            _ = PumpAsync(socket, destination, Closing.Token);
        }

        await socket.SendAsync(payload, SocketFlags.None, ct).ConfigureAwait(false);
    }

    private async Task PumpAsync(Socket socket, IPEndPoint destination, CancellationToken ct)
    {
        var buffer = new byte[2048];
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

            // Connected, so the kernel delivers only what the destination sent.
            Deliver(new NatDatagram(destination, buffer[..received]));
        }
    }

    protected override ValueTask CloseAsync()
    {
        foreach (var socket in _sockets.Values)
        {
            socket.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>SOCKS5 UDP associations, one per destination, as the forwarder opens them.</summary>
/// <remarks>
/// The forwarder opens an association for every (application socket, destination) flow, and
/// hands whatever arrives on it to the application as if it came from that flow's destination.
/// So through Yura a game's peers see one relay socket each — whatever mapping the proxy keeps
/// per association — and a datagram from anyone else reaches the game labelled as the wrong
/// peer, which for peer-to-peer purposes is as good as not reaching it. That is what is measured
/// here: one association per destination, crediting only what the destination itself sent.
/// </remarks>
internal sealed class Socks5NatTransport : FannedInNatTransport
{
    private static readonly TimeSpan AssociateTimeout = TimeSpan.FromSeconds(10);

    private readonly ProxyHop _hop;
    private readonly IPAddress _proxyAddress;
    private readonly Dictionary<IPEndPoint, (Socket Control, Socket Relay)> _associations = [];

    private Socks5NatTransport(ProxyHop hop, IPAddress proxyAddress)
    {
        _hop = hop;
        _proxyAddress = proxyAddress;
    }

    /// <summary>Opens the association for the first destination now, so a proxy that refuses UDP says so at once.</summary>
    public static async Task<Socks5NatTransport> OpenAsync(ProxyHop hop, IPEndPoint firstDestination, CancellationToken ct)
    {
        var proxyAddress = await ProxyDialer.ResolveAsync(hop.Endpoint.Host, ct).ConfigureAwait(false);
        var transport = new Socks5NatTransport(hop, proxyAddress);
        try
        {
            await transport.AssociationForAsync(firstDestination, ct).ConfigureAwait(false);
        }
        catch
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        return transport;
    }

    /// <summary>Null: the socket facing the internet is the proxy's, not ours.</summary>
    public override IPEndPoint? LocalEndpoint => null;

    public override string Detail =>
        $"Measured through '{_hop.Endpoint.Name}' with one UDP association per destination, as the " +
        "forwarder relays a game's UDP — so each peer reaches the game through its own relay socket.";

    public override async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
    {
        var (_, relay) = await AssociationForAsync(destination, ct).ConfigureAwait(false);

        // SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT, then the datagram.
        var address = destination.Address.GetAddressBytes();
        var framed = new byte[4 + address.Length + 2 + payload.Length];
        framed[3] = destination.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
        address.CopyTo(framed, 4);
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(4 + address.Length), (ushort)destination.Port);
        payload.CopyTo(framed, 4 + address.Length + 2);

        await relay.SendAsync(framed, ct).ConfigureAwait(false);
    }

    private async Task<(Socket Control, Socket Relay)> AssociationForAsync(IPEndPoint destination, CancellationToken ct)
    {
        if (_associations.TryGetValue(destination, out var existing))
        {
            return existing;
        }

        var control = await ProxyDialer
            .ConnectWithBypassAsync(_hop.Endpoint.Host, _hop.Endpoint.Port, ct)
            .ConfigureAwait(false);

        IPEndPoint relayEndpoint;
        try
        {
            relayEndpoint = await AssociateAsync(control, ct).ConfigureAwait(false);
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

        _associations[destination] = (control, relay);
        _ = PumpAsync(relay, destination, Closing.Token);
        return (control, relay);
    }

    private async Task<IPEndPoint> AssociateAsync(Socket control, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(AssociateTimeout);
        try
        {
            using var stream = new NetworkStream(control, ownsSocket: false);
            await ProxyDialer.Socks5GreetAsync(stream, _hop.Endpoint.Username, _hop.Password, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(ProxyDialer.BuildSocks5Request(0x03, "0.0.0.0", 0), timeout.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeout.Token).ConfigureAwait(false);

            var reply = await ProxyDialer.ReadExactlyAsync(stream, 4, timeout.Token).ConfigureAwait(false);
            if (reply[1] != 0)
            {
                throw new UdpUnsupportedException(reply[1] == 7
                    ? $"'{_hop.Endpoint.Name}' refuses UDP, so a game's peer-to-peer traffic cannot go through it."
                    : $"'{_hop.Endpoint.Name}' refused UDP ASSOCIATE (reply {reply[1]:#x}).");
            }

            var bound = await ProxyDialer.DrainSocks5AddressAsync(stream, reply[3], timeout.Token).ConfigureAwait(false)
                        ?? throw new ProxyHandshakeException("The proxy returned a named relay address.");
            return bound.Address.Equals(IPAddress.Any) ? new IPEndPoint(_proxyAddress, bound.Port) : bound;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ProxyHandshakeException(
                $"'{_hop.Endpoint.Name}' did not answer UDP ASSOCIATE within {AssociateTimeout.TotalSeconds:0} s.");
        }
    }

    private async Task PumpAsync(Socket relay, IPEndPoint destination, CancellationToken ct)
    {
        var buffer = new byte[2048];
        while (!ct.IsCancellationRequested)
        {
            int received;
            try
            {
                received = await relay.ReceiveAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            if (received < 4 || buffer[2] != 0)
            {
                continue;
            }

            var offset = buffer[3] switch
            {
                1 => 4 + 4 + 2,
                4 => 4 + 16 + 2,
                3 when received > 4 => 4 + 1 + buffer[4] + 2,
                _ => -1,
            };
            if (offset < 0 || offset > received)
            {
                continue;
            }

            // The header names who sent it. Only the association's own destination is delivered
            // as itself by the forwarder, so only it is credited here.
            IPEndPoint? from = buffer[3] switch
            {
                1 => new IPEndPoint(new IPAddress(buffer.AsSpan(4, 4)), BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(8))),
                4 => new IPEndPoint(new IPAddress(buffer.AsSpan(4, 16)), BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(20))),
                _ => null,
            };
            if (from is not null && !from.Equals(destination))
            {
                continue;
            }

            Deliver(new NatDatagram(destination, buffer[offset..received]));
        }
    }

    protected override ValueTask CloseAsync()
    {
        foreach (var (control, relay) in _associations.Values)
        {
            relay.Dispose();
            control.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// An agent's datagram channel, used the way the forwarder uses it.
/// </summary>
/// <remarks>
/// Through an agent that grants full cone, one channel for every destination, because the
/// forwarder gives an application socket one channel whatever it sends to — so both servers see
/// one mapping, and an answer from the server's other address can arrive on it. Through one that
/// does not, a channel per destination, each a socket of its own at the agent, which a peer sees
/// as a different source port per peer. Either way this reports the mapping a game would really
/// get through that agent.
/// </remarks>
internal sealed class AgentNatTransport : FannedInNatTransport
{
    private readonly AgentSession _session;
    private readonly Dictionary<IPEndPoint, ushort> _channels = [];
    private ushort? _cone;

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
            session.FullCone
                ? $"Measured through agent '{session.AgentName}' with full-cone UDP: one socket at the agent for " +
                  "every peer, which anyone may send to if the agent's firewall lets them."
                : $"Measured through agent '{session.AgentName}'. The agent gives each destination its own " +
                  "socket, so a peer sees a different source port per peer. An agent started with full cone, " +
                  "which is the default for recent ones, would not.");
    }

    /// <summary>Null: the socket facing the internet is the agent's.</summary>
    public override IPEndPoint? LocalEndpoint => null;

    public override string? Detail { get; }

    public override async Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
    {
        ushort channel;
        if (_session.FullCone)
        {
            channel = _cone ??= _session.OpenChannel(
                (from, data) => Deliver(new NatDatagram(from, data.ToArray())), fullCone: true);
        }
        else if (!_channels.TryGetValue(destination, out channel))
        {
            channel = _session.OpenChannel((from, data) => Deliver(new NatDatagram(from, data.ToArray())));
            _channels[destination] = channel;
        }

        await _session.SendDatagramAsync(channel, destination, payload, ct).ConfigureAwait(false);
    }

    protected override async ValueTask CloseAsync()
    {
        foreach (var channel in _channels.Values)
        {
            _session.CloseChannel(channel);
        }

        if (_cone is { } cone)
        {
            _session.CloseChannel(cone);
        }

        await _session.DisposeAsync().ConfigureAwait(false);
    }
}
