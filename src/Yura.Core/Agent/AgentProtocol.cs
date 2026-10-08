using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Yura.Core.Agent;

/// <summary>Raised when the other end sends something the protocol does not allow.</summary>
public sealed class AgentProtocolException(string message) : Exception(message);

/// <summary>What one control frame is for.</summary>
public enum AgentFrameKind : byte
{
    /// <summary>Client's first frame on any connection: version, token, and what it is for.</summary>
    Hello = 1,

    /// <summary>Answer to a control <see cref="Hello"/>: session id, datagram key, limits.</summary>
    Welcome = 2,

    /// <summary>Client asks a stream connection to be joined to a destination.</summary>
    Open = 3,

    /// <summary>Destination reached. Everything after this frame is the tunnel itself.</summary>
    Opened = 4,

    /// <summary>Refusal, with a reason. Always the last frame on the connection.</summary>
    Reject = 5,

    /// <summary>Liveness and round-trip measurement on the control connection.</summary>
    Ping = 6,

    Pong = 7,

    /// <summary>Ask the agent to measure the round trip from where it is standing.</summary>
    Probe = 8,

    Probed = 9,

    /// <summary>Ask what the agent is doing: sessions, streams, bytes.</summary>
    Stats = 10,

    StatsReply = 11,

    /// <summary>The agent is going away. Sent before it stops accepting.</summary>
    Bye = 12,
}

/// <summary>What a connection is being opened for.</summary>
public enum AgentRole : byte
{
    /// <summary>The session: authentication, keepalive, probes, and the datagram key.</summary>
    Control = 0,

    /// <summary>One relayed TCP flow, which the connection becomes after <see cref="AgentFrameKind.Opened"/>.</summary>
    Stream = 1,
}

/// <summary>Why the agent refused. Distinct codes so the client can say something useful.</summary>
public enum AgentRejection : byte
{
    /// <summary>The token did not match. Deliberately says nothing more.</summary>
    Unauthorised = 1,

    UnsupportedVersion = 2,

    /// <summary>The agent's own policy forbids this destination.</summary>
    DestinationRefused = 3,

    /// <summary>The agent tried and could not reach the destination.</summary>
    ConnectFailed = 4,

    /// <summary>A limit was hit: sessions, streams, or channels.</summary>
    TooMany = 5,

    Malformed = 6,

    /// <summary>The agent was started without UDP relaying.</summary>
    UdpDisabled = 7,

    /// <summary>
    /// The destination itself refused: it is there, and answered. Kept apart from
    /// <see cref="ConnectFailed"/> because measuring counts it as an answer. An agent older than
    /// this code says <see cref="ConnectFailed"/> instead, and a client older than it shows the message.
    /// </summary>
    ConnectionRefused = 8,
}

/// <summary>
/// The Yura Agent Protocol, version 1.
/// </summary>
/// <remarks>
/// <para>
/// The agent runs on a server near a game's servers; the daemon sends selected flows through
/// it. What a plain SOCKS5 proxy cannot do, and this exists for:
/// </para>
/// <list type="bullet">
/// <item>The connection is authenticated in both directions before anything is relayed — the
/// server by a pinned public key, the client by a shared token — with no certificate
/// authority and no password to type.</item>
/// <item>UDP is a first-class transport rather than an optional command, because games are
/// mostly UDP, and it is carried over its own encrypted datagram channel rather than inside
/// the TCP connection: a lost game packet must not delay the ones behind it.</item>
/// <item>The agent will measure the round trip to a destination from where <em>it</em> is
/// standing, which is the only way to say why a route is faster or slower rather than just
/// that it is.</item>
/// </list>
/// <para>
/// Framing: <c>kind(1) | length(3, big endian) | payload</c>, over TLS 1.3. Every integer on
/// the wire is big endian. A stream connection stops being framed once the destination is
/// joined — after <see cref="AgentFrameKind.Opened"/> the bytes are the application's, so
/// the relay is a plain copy with no per-chunk header to add or trust.
/// </para>
/// </remarks>
public static class AgentProtocol
{
    public const byte Version = 1;

    /// <summary>Sent at the head of the first frame so a wrong port fails clearly.</summary>
    public static ReadOnlySpan<byte> Magic => "YURA"u8;

    public const int TokenBytes = 32;

    public const int SessionIdBytes = 8;

    public const int KeyBytes = 32;

    /// <summary>Frames carry a handshake, never payload, so this is generous already.</summary>
    public const int MaxFramePayload = 8 * 1024;

    /// <summary>
    /// The largest datagram payload the protocol will carry.
    /// </summary>
    /// <remarks>
    /// Chosen so the whole packet — payload, relay header, <see cref="DatagramOverheadBytes"/>,
    /// and an IPv6 and UDP header — fits inside a 1500-byte path with room to spare for one
    /// layer of encapsulation on the way. A fragmented game packet arrives late and in pieces,
    /// which is worse than a smaller one, so the limit is enforced rather than approached.
    /// Anything larger is refused with a reason instead of being split.
    /// </remarks>
    public const int MaxDatagramPayload = 1350;

    /// <summary>sessionId(8) | direction(1) | counter(8).</summary>
    public const int DatagramHeaderBytes = 17;

    /// <summary>Header plus the AEAD tag.</summary>
    public const int DatagramOverheadBytes = DatagramHeaderBytes + 16;

    public const ushort DefaultPort = 7311;

    /// <summary>
    /// How long an agent keeps a full-cone channel's port after the client last sent on it.
    /// </summary>
    /// <remarks>
    /// Part of the protocol rather than either end's choice, because both have to agree: a
    /// client that kept a channel longer than the agent would send on one the agent had closed,
    /// and be given a new port under an address its peers still hold. RFC 4787 asks a NAT to
    /// keep a UDP mapping at least two minutes, and recommends five.
    /// </remarks>
    public static readonly TimeSpan ConeMappingLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Feature bits, exchanged so neither end has to guess what the other supports.</summary>
    [Flags]
    public enum Features : ushort
    {
        None = 0,

        /// <summary>The datagram channel is available.</summary>
        Udp = 1 << 0,

        /// <summary>The agent will resolve names on the client's behalf.</summary>
        Resolve = 1 << 1,

        /// <summary>The agent will measure a destination on request.</summary>
        Probe = 1 << 2,

        /// <summary>
        /// Full-cone UDP: a datagram channel stands for one of the client's sockets rather than
        /// one destination. It keeps one address at the agent for every peer it sends to, and
        /// datagrams from anyone are relayed back with their true source.
        /// </summary>
        /// <remarks>
        /// What a peer-to-peer game needs to be reachable through the agent. Asked for by the
        /// client and granted per session, so either end may be older than the other: a session
        /// without it has a channel per destination, each with a socket of its own.
        /// </remarks>
        FullCone = 1 << 3,
    }

    // -- framing -------------------------------------------------------------

    public static async Task WriteFrameAsync(
        Stream stream, AgentFrameKind kind, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        if (payload.Length > MaxFramePayload)
        {
            throw new AgentProtocolException($"a {kind} frame of {payload.Length} bytes is over the limit");
        }

        var header = new byte[4];
        header[0] = (byte)kind;
        header[1] = (byte)(payload.Length >> 16);
        header[2] = (byte)(payload.Length >> 8);
        header[3] = (byte)payload.Length;

        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        }

        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<(AgentFrameKind Kind, byte[] Payload)> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        try
        {
            await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            throw new AgentProtocolException("the connection closed before a frame arrived");
        }

        var length = (header[1] << 16) | (header[2] << 8) | header[3];
        if (length > MaxFramePayload)
        {
            throw new AgentProtocolException($"a frame claimed {length} bytes, over the limit");
        }

        var payload = new byte[length];
        if (length > 0)
        {
            try
            {
                await stream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
            }
            catch (EndOfStreamException)
            {
                throw new AgentProtocolException("the connection closed part way through a frame");
            }
        }

        return ((AgentFrameKind)header[0], payload);
    }

    // -- payload primitives --------------------------------------------------

    /// <summary>Builds a frame payload. Frames are small, so clarity is worth more than reuse.</summary>
    public sealed class Writer
    {
        private readonly List<byte> _bytes = [];

        public Writer Byte(byte value)
        {
            _bytes.Add(value);
            return this;
        }

        public Writer UInt16(ushort value)
        {
            _bytes.Add((byte)(value >> 8));
            _bytes.Add((byte)value);
            return this;
        }

        public Writer UInt32(uint value)
        {
            Span<byte> scratch = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(scratch, value);
            _bytes.AddRange(scratch);
            return this;
        }

        public Writer UInt64(ulong value)
        {
            Span<byte> scratch = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(scratch, value);
            _bytes.AddRange(scratch);
            return this;
        }

        public Writer Bytes(ReadOnlySpan<byte> value)
        {
            _bytes.AddRange(value);
            return this;
        }

        /// <summary>A short string with a one-byte length, which is every string this protocol has.</summary>
        public Writer Text(string? value)
        {
            var encoded = Encoding.UTF8.GetBytes(value ?? string.Empty);
            if (encoded.Length > 255)
            {
                encoded = encoded[..255];
            }

            _bytes.Add((byte)encoded.Length);
            _bytes.AddRange(encoded);
            return this;
        }

        /// <summary>An address as type, value and port.</summary>
        public Writer Address(AgentAddress address)
        {
            if (IPAddress.TryParse(address.Host, out var ip))
            {
                var raw = ip.GetAddressBytes();
                _bytes.Add(raw.Length == 16 ? (byte)0x04 : (byte)0x01);
                _bytes.AddRange(raw);
            }
            else
            {
                var name = Encoding.ASCII.GetBytes(address.Host);
                if (name.Length > 255)
                {
                    throw new AgentProtocolException("the destination host name is too long");
                }

                _bytes.Add(0x03);
                _bytes.Add((byte)name.Length);
                _bytes.AddRange(name);
            }

            return UInt16(address.Port);
        }

        public byte[] ToArray() => _bytes.ToArray();
    }

    /// <summary>Reads a frame payload, refusing anything short or malformed.</summary>
    public ref struct Reader(ReadOnlySpan<byte> payload)
    {
        private ReadOnlySpan<byte> _rest = payload;

        public int Remaining => _rest.Length;

        private ReadOnlySpan<byte> Take(int count)
        {
            if (_rest.Length < count)
            {
                throw new AgentProtocolException("a frame ended part way through a field");
            }

            var taken = _rest[..count];
            _rest = _rest[count..];
            return taken;
        }

        public byte Byte() => Take(1)[0];

        public ushort UInt16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));

        public uint UInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        public ulong UInt64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));

        public byte[] Bytes(int count) => Take(count).ToArray();

        public string Text() => Encoding.UTF8.GetString(Take(Byte()));

        public AgentAddress Address()
        {
            var type = Byte();
            var host = type switch
            {
                0x01 => new IPAddress(Take(4)).ToString(),
                0x04 => new IPAddress(Take(16)).ToString(),
                0x03 => Encoding.ASCII.GetString(Take(Byte())),
                _ => throw new AgentProtocolException($"unknown address type {type:#x}"),
            };

            return new AgentAddress(host, UInt16());
        }
    }
}

/// <summary>A destination: a literal address or a name, with a port.</summary>
public readonly record struct AgentAddress(string Host, ushort Port)
{
    public static AgentAddress From(IPEndPoint endpoint) =>
        new(endpoint.Address.ToString(), (ushort)endpoint.Port);

    /// <summary>True when the host is a literal, which is the only form the forwarder sends.</summary>
    public bool IsLiteral => IPAddress.TryParse(Host, out _);

    public IPEndPoint? AsEndPoint() =>
        IPAddress.TryParse(Host, out var address) ? new IPEndPoint(address, Port) : null;

    public override string ToString() =>
        Host.Contains(':', StringComparison.Ordinal) ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}

/// <summary>First frame on every connection: what version, what for, and with what authority.</summary>
public sealed record AgentHello(AgentRole Role, byte[] Token, AgentProtocol.Features Wanted, string Label)
{
    public byte[] Encode() => new AgentProtocol.Writer()
        .Bytes(AgentProtocol.Magic)
        .Byte(AgentProtocol.Version)
        .Byte((byte)Role)
        .Bytes(Token)
        .UInt16((ushort)Wanted)
        .Text(Label)
        .ToArray();

    public static AgentHello Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        if (!reader.Bytes(4).AsSpan().SequenceEqual(AgentProtocol.Magic))
        {
            throw new AgentProtocolException("this is not a Yura agent client");
        }

        var version = reader.Byte();
        if (version != AgentProtocol.Version)
        {
            throw new AgentProtocolException($"protocol version {version} is not supported");
        }

        var role = reader.Byte();
        var token = reader.Bytes(AgentProtocol.TokenBytes);
        var wanted = (AgentProtocol.Features)reader.UInt16();
        return new AgentHello(
            role switch
            {
                0 => AgentRole.Control,
                1 => AgentRole.Stream,
                _ => throw new AgentProtocolException($"unknown role {role}"),
            },
            token,
            wanted,
            reader.Text());
    }
}

/// <summary>
/// The session, as the agent granted it: its identity, its limits, and the key for the
/// datagram channel.
/// </summary>
/// <remarks>
/// The datagram key is generated per session by the agent and travels only inside the
/// authenticated TLS connection. Possession of it is what authorises datagrams, so the
/// session id can be — and is — public: it is the demultiplexing key on a shared UDP port.
/// </remarks>
public sealed record AgentWelcome(
    byte[] SessionId,
    byte[] DatagramKey,
    ushort DatagramPort,
    ushort MaxDatagramPayload,
    AgentProtocol.Features Available,
    string AgentVersion,
    string AgentName,
    string Resolver = "")
{
    /// <summary>
    /// The resolver the agent itself uses, when it has one to offer.
    /// </summary>
    /// <remarks>
    /// Name lookups from a process on this exit are sent here, because the resolver the
    /// application asked for is usually a LAN or loopback address that means nothing at the
    /// far end — and because a game's servers are chosen by DNS, so resolving where the agent
    /// is standing is what makes the acceleration work rather than merely happen.
    /// </remarks>
    public string Resolver { get; init; } = Resolver;

    public byte[] Encode() => new AgentProtocol.Writer()
        .Byte(AgentProtocol.Version)
        .Bytes(SessionId)
        .Bytes(DatagramKey)
        .UInt16(DatagramPort)
        .UInt16(MaxDatagramPayload)
        .UInt16((ushort)Available)
        .Text(AgentVersion)
        .Text(AgentName)
        .Text(Resolver)
        .ToArray();

    public static AgentWelcome Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        var version = reader.Byte();
        if (version != AgentProtocol.Version)
        {
            throw new AgentProtocolException($"the agent speaks protocol version {version}, which this build does not");
        }

        return new AgentWelcome(
            reader.Bytes(AgentProtocol.SessionIdBytes),
            reader.Bytes(AgentProtocol.KeyBytes),
            reader.UInt16(),
            reader.UInt16(),
            (AgentProtocol.Features)reader.UInt16(),
            reader.Text(),
            reader.Text(),
            reader.Text());
    }
}

/// <summary>Join this stream connection to a destination.</summary>
public sealed record AgentOpen(AgentAddress Target)
{
    public byte[] Encode() => new AgentProtocol.Writer().Address(Target).ToArray();

    public static AgentOpen Decode(ReadOnlySpan<byte> payload) =>
        new(new AgentProtocol.Reader(payload).Address());
}

/// <summary>
/// The destination is joined. Carries what the destination sees as the source, and how long
/// the agent's own connect took — the half of the round trip the client cannot measure.
/// </summary>
public sealed record AgentOpened(string LocalEndpoint, uint ConnectMicroseconds)
{
    public byte[] Encode() => new AgentProtocol.Writer()
        .Text(LocalEndpoint)
        .UInt32(ConnectMicroseconds)
        .ToArray();

    public static AgentOpened Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        return new AgentOpened(reader.Text(), reader.UInt32());
    }
}

/// <summary>A refusal and its reason, which is the last thing sent on that connection.</summary>
public sealed record AgentReject(AgentRejection Code, string Message)
{
    public byte[] Encode() => new AgentProtocol.Writer().Byte((byte)Code).Text(Message).ToArray();

    public static AgentReject Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        return new AgentReject((AgentRejection)reader.Byte(), reader.Text());
    }
}

/// <summary>Measure a destination from the agent, so a route's two halves can be told apart.</summary>
public sealed record AgentProbeRequest(uint RequestId, byte Samples, AgentAddress Target)
{
    public byte[] Encode() => new AgentProtocol.Writer()
        .UInt32(RequestId)
        .Byte(Samples)
        .Address(Target)
        .ToArray();

    public static AgentProbeRequest Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        return new AgentProbeRequest(reader.UInt32(), reader.Byte(), reader.Address());
    }
}

/// <summary>What the agent measured. An empty sample list with a reason is a real answer.</summary>
public sealed record AgentProbeReply(uint RequestId, string Resolved, uint[] Microseconds, string? Failure)
{
    public byte[] Encode()
    {
        var writer = new AgentProtocol.Writer()
            .UInt32(RequestId)
            .Text(Resolved)
            .Byte((byte)Math.Min(Microseconds.Length, 255));
        foreach (var sample in Microseconds.Take(255))
        {
            writer.UInt32(sample);
        }

        return writer.Text(Failure).ToArray();
    }

    public static AgentProbeReply Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        var requestId = reader.UInt32();
        var resolved = reader.Text();
        var count = reader.Byte();
        var samples = new uint[count];
        for (var i = 0; i < count; i++)
        {
            samples[i] = reader.UInt32();
        }

        var failure = reader.Text();
        return new AgentProbeReply(requestId, resolved, samples, failure.Length == 0 ? null : failure);
    }
}

/// <summary>
/// What the agent is carrying right now.
/// </summary>
/// <param name="Refused">
/// Destinations the agent's own policy turned away. Worth reporting: a game that will not
/// work through an agent whose policy forbids its servers looks like a network fault, and this
/// is what tells the operator it is not one.
/// </param>
public sealed record AgentStats(
    uint Sessions,
    uint Streams,
    uint Channels,
    ulong BytesUp,
    ulong BytesDown,
    ulong UptimeSeconds,
    uint Refused)
{
    public byte[] Encode() => new AgentProtocol.Writer()
        .UInt32(Sessions)
        .UInt32(Streams)
        .UInt32(Channels)
        .UInt64(BytesUp)
        .UInt64(BytesDown)
        .UInt64(UptimeSeconds)
        .UInt32(Refused)
        .ToArray();

    public static AgentStats Decode(ReadOnlySpan<byte> payload)
    {
        var reader = new AgentProtocol.Reader(payload);
        return new AgentStats(
            reader.UInt32(), reader.UInt32(), reader.UInt32(),
            reader.UInt64(), reader.UInt64(), reader.UInt64(), reader.UInt32());
    }
}
