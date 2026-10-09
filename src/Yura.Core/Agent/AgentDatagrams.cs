using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Yura.Core.Agent;

/// <summary>What one datagram carries.</summary>
public enum AgentDatagramKind : byte
{
    /// <summary>A relayed datagram: channel, destination, payload.</summary>
    Relay = 1,

    /// <summary>Round trip on the datagram channel itself, which is how it is proved to work.</summary>
    Echo = 2,

    EchoReply = 3,

    /// <summary>Nothing to say; keeps the path and its NAT mapping alive.</summary>
    Keepalive = 4,

    /// <summary>
    /// A relayed datagram on a full-cone channel: the same layout as <see cref="Relay"/>, for a
    /// channel that stands for one of the client's sockets rather than one destination.
    /// </summary>
    /// <remarks>
    /// Chosen per channel, by the kind of its first datagram, and only in a session granted
    /// <see cref="AgentProtocol.Features.FullCone"/>. Per channel because not everything wants
    /// it: a name lookup comes from a fresh socket each time and gains nothing from a port kept
    /// open for minutes after it.
    /// </remarks>
    ConeRelay = 5,

    /// <summary>
    /// One piece of a body too large for one packet: id(4) index(1) count(1), then the piece.
    /// </summary>
    /// <remarks>
    /// Only in a session granted <see cref="AgentProtocol.Features.Fragments"/>. Each piece is
    /// sealed and counted like any datagram, so nobody outside the session can forge or repeat
    /// one, and the body they make up is handled as if it had arrived whole.
    /// </remarks>
    Fragment = 6,
}

/// <summary>
/// The datagram channel's encryption: AES-GCM under keys derived per session and direction.
/// </summary>
/// <remarks>
/// <para>
/// Datagrams do not go through TLS. Games are mostly UDP, and carrying UDP inside a TCP
/// connection means one lost packet delays every packet behind it — which is exactly the
/// damage an accelerator exists to avoid. So the control connection issues a key and the
/// datagrams carry their own AEAD, the same split QUIC and WireGuard use.
/// </para>
/// <para>
/// The master key is generated per session by the agent and travels only inside the
/// authenticated TLS control connection. Each direction gets its own derived key, so a
/// counter can never be reused with the same key even though both ends count from one, and
/// received counters go through a replay window. Nonces are the counter, never random: with
/// a 64-bit counter and one key per session there is nothing to collide with.
/// </para>
/// </remarks>
public sealed class AgentDatagramCrypto : IDisposable
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    private readonly byte[] _sessionId;
    private readonly AesGcm _send;
    private readonly AesGcm _receive;
    private readonly byte _sendDirection;
    private readonly byte _receiveDirection;
    private readonly Lock _replayGate = new();

    // AesGcm keeps one cipher context per instance and is not safe to use from two threads at
    // once: two datagrams sealed at the same moment — two of a game's peers answering together,
    // or a keepalive beside a relayed packet — make OpenSSL fail the operation outright. So each
    // direction is used by one thread at a time.
    private readonly Lock _sendGate = new();
    private readonly Lock _receiveGate = new();

    private ulong _counter;
    private ulong _highestSeen;
    private ulong _window;

    private AgentDatagramCrypto(byte[] sessionId, byte[] sendKey, byte[] receiveKey, byte sendDirection)
    {
        _sessionId = sessionId;
        _send = new AesGcm(sendKey, TagBytes);
        _receive = new AesGcm(receiveKey, TagBytes);
        _sendDirection = sendDirection;
        _receiveDirection = (byte)(sendDirection ^ 1);
    }

    /// <summary>True when this machine can do AES-GCM at all, which every supported platform can.</summary>
    public static bool IsSupported => AesGcm.IsSupported;

    /// <summary>The client's half: sends direction 0, accepts direction 1.</summary>
    public static AgentDatagramCrypto ForClient(byte[] sessionId, byte[] master) =>
        new(sessionId, DeriveKey(master, sessionId, "c2a"), DeriveKey(master, sessionId, "a2c"), 0);

    /// <summary>The agent's half: sends direction 1, accepts direction 0.</summary>
    public static AgentDatagramCrypto ForAgent(byte[] sessionId, byte[] master) =>
        new(sessionId, DeriveKey(master, sessionId, "a2c"), DeriveKey(master, sessionId, "c2a"), 1);

    /// <summary>
    /// One direction's key. Salted with the session id so keys cannot be carried between
    /// sessions even if a master key were ever reused.
    /// </summary>
    public static byte[] DeriveKey(byte[] master, byte[] sessionId, string direction) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            master,
            AgentProtocol.KeyBytes,
            sessionId,
            System.Text.Encoding.ASCII.GetBytes($"yura-agent/{AgentProtocol.Version} {direction}"));

    /// <summary>The largest sealed packet a payload of this size produces.</summary>
    public static int SealedSize(int plaintextLength) => AgentProtocol.DatagramOverheadBytes + plaintextLength;

    /// <summary>Seals one datagram into <paramref name="destination"/>, returning its length.</summary>
    public int Seal(ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        var length = SealedSize(plaintext.Length);
        if (destination.Length < length)
        {
            throw new ArgumentException("the destination buffer is too small for this datagram", nameof(destination));
        }

        lock (_sendGate)
        {
            var counter = ++_counter;
            _sessionId.CopyTo(destination);
            destination[AgentProtocol.SessionIdBytes] = _sendDirection;
            BinaryPrimitives.WriteUInt64BigEndian(destination[(AgentProtocol.SessionIdBytes + 1)..], counter);

            var header = destination[..AgentProtocol.DatagramHeaderBytes];
            Span<byte> nonce = stackalloc byte[NonceBytes];
            nonce[3] = _sendDirection;
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], counter);

            _send.Encrypt(
                nonce,
                plaintext,
                destination.Slice(AgentProtocol.DatagramHeaderBytes, plaintext.Length),
                destination.Slice(AgentProtocol.DatagramHeaderBytes + plaintext.Length, TagBytes),
                header);
        }

        return length;
    }

    /// <summary>
    /// Opens a datagram, rejecting anything that is not this session's, not this direction's,
    /// forged, or a replay.
    /// </summary>
    public bool TryOpen(ReadOnlySpan<byte> packet, Span<byte> plaintext, out int length)
    {
        length = 0;
        if (packet.Length < AgentProtocol.DatagramOverheadBytes ||
            !packet[..AgentProtocol.SessionIdBytes].SequenceEqual(_sessionId) ||
            packet[AgentProtocol.SessionIdBytes] != _receiveDirection)
        {
            return false;
        }

        var counter = BinaryPrimitives.ReadUInt64BigEndian(packet[(AgentProtocol.SessionIdBytes + 1)..]);
        if (counter == 0 || !WithinWindow(counter, commit: false))
        {
            return false;
        }

        var body = packet.Length - AgentProtocol.DatagramOverheadBytes;
        if (plaintext.Length < body)
        {
            return false;
        }

        Span<byte> nonce = stackalloc byte[NonceBytes];
        nonce[3] = _receiveDirection;
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], counter);

        try
        {
            lock (_receiveGate)
            {
                _receive.Decrypt(
                    nonce,
                    packet.Slice(AgentProtocol.DatagramHeaderBytes, body),
                    packet.Slice(AgentProtocol.DatagramHeaderBytes + body, TagBytes),
                    plaintext[..body],
                    packet[..AgentProtocol.DatagramHeaderBytes]);
            }
        }
        catch (AuthenticationTagMismatchException)
        {
            // Forged, corrupted, or a packet for a session that has been re-keyed. Silent by
            // design: answering would tell an attacker which of those it was.
            return false;
        }

        // Only counted once the packet is known to be genuine, so a forgery cannot advance the
        // window and lock out real datagrams.
        if (!WithinWindow(counter, commit: true))
        {
            return false;
        }

        length = body;
        return true;
    }

    /// <summary>
    /// The replay window: the highest counter seen and a bitmap of the 64 below it.
    /// </summary>
    /// <remarks>
    /// Datagrams reorder, so a window rather than a high-water mark; 64 is what IPsec and
    /// WireGuard use and is far wider than any reordering a game path produces.
    /// </remarks>
    private bool WithinWindow(ulong counter, bool commit)
    {
        lock (_replayGate)
        {
            if (counter > _highestSeen)
            {
                if (!commit)
                {
                    return true;
                }

                var advance = counter - _highestSeen;
                _window = advance >= 64 ? 1 : (_window << (int)advance) | 1;
                _highestSeen = counter;
                return true;
            }

            var behind = _highestSeen - counter;
            if (behind >= 64)
            {
                return false;
            }

            var mask = 1UL << (int)behind;
            if ((_window & mask) != 0)
            {
                return false;
            }

            if (commit)
            {
                _window |= mask;
            }

            return true;
        }
    }

    public void Dispose()
    {
        _send.Dispose();
        _receive.Dispose();
    }
}

/// <summary>
/// The body of a datagram, inside the AEAD.
/// </summary>
/// <remarks>
/// A relayed datagram names a channel as well as an address: the destination on the way out,
/// the sender on the way back. The channel is the client's own handle: the agent keeps a socket
/// per channel, so a game's source port at the far end stays stable for as long as it is
/// playing, and the answer comes back with the channel already on it. An ordinary channel
/// stands for one (process, destination) pair; a full-cone one (<see cref="AgentDatagramKind.ConeRelay"/>)
/// for one of the client's sockets, whatever it sends to and whoever sends to it.
/// </remarks>
public static class AgentDatagram
{
    /// <summary>kind(1) channel(2) type(1) address(16 max) port(2).</summary>
    public const int MaxRelayHeaderBytes = 22;

    public static int MaxPacketBytes =>
        AgentProtocol.DatagramOverheadBytes + MaxRelayHeaderBytes + AgentProtocol.MaxDatagramPayload;

    /// <summary>The largest body one packet carries: a relay header and a full payload.</summary>
    public static int MaxBodyBytes => MaxRelayHeaderBytes + AgentProtocol.MaxDatagramPayload;

    /// <summary>kind(1) id(4) index(1) count(1).</summary>
    public const int FragmentHeaderBytes = 7;

    /// <summary>The most of a body one fragment carries.</summary>
    public static int MaxPieceBytes => MaxBodyBytes - FragmentHeaderBytes;

    /// <summary>The most pieces the largest datagram carried at all is split into.</summary>
    public static int MaxPieces => (MaxRelayHeaderBytes + AgentProtocol.MaxFragmentedPayload + MaxPieceBytes - 1) / MaxPieceBytes;

    /// <summary>
    /// Splits a body too large for one packet into fragments, each a datagram body of its own:
    /// every piece full-size but the last.
    /// </summary>
    public static List<byte[]> Split(ReadOnlySpan<byte> body, uint id)
    {
        var count = (body.Length + MaxPieceBytes - 1) / MaxPieceBytes;
        if (count < 2 || count > MaxPieces)
        {
            throw new ArgumentException($"a {body.Length}-byte body is not split into {count} piece(s)", nameof(body));
        }

        var fragments = new List<byte[]>(count);
        for (var index = 0; index < count; index++)
        {
            var piece = body.Slice(index * MaxPieceBytes, Math.Min(MaxPieceBytes, body.Length - (index * MaxPieceBytes)));
            var fragment = new byte[FragmentHeaderBytes + piece.Length];
            fragment[0] = (byte)AgentDatagramKind.Fragment;
            BinaryPrimitives.WriteUInt32BigEndian(fragment.AsSpan(1), id);
            fragment[5] = (byte)index;
            fragment[6] = (byte)count;
            piece.CopyTo(fragment.AsSpan(FragmentHeaderBytes));
            fragments.Add(fragment);
        }

        return fragments;
    }

    /// <param name="cone">Write it as <see cref="AgentDatagramKind.ConeRelay"/>, for a full-cone channel.</param>
    public static int WriteRelay(
        Span<byte> destination, ushort channel, IPEndPoint target, ReadOnlySpan<byte> payload, bool cone = false)
    {
        var address = target.Address.GetAddressBytes();
        var length = 4 + address.Length + 2 + payload.Length;
        if (destination.Length < length)
        {
            throw new ArgumentException("the destination buffer is too small", nameof(destination));
        }

        destination[0] = (byte)(cone ? AgentDatagramKind.ConeRelay : AgentDatagramKind.Relay);
        BinaryPrimitives.WriteUInt16BigEndian(destination[1..], channel);
        destination[3] = target.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
        address.CopyTo(destination[4..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(4 + address.Length)..], (ushort)target.Port);
        payload.CopyTo(destination[(4 + address.Length + 2)..]);
        return length;
    }

    public static int WriteSimple(Span<byte> destination, AgentDatagramKind kind, ReadOnlySpan<byte> payload)
    {
        destination[0] = (byte)kind;
        payload.CopyTo(destination[1..]);
        return 1 + payload.Length;
    }

    public static AgentDatagramKind KindOf(ReadOnlySpan<byte> body) =>
        body.Length == 0 ? default : (AgentDatagramKind)body[0];

    /// <summary>Reads a relay body of either kind, without copying the payload.</summary>
    public static bool TryReadRelay(
        ReadOnlySpan<byte> body, out ushort channel, out IPEndPoint? target, out ReadOnlySpan<byte> payload)
    {
        channel = 0;
        target = null;
        payload = default;

        if (body.Length < 4 || body[0] is not ((byte)AgentDatagramKind.Relay or (byte)AgentDatagramKind.ConeRelay))
        {
            return false;
        }

        var addressLength = body[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            _ => 0,
        };

        if (addressLength == 0 || body.Length < 4 + addressLength + 2)
        {
            return false;
        }

        channel = BinaryPrimitives.ReadUInt16BigEndian(body[1..]);
        target = new IPEndPoint(
            new IPAddress(body.Slice(4, addressLength)),
            BinaryPrimitives.ReadUInt16BigEndian(body[(4 + addressLength)..]));
        payload = body[(4 + addressLength + 2)..];
        return true;
    }
}

/// <summary>
/// Puts fragmented datagrams back together, within bounds the other end cannot push.
/// </summary>
/// <remarks>
/// Every piece arrived sealed and through the replay window, so nothing outside the session can
/// forge or repeat one. What is bounded here is what the session's own peer can make this end
/// hold: <see cref="MaxPending"/> datagrams in progress, each no larger than
/// <see cref="AgentProtocol.MaxFragmentedPayload"/>, none for longer than <see cref="Patience"/>.
/// After that, a datagram still missing a piece is as lost as one that never arrived, which is
/// what anything using UDP is built to expect.
/// </remarks>
public sealed class AgentFragmentAssembler(TimeProvider? time = null)
{
    /// <summary>How long a datagram may wait for its missing pieces.</summary>
    public static readonly TimeSpan Patience = TimeSpan.FromSeconds(2);

    /// <summary>How many datagrams may be in progress at once; a new one pushes out the oldest.</summary>
    public const int MaxPending = 16;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly Dictionary<uint, Pending> _pending = [];
    private readonly Lock _gate = new();

    private sealed class Pending(int count, DateTimeOffset started)
    {
        public byte[]?[] Pieces { get; } = new byte[]?[count];

        public int Missing { get; set; } = count;

        public DateTimeOffset Started { get; } = started;
    }

    /// <summary>Datagrams now in progress.</summary>
    public int InProgress
    {
        get
        {
            lock (_gate)
            {
                return _pending.Count;
            }
        }
    }

    /// <summary>Takes one fragment, and returns the whole body once its last piece is in.</summary>
    /// <returns>The body, or null while pieces are missing or when the fragment was not a valid one.</returns>
    public byte[]? Add(ReadOnlySpan<byte> fragment)
    {
        if (fragment.Length <= AgentDatagram.FragmentHeaderBytes || fragment[0] != (byte)AgentDatagramKind.Fragment)
        {
            return null;
        }

        var id = BinaryPrimitives.ReadUInt32BigEndian(fragment[1..]);
        int index = fragment[5];
        int count = fragment[6];
        var piece = fragment[AgentDatagram.FragmentHeaderBytes..];

        // Every piece but the last is full-size, which is what holds the whole to the limit.
        if (count < 2 || count > AgentDatagram.MaxPieces || index >= count ||
            piece.Length > AgentDatagram.MaxPieceBytes ||
            (index < count - 1 && piece.Length != AgentDatagram.MaxPieceBytes))
        {
            return null;
        }

        lock (_gate)
        {
            var now = _time.GetUtcNow();
            foreach (var stale in _pending.Where(p => now - p.Value.Started > Patience).Select(p => p.Key).ToList())
            {
                _pending.Remove(stale);
            }

            if (!_pending.TryGetValue(id, out var pending))
            {
                if (_pending.Count >= MaxPending)
                {
                    _pending.Remove(_pending.MinBy(p => p.Value.Started).Key);
                }

                pending = new Pending(count, now);
                _pending[id] = pending;
            }
            else if (pending.Pieces.Length != count)
            {
                // Pieces that disagree about how many there are cannot make one datagram.
                _pending.Remove(id);
                return null;
            }

            if (pending.Pieces[index] is not null)
            {
                return null;
            }

            pending.Pieces[index] = piece.ToArray();
            if (--pending.Missing > 0)
            {
                return null;
            }

            _pending.Remove(id);
            var whole = new byte[pending.Pieces.Sum(p => p!.Length)];
            var offset = 0;
            foreach (var part in pending.Pieces)
            {
                part!.CopyTo(whole, offset);
                offset += part.Length;
            }

            return whole;
        }
    }
}
