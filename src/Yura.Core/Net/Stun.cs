using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Yura.Core.Net;

/// <summary>What a STUN message is.</summary>
public enum StunMessageKind
{
    /// <summary>Not a STUN message class we act on.</summary>
    Other,

    BindingRequest,

    BindingSuccess,

    BindingError,
}

/// <summary>The parts of a STUN message Yura reads.</summary>
/// <remarks>
/// Deliberately a small subset. Yura uses STUN for one thing — asking "what address does the
/// far side see me as" over a specific route — so authentication, fingerprints and the ICE
/// attributes are not parsed. What is absent is absent, never guessed: every address is
/// nullable and a missing one means the server did not send it.
/// </remarks>
public sealed record StunMessage
{
    public required StunMessageKind Kind { get; init; }

    public required byte[] TransactionId { get; init; }

    /// <summary>
    /// The address the server saw the request come from, from XOR-MAPPED-ADDRESS or, for an
    /// older server, MAPPED-ADDRESS.
    /// </summary>
    public IPEndPoint? MappedEndpoint { get; init; }

    /// <summary>
    /// The server's second address, from OTHER-ADDRESS (RFC 5780) or CHANGED-ADDRESS
    /// (RFC 3489). Without one, a server cannot answer from anywhere else, so the filtering
    /// tests cannot be run against it.
    /// </summary>
    public IPEndPoint? OtherAddress { get; init; }

    /// <summary>Which of the server's addresses this answer was sent from, when it says.</summary>
    public IPEndPoint? ResponseOrigin { get; init; }

    public string? Software { get; init; }

    public int? ErrorCode { get; init; }

    public string? ErrorReason { get; init; }
}

/// <summary>
/// The slice of STUN (RFC 5389 / RFC 5780) needed to discover a route's NAT behaviour.
/// </summary>
/// <remarks>
/// Written out rather than taken from a library because it is a hundred lines, because the
/// message has to be built and read identically whether it travels over a plain socket, a
/// SOCKS5 association or an agent's datagram channel, and because a NAT verdict is only worth
/// showing if the thing that produced it can be unit tested end to end.
/// </remarks>
public static class Stun
{
    public const int DefaultPort = 3478;

    /// <summary>RFC 5389 §6: the value that distinguishes STUN from anything else on the port.</summary>
    public const uint MagicCookie = 0x2112A442;

    public const int HeaderBytes = 20;

    public const int TransactionIdBytes = 12;

    private const ushort BindingRequest = 0x0001;
    private const ushort BindingSuccess = 0x0101;
    private const ushort BindingError = 0x0111;

    private const ushort AttrMappedAddress = 0x0001;
    private const ushort AttrChangeRequest = 0x0003;
    private const ushort AttrChangedAddress = 0x0005;
    private const ushort AttrErrorCode = 0x0009;
    private const ushort AttrXorMappedAddress = 0x0020;
    private const ushort AttrSoftware = 0x8022;
    private const ushort AttrResponseOrigin = 0x802B;
    private const ushort AttrOtherAddress = 0x802C;

    /// <summary>Where the server should answer from, which is what tests the NAT's filtering.</summary>
    [Flags]
    public enum Change
    {
        None = 0,

        /// <summary>Answer from the server's other port. Tests port-dependent filtering.</summary>
        Port = 0x02,

        /// <summary>Answer from the server's other address. Tests address-dependent filtering.</summary>
        Address = 0x04,
    }

    public static byte[] NewTransactionId() => RandomNumberGenerator.GetBytes(TransactionIdBytes);

    /// <summary>Builds a binding request, optionally asking to be answered from elsewhere.</summary>
    public static byte[] BuildBindingRequest(ReadOnlySpan<byte> transactionId, Change change = Change.None)
    {
        if (transactionId.Length != TransactionIdBytes)
        {
            throw new ArgumentException($"A STUN transaction id is {TransactionIdBytes} bytes.", nameof(transactionId));
        }

        var body = change == Change.None ? 0 : 8;
        var message = new byte[HeaderBytes + body];
        var span = message.AsSpan();

        BinaryPrimitives.WriteUInt16BigEndian(span, BindingRequest);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], (ushort)body);
        BinaryPrimitives.WriteUInt32BigEndian(span[4..], MagicCookie);
        transactionId.CopyTo(span[8..]);

        if (body > 0)
        {
            BinaryPrimitives.WriteUInt16BigEndian(span[20..], AttrChangeRequest);
            BinaryPrimitives.WriteUInt16BigEndian(span[22..], 4);
            BinaryPrimitives.WriteUInt32BigEndian(span[24..], (uint)change);
        }

        return message;
    }

    /// <summary>
    /// Reads a STUN message, or reports that the datagram is not one.
    /// </summary>
    /// <remarks>
    /// Returns false rather than throwing for anything malformed. These datagrams arrive from
    /// the network on a socket that a game's traffic also uses, so "not STUN" is an ordinary
    /// outcome and not an error.
    /// </remarks>
    public static bool TryParse(ReadOnlySpan<byte> datagram, out StunMessage? message)
    {
        message = null;
        if (datagram.Length < HeaderBytes)
        {
            return false;
        }

        var type = BinaryPrimitives.ReadUInt16BigEndian(datagram);

        // The two most significant bits of a STUN message type are zero.
        if ((type & 0xC000) != 0)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..]);
        if (BinaryPrimitives.ReadUInt32BigEndian(datagram[4..]) != MagicCookie ||
            HeaderBytes + length > datagram.Length)
        {
            return false;
        }

        var transactionId = datagram[8..20].ToArray();
        var kind = type switch
        {
            BindingRequest => StunMessageKind.BindingRequest,
            BindingSuccess => StunMessageKind.BindingSuccess,
            BindingError => StunMessageKind.BindingError,
            _ => StunMessageKind.Other,
        };

        IPEndPoint? mapped = null;
        IPEndPoint? xorMapped = null;
        IPEndPoint? other = null;
        IPEndPoint? origin = null;
        string? software = null;
        int? errorCode = null;
        string? errorReason = null;

        var attributes = datagram[HeaderBytes..(HeaderBytes + length)];
        var offset = 0;
        while (offset + 4 <= attributes.Length)
        {
            var attribute = BinaryPrimitives.ReadUInt16BigEndian(attributes[offset..]);
            var size = BinaryPrimitives.ReadUInt16BigEndian(attributes[(offset + 2)..]);
            var start = offset + 4;
            if (start + size > attributes.Length)
            {
                break;
            }

            var value = attributes[start..(start + size)];
            switch (attribute)
            {
                case AttrMappedAddress:
                    TryReadAddress(value, null, out mapped);
                    break;

                case AttrXorMappedAddress:
                    TryReadAddress(value, transactionId, out xorMapped);
                    break;

                case AttrOtherAddress or AttrChangedAddress:
                    // CHANGED-ADDRESS is the same thing under its RFC 3489 name; whichever
                    // arrives, it is the server's second address.
                    if (other is null)
                    {
                        TryReadAddress(value, null, out other);
                    }

                    break;

                case AttrResponseOrigin:
                    TryReadAddress(value, null, out origin);
                    break;

                case AttrSoftware:
                    software = Encoding.UTF8.GetString(value).TrimEnd('\0');
                    break;

                case AttrErrorCode when size >= 4:
                    errorCode = (value[2] * 100) + value[3];
                    errorReason = Encoding.UTF8.GetString(value[4..]).TrimEnd('\0');
                    break;
            }

            // Attributes are padded to a four-byte boundary; the padding is not counted in
            // the attribute's own length.
            offset = start + size + ((4 - (size % 4)) % 4);
        }

        message = new StunMessage
        {
            Kind = kind,
            TransactionId = transactionId,
            MappedEndpoint = xorMapped ?? mapped,
            OtherAddress = other,
            ResponseOrigin = origin,
            Software = software is { Length: > 0 } ? software : null,
            ErrorCode = errorCode,
            ErrorReason = errorReason is { Length: > 0 } ? errorReason : null,
        };
        return true;
    }

    /// <summary>
    /// Reads a STUN address attribute: a reserved byte, a family, a port and an address.
    /// </summary>
    /// <param name="transactionId">
    /// Non-null for XOR-MAPPED-ADDRESS, whose port and address are exclusive-ored with the
    /// magic cookie — and, for IPv6, with the transaction id as well. The point of that
    /// obfuscation is NATs that rewrite addresses they recognise inside payloads.
    /// </param>
    private static bool TryReadAddress(ReadOnlySpan<byte> value, byte[]? transactionId, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (value.Length < 8)
        {
            return false;
        }

        var family = value[1];
        var size = family switch { 0x01 => 4, 0x02 => 16, _ => 0 };
        if (size == 0 || value.Length < 4 + size)
        {
            return false;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(value[2..]);
        var address = value[4..(4 + size)].ToArray();

        if (transactionId is not null)
        {
            port ^= (ushort)(MagicCookie >> 16);
            Span<byte> mask = stackalloc byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(mask, MagicCookie);
            transactionId.CopyTo(mask[4..]);
            for (var i = 0; i < address.Length; i++)
            {
                address[i] ^= mask[i];
            }
        }

        endpoint = new IPEndPoint(new IPAddress(address), port);
        return endpoint.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
    }
}
