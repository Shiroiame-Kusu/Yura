using System.Buffers.Binary;
using System.Net;
using Yura.Core.Net;

namespace Yura.Core.Tests;

/// <summary>
/// The STUN codec, against messages built the way RFC 5389 says to build them.
/// </summary>
/// <remarks>
/// The parser is what a NAT verdict rests on: an address read wrongly is a verdict stated
/// confidently and wrongly, which is worse for a player than no verdict at all. So the
/// responses here are assembled byte by byte from the RFC's own rules — including the
/// exclusive-or that XOR-MAPPED-ADDRESS applies — rather than by reusing the code under test.
/// </remarks>
public sealed class StunTests
{
    private const uint Cookie = 0x2112A442;

    private static byte[] Response(byte[] transactionId, params byte[][] attributes)
    {
        var body = attributes.SelectMany(a => a).ToArray();
        var message = new byte[20 + body.Length];
        BinaryPrimitives.WriteUInt16BigEndian(message, 0x0101); // binding success
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)body.Length);
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4), Cookie);
        transactionId.CopyTo(message, 8);
        body.CopyTo(message, 20);
        return message;
    }

    /// <summary>An address attribute, padded the way STUN pads: to a four-byte boundary.</summary>
    private static byte[] Address(ushort type, IPEndPoint endpoint, byte[]? xorWith = null)
    {
        var raw = endpoint.Address.GetAddressBytes();
        var port = (ushort)endpoint.Port;

        if (xorWith is not null)
        {
            port ^= (ushort)(Cookie >> 16);
            var mask = new byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(mask, Cookie);
            xorWith.CopyTo(mask, 4);
            for (var i = 0; i < raw.Length; i++)
            {
                raw[i] ^= mask[i];
            }
        }

        var value = new byte[4 + raw.Length];
        value[1] = raw.Length == 4 ? (byte)0x01 : (byte)0x02;
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), port);
        raw.CopyTo(value, 4);

        var attribute = new byte[4 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(attribute, type);
        BinaryPrimitives.WriteUInt16BigEndian(attribute.AsSpan(2), (ushort)value.Length);
        value.CopyTo(attribute, 4);
        return attribute;
    }

    private static byte[] Software(string text)
    {
        var value = System.Text.Encoding.UTF8.GetBytes(text);
        var padded = new byte[4 + value.Length + ((4 - (value.Length % 4)) % 4)];
        BinaryPrimitives.WriteUInt16BigEndian(padded, 0x8022);
        BinaryPrimitives.WriteUInt16BigEndian(padded.AsSpan(2), (ushort)value.Length);
        value.CopyTo(padded, 4);
        return padded;
    }

    // -- requests ---------------------------------------------------------------

    [Fact]
    public void A_binding_request_is_a_bare_header_with_the_magic_cookie()
    {
        var transactionId = Stun.NewTransactionId();
        var request = Stun.BuildBindingRequest(transactionId);

        Assert.Equal(20, request.Length);
        Assert.Equal(0x0001, BinaryPrimitives.ReadUInt16BigEndian(request));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2)));
        Assert.Equal(Cookie, BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(4)));
        Assert.Equal(transactionId, request[8..20]);
    }

    [Fact]
    public void Asking_to_be_answered_from_elsewhere_carries_a_change_request()
    {
        var request = Stun.BuildBindingRequest(Stun.NewTransactionId(), Stun.Change.Address | Stun.Change.Port);

        Assert.Equal(28, request.Length);
        Assert.Equal(8, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(2)));
        Assert.Equal(0x0003, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(20)));
        Assert.Equal(4, BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(22)));
        Assert.Equal(0x06u, BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(24)));
    }

    [Fact]
    public void Transaction_ids_are_random_and_the_right_length()
    {
        var a = Stun.NewTransactionId();
        var b = Stun.NewTransactionId();

        Assert.Equal(12, a.Length);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void A_transaction_id_of_the_wrong_length_is_refused_rather_than_padded()
    {
        Assert.Throws<ArgumentException>(() => Stun.BuildBindingRequest(new byte[8]));
    }

    // -- responses --------------------------------------------------------------

    [Fact]
    public void The_mapped_address_is_read_back_through_the_exclusive_or()
    {
        var transactionId = Stun.NewTransactionId();
        var mapped = IPEndPoint.Parse("203.0.113.44:51820");
        var datagram = Response(transactionId, Address(0x0020, mapped, transactionId));

        Assert.True(Stun.TryParse(datagram, out var message));
        Assert.NotNull(message);
        Assert.Equal(StunMessageKind.BindingSuccess, message.Kind);
        Assert.Equal(transactionId, message.TransactionId);
        Assert.Equal(mapped, message.MappedEndpoint);
    }

    [Fact]
    public void An_older_server_sending_a_plain_mapped_address_is_still_understood()
    {
        var transactionId = Stun.NewTransactionId();
        var mapped = IPEndPoint.Parse("198.51.100.9:3478");
        var datagram = Response(transactionId, Address(0x0001, mapped));

        Assert.True(Stun.TryParse(datagram, out var message));
        Assert.Equal(mapped, message!.MappedEndpoint);
    }

    [Fact]
    public void The_exclusive_ored_address_wins_when_a_server_sends_both()
    {
        var transactionId = Stun.NewTransactionId();
        var xored = IPEndPoint.Parse("203.0.113.44:51820");
        var plain = IPEndPoint.Parse("10.0.0.1:1");
        var datagram = Response(transactionId, Address(0x0001, plain), Address(0x0020, xored, transactionId));

        Assert.True(Stun.TryParse(datagram, out var message));

        // A NAT that rewrites addresses it recognises in payloads would have corrupted the
        // plain one, which is the entire reason the exclusive-ored form exists.
        Assert.Equal(xored, message!.MappedEndpoint);
    }

    [Fact]
    public void An_IPv6_mapped_address_is_exclusive_ored_with_the_transaction_id_too()
    {
        var transactionId = Stun.NewTransactionId();
        var mapped = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 40000);
        var datagram = Response(transactionId, Address(0x0020, mapped, transactionId));

        Assert.True(Stun.TryParse(datagram, out var message));
        Assert.Equal(mapped, message!.MappedEndpoint);
    }

    [Fact]
    public void The_servers_second_address_is_read_from_either_name_for_it()
    {
        var transactionId = Stun.NewTransactionId();
        var other = IPEndPoint.Parse("198.51.100.2:3479");

        Assert.True(Stun.TryParse(Response(transactionId, Address(0x802C, other)), out var modern));
        Assert.Equal(other, modern!.OtherAddress);

        // CHANGED-ADDRESS is the same thing under its RFC 3489 name, and plenty of servers
        // still send only that.
        Assert.True(Stun.TryParse(Response(transactionId, Address(0x0005, other)), out var classic));
        Assert.Equal(other, classic!.OtherAddress);
    }

    [Fact]
    public void An_attribute_whose_length_is_not_a_multiple_of_four_does_not_derail_the_rest()
    {
        var transactionId = Stun.NewTransactionId();
        var mapped = IPEndPoint.Parse("203.0.113.44:51820");

        // "coturn" is six bytes, so the attribute carries two bytes of padding that are not
        // counted in its length. Missing that shifts everything after it.
        var datagram = Response(transactionId, Software("coturn"), Address(0x0020, mapped, transactionId));

        Assert.True(Stun.TryParse(datagram, out var message));
        Assert.Equal("coturn", message!.Software);
        Assert.Equal(mapped, message.MappedEndpoint);
    }

    [Fact]
    public void An_error_response_is_reported_as_one_rather_than_as_an_answer()
    {
        var transactionId = Stun.NewTransactionId();
        var value = new byte[] { 0, 0, 4, 20, (byte)'n', (byte)'o' };
        var attribute = new byte[4 + value.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(attribute, 0x0009);
        BinaryPrimitives.WriteUInt16BigEndian(attribute.AsSpan(2), (ushort)value.Length);
        value.CopyTo(attribute, 4);

        var datagram = Response(transactionId, attribute);
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(0), 0x0111); // binding error

        Assert.True(Stun.TryParse(datagram, out var message));
        Assert.Equal(StunMessageKind.BindingError, message!.Kind);
        Assert.Equal(420, message.ErrorCode);
        Assert.Null(message.MappedEndpoint);
    }

    // -- what is not STUN -------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(19)]
    public void A_datagram_too_short_to_be_STUN_is_refused(int length)
    {
        Assert.False(Stun.TryParse(new byte[length], out _));
    }

    [Fact]
    public void A_datagram_without_the_magic_cookie_is_refused()
    {
        var datagram = Response(Stun.NewTransactionId());
        BinaryPrimitives.WriteUInt32BigEndian(datagram.AsSpan(4), 0xDEADBEEF);

        Assert.False(Stun.TryParse(datagram, out _));
    }

    [Fact]
    public void A_game_packet_that_happens_to_be_the_right_size_is_refused()
    {
        // The two most significant bits of a STUN type are zero; anything else on the socket
        // is a game's own traffic and must not be mistaken for an answer.
        var datagram = new byte[64];
        datagram[0] = 0xFF;
        BinaryPrimitives.WriteUInt32BigEndian(datagram.AsSpan(4), Cookie);

        Assert.False(Stun.TryParse(datagram, out _));
    }

    [Fact]
    public void A_length_that_runs_past_the_end_of_the_datagram_is_refused()
    {
        var datagram = Response(Stun.NewTransactionId());
        BinaryPrimitives.WriteUInt16BigEndian(datagram.AsSpan(2), 400);

        Assert.False(Stun.TryParse(datagram, out _));
    }
}
