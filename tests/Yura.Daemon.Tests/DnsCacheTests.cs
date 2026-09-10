using System.Buffers.Binary;
using System.Net;
using System.Text;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Tests;

public sealed class DnsCacheTests
{
    /// <summary>A response with the question name compressed in the answer, as real resolvers emit.</summary>
    private static byte[] Response(string name, uint ttl, params IPAddress[] addresses)
    {
        var message = new List<byte>();
        message.AddRange([0x12, 0x34, 0x81, 0x80]);              // id, flags: response, RD, RA
        message.AddRange(BigEndian16(1));                        // qdcount
        message.AddRange(BigEndian16(addresses.Length));         // ancount
        message.AddRange(BigEndian16(0));
        message.AddRange(BigEndian16(0));

        foreach (var label in name.Split('.'))
        {
            message.Add((byte)label.Length);
            message.AddRange(Encoding.ASCII.GetBytes(label));
        }

        message.Add(0);
        message.AddRange([0x00, 0x01, 0x00, 0x01]);              // qtype A, qclass IN

        foreach (var address in addresses)
        {
            message.AddRange([0xC0, 0x0C]);                      // pointer to the question name
            var bytes = address.GetAddressBytes();
            message.AddRange(BigEndian16(bytes.Length == 4 ? 1 : 28));
            message.AddRange(BigEndian16(1));
            var ttlBytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(ttlBytes, ttl);
            message.AddRange(ttlBytes);
            message.AddRange(BigEndian16(bytes.Length));
            message.AddRange(bytes);
        }

        return message.ToArray();
    }

    private static byte[] BigEndian16(int value)
    {
        var buffer = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)value);
        return buffer;
    }

    [Fact]
    public void Learns_every_address_in_an_answer_under_the_queried_name()
    {
        var cache = new DnsCache();

        var learned = cache.Learn(Response("api.example.com", 300,
            IPAddress.Parse("203.0.113.10"), IPAddress.Parse("203.0.113.11"), IPAddress.Parse("2001:db8::10")));

        Assert.Equal(3, learned);
        Assert.Equal("api.example.com", cache.Lookup(IPAddress.Parse("203.0.113.11")));
        Assert.Equal("api.example.com", cache.Lookup(IPAddress.Parse("2001:db8::10")));
        Assert.Null(cache.Lookup(IPAddress.Parse("203.0.113.12")));
    }

    [Fact]
    public void A_query_teaches_nothing()
    {
        var cache = new DnsCache();
        var query = Response("api.example.com", 300, IPAddress.Parse("203.0.113.10"));
        query[2] = 0x01; // clear QR: this is a question

        Assert.Equal(0, cache.Learn(query));
    }

    [Fact]
    public void Garbage_is_ignored_rather_than_thrown()
    {
        var cache = new DnsCache();

        Assert.Equal(0, cache.Learn([0x81, 0x80]));
        Assert.Equal(0, cache.Learn(new byte[] { 0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C }));
    }
}
