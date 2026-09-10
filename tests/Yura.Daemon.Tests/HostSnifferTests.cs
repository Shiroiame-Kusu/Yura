using System.Buffers.Binary;
using System.Text;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Tests;

public sealed class HostSnifferTests
{
    /// <summary>Builds a minimal but well-formed TLS 1.2 ClientHello with the given SNI.</summary>
    private static byte[] ClientHello(string host, bool includeSni = true)
    {
        var body = new List<byte>();
        body.AddRange([0x03, 0x03]);                 // client_version
        body.AddRange(new byte[32]);                 // random
        body.Add(0);                                 // session id length
        body.AddRange([0x00, 0x02, 0x13, 0x01]);     // one cipher suite
        body.AddRange([0x01, 0x00]);                 // compression: null

        var extensions = new List<byte>();
        if (includeSni)
        {
            var name = Encoding.ASCII.GetBytes(host);
            var list = new List<byte> { 0 };                                // name type: host_name
            list.AddRange(BigEndian16(name.Length));
            list.AddRange(name);
            var ext = new List<byte>();
            ext.AddRange(BigEndian16(list.Count));
            ext.AddRange(list);
            extensions.AddRange([0x00, 0x00]);                             // extension type server_name
            extensions.AddRange(BigEndian16(ext.Count));
            extensions.AddRange(ext);
        }

        // A second, unrelated extension so the walk has to skip something.
        extensions.AddRange([0x00, 0x17, 0x00, 0x00]);                     // extended_master_secret

        body.AddRange(BigEndian16(extensions.Count));
        body.AddRange(extensions);

        var handshake = new List<byte> { 0x01, 0, (byte)(body.Count >> 8), (byte)body.Count };
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 };
        record.AddRange(BigEndian16(handshake.Count));
        record.AddRange(handshake);
        return record.ToArray();
    }

    private static byte[] BigEndian16(int value)
    {
        var buffer = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)value);
        return buffer;
    }

    [Fact]
    public void Reads_the_server_name_from_a_client_hello()
    {
        Assert.True(HostSniffer.TryParseTlsServerName(ClientHello("cdn.example.com"), out var host, out _));
        Assert.Equal("cdn.example.com", host);
    }

    [Fact]
    public void A_client_hello_without_sni_yields_nothing_and_asks_for_no_more_bytes()
    {
        Assert.False(HostSniffer.TryParseTlsServerName(ClientHello("x", includeSni: false), out var host, out var needMore));
        Assert.Null(host);
        Assert.False(needMore);
    }

    [Fact]
    public void A_partial_client_hello_asks_for_more_bytes()
    {
        var full = ClientHello("cdn.example.com");

        Assert.False(HostSniffer.TryParseTlsServerName(full.AsSpan(0, 20), out _, out var needMore));
        Assert.True(needMore);
    }

    [Fact]
    public void Non_tls_bytes_are_not_mistaken_for_a_client_hello()
    {
        Assert.False(HostSniffer.TryParseTlsServerName("SSH-2.0-OpenSSH_9.6\r\n"u8, out _, out var needMore));
        Assert.False(needMore);
    }

    [Fact]
    public void Reads_the_host_header_from_an_http_request()
    {
        Assert.Equal("example.org", HostSniffer.TryParseHttpHost("GET /path HTTP/1.1\r\nHost: example.org:8080\r\nAccept: */*\r\n\r\n"u8));
        Assert.Equal("2001:db8::1", HostSniffer.TryParseHttpHost("GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"u8));
        Assert.Null(HostSniffer.TryParseHttpHost("YURA-PING"u8));
    }
}
