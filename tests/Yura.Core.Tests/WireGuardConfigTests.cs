using Yura.Core.Proxies;

namespace Yura.Core.Tests;

/// <summary>
/// The importer reads what wg-quick reads. These pin the shape of a real file, the parts
/// that must be ignored rather than misread, and the validation the form relies on.
/// </summary>
public sealed class WireGuardConfigTests
{
    private const string PrivateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    private const string PeerKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    private const string Psk = "FpCyhws9cxwWoV4xbtR2+vNmdyUAgIkfBOozrfp2HbE=";

    private const string Sample = $"""
        # A typical provider file.
        [Interface]
        PrivateKey = {PrivateKey}
        Address = 10.8.0.7/32, fd42:42:42::7/128
        DNS = 10.8.0.1, example.internal
        MTU = 1380
        PostUp = iptables -A FORWARD -i %i -j ACCEPT   # never run
        Table = off

        [Peer]
        PublicKey = {PeerKey}
        PresharedKey = {Psk}
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = vpn.example.net:51820
        PersistentKeepalive = 25

        [Peer]
        PublicKey = {PeerKey}
        Endpoint = 203.0.113.9:51820
        """;

    [Fact]
    public void Reads_every_field_a_wg_quick_file_carries()
    {
        var import = WireGuardConfig.Parse(Sample);

        Assert.True(import.Recognised);
        Assert.Equal(PrivateKey, import.PrivateKey);
        Assert.Equal(PeerKey, import.PeerPublicKey);
        Assert.Equal(Psk, import.PresharedKey);
        Assert.Equal(["10.8.0.7/32", "fd42:42:42::7/128"], import.Addresses);
        Assert.Equal(["10.8.0.1"], import.DnsServers); // The search domain is not a resolver.
        Assert.Equal(["0.0.0.0/0", "::/0"], import.AllowedIps);
        Assert.Equal("vpn.example.net", import.EndpointHost);
        Assert.Equal((ushort)51820, import.EndpointPort);
        Assert.Equal(1380, import.Mtu);
        Assert.Equal(25, import.PersistentKeepalive);
    }

    [Fact]
    public void Says_what_it_ignored_rather_than_silently_dropping_it()
    {
        var import = WireGuardConfig.Parse(Sample);

        Assert.Contains(import.Ignored, i => i.StartsWith("PostUp", StringComparison.Ordinal));
        Assert.Contains(import.Ignored, i => i.StartsWith("Table", StringComparison.Ordinal));
        Assert.Contains(import.Ignored, i => i.Contains("second [Peer]", StringComparison.Ordinal));
    }

    [Fact]
    public void Text_without_sections_is_not_recognised()
    {
        var import = WireGuardConfig.Parse("PrivateKey = abc\nEndpoint = 1.2.3.4:5");

        Assert.False(import.Recognised);
        Assert.Null(import.PrivateKey);
    }

    [Theory]
    [InlineData(PrivateKey, true)]
    [InlineData("  " + PrivateKey + "\n", true)]
    [InlineData("not-a-key", false)]
    [InlineData("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3f", false)] // 30 bytes
    [InlineData("", false)]
    [InlineData(null, false)]
    public void A_key_is_exactly_32_bytes_of_base64(string? key, bool valid) =>
        Assert.Equal(valid, WireGuardConfig.IsValidKey(key));

    [Theory]
    [InlineData("vpn.example.net:51820", "vpn.example.net", 51820)]
    [InlineData("203.0.113.9:1", "203.0.113.9", 1)]
    [InlineData("[2001:db8::1]:51820", "2001:db8::1", 51820)]
    public void Endpoints_are_read_the_way_wireguard_writes_them(string text, string host, int port)
    {
        Assert.True(WireGuardConfig.TryParseEndpoint(text, out var parsedHost, out var parsedPort));
        Assert.Equal(host, parsedHost);
        Assert.Equal(port, parsedPort);
    }

    [Theory]
    [InlineData("vpn.example.net")]
    [InlineData("2001:db8::1:51820")]
    [InlineData("host:0")]
    [InlineData("host:")]
    [InlineData("")]
    public void Endpoints_without_a_usable_port_are_refused(string text) =>
        Assert.False(WireGuardConfig.TryParseEndpoint(text, out _, out _));

    [Fact]
    public void Tunnel_addresses_keep_their_host_part()
    {
        Assert.True(WireGuardConfig.TryParseAddress("10.8.0.7/24", out var address, out var prefix));
        Assert.Equal("10.8.0.7", address.ToString());
        Assert.Equal(24, prefix);

        Assert.True(WireGuardConfig.TryParseAddress("fd00::7", out var v6, out var v6Prefix));
        Assert.Equal(128, v6Prefix);
        Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, v6.AddressFamily);

        Assert.False(WireGuardConfig.TryParseAddress("10.8.0.7/33", out _, out _));
        Assert.False(WireGuardConfig.TryParseAddress("nope", out _, out _));
    }

    private static ProxyEndpoint Endpoint(string name, ProxyProtocol protocol) => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        Protocol = protocol,
        Host = "h",
        Port = 1,
        WireGuard = protocol == ProxyProtocol.WireGuard ? new WireGuardSettings { PeerPublicKey = PeerKey } : null,
    };

    [Fact]
    public void A_wireguard_exit_may_only_start_a_chain()
    {
        var exit = Endpoint("exit", ProxyProtocol.WireGuard);
        var socks = Endpoint("socks", ProxyProtocol.Socks5);

        Assert.Null(ProxyChain.Validate([exit, socks]));
        Assert.Null(ProxyChain.Validate([socks]));
        Assert.Contains("first hop", ProxyChain.Validate([socks, exit])!);
        Assert.NotNull(ProxyChain.Validate([]));
    }

    [Fact]
    public void A_wireguard_exit_carries_udp_by_construction_and_says_so_without_a_probe()
    {
        var exit = Endpoint("exit", ProxyProtocol.WireGuard);

        Assert.Equal(CapabilityState.Supported, exit.UdpSupport);
        Assert.Equal("WireGuard", exit.ProtocolDisplay);
        Assert.True(exit.IsWireGuard);
        Assert.Equal(CapabilityState.Unknown, Endpoint("s", ProxyProtocol.Socks5).UdpSupport);
    }
}
