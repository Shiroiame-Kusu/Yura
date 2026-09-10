using Yura.Core.Proxies;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Tests;

/// <summary>
/// The parts of the tunnel manager that need no root: what goes to <c>wg setconf</c>, what
/// is refused before the kernel sees it, and how <c>wg show</c> is read back.
/// </summary>
public sealed class WireGuardManagerTests
{
    private const string PrivateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    private const string PeerKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    private const string Psk = "FpCyhws9cxwWoV4xbtR2+vNmdyUAgIkfBOozrfp2HbE=";

    private static ProxyEndpoint Exit(WireGuardSettings? settings = null) => new()
    {
        Id = Guid.Parse("eeee0000-0000-4000-8000-00000000000e"),
        Name = "exit",
        Protocol = ProxyProtocol.WireGuard,
        Host = "vpn.example.net",
        Port = 51820,
        WireGuard = settings ?? new WireGuardSettings
        {
            PeerPublicKey = PeerKey,
            Addresses = ["10.8.0.7/32"],
            DnsServers = ["10.8.0.1"],
            PersistentKeepalive = 25,
        },
    };

    [Fact]
    public void The_configuration_handed_to_wg_carries_the_bypass_mark_and_the_peer()
    {
        var text = WireGuardManager.RenderConfig(Exit(), new ProxySecrets(PrivateKey, Psk));

        Assert.Contains($"PrivateKey = {PrivateKey}\n", text);
        Assert.Contains($"FwMark = 0x{PolicyRouting.BypassMark:x}\n", text);
        Assert.Contains($"PublicKey = {PeerKey}\n", text);
        Assert.Contains($"PresharedKey = {Psk}\n", text);
        Assert.Contains("AllowedIPs = 0.0.0.0/0, ::/0\n", text);
        Assert.Contains("Endpoint = vpn.example.net:51820\n", text);
        Assert.Contains("PersistentKeepalive = 25\n", text);
        // Addresses, DNS and MTU are interface properties set with ip, not wg.
        Assert.DoesNotContain("Address", text);
        Assert.DoesNotContain("DNS", text);
    }

    [Fact]
    public void No_preshared_key_means_no_preshared_line()
    {
        var text = WireGuardManager.RenderConfig(Exit(), new ProxySecrets(PrivateKey));

        Assert.DoesNotContain("PresharedKey", text);
    }

    [Fact]
    public void The_fingerprint_changes_with_the_key_and_reveals_none_of_it()
    {
        var one = WireGuardManager.Fingerprint(Exit(), new ProxySecrets(PrivateKey, Psk));
        var same = WireGuardManager.Fingerprint(Exit(), new ProxySecrets(PrivateKey, Psk));
        var otherKey = WireGuardManager.Fingerprint(Exit(), new ProxySecrets(Psk, Psk));
        var otherAddress = WireGuardManager.Fingerprint(
            Exit(new WireGuardSettings { PeerPublicKey = PeerKey, Addresses = ["10.8.0.8/32"] }), new ProxySecrets(PrivateKey, Psk));

        Assert.Equal(one, same);
        Assert.NotEqual(one, otherKey);
        Assert.NotEqual(one, otherAddress);
        Assert.DoesNotContain(PrivateKey[..12], one);
        Assert.Equal(64, one.Length);
    }

    [Theory]
    [InlineData(null, "No private key")]
    [InlineData("garbage", "not a valid WireGuard key")]
    public void A_bad_private_key_is_refused_in_words_before_wg_sees_it(string? key, string expected)
    {
        var reason = WireGuardManager.Validate(Exit(), new ProxySecrets(key));

        Assert.NotNull(reason);
        Assert.Contains(expected, reason);
    }

    [Fact]
    public void Every_other_field_is_checked_too()
    {
        Assert.Contains("peer's public key", WireGuardManager.Validate(
            Exit(new WireGuardSettings { PeerPublicKey = "nope", Addresses = ["10.0.0.1/32"] }), new ProxySecrets(PrivateKey))!);
        Assert.Contains("No tunnel address", WireGuardManager.Validate(
            Exit(new WireGuardSettings { PeerPublicKey = PeerKey }), new ProxySecrets(PrivateKey))!);
        Assert.Contains("DNS server", WireGuardManager.Validate(
            Exit(new WireGuardSettings { PeerPublicKey = PeerKey, Addresses = ["10.0.0.1/32"], DnsServers = ["dns.local"] }), new ProxySecrets(PrivateKey))!);
        Assert.Contains("AllowedIPs", WireGuardManager.Validate(
            Exit(new WireGuardSettings { PeerPublicKey = PeerKey, Addresses = ["10.0.0.1/32"], AllowedIps = ["everything"] }), new ProxySecrets(PrivateKey))!);
        Assert.Contains("MTU", WireGuardManager.Validate(
            Exit(new WireGuardSettings { PeerPublicKey = PeerKey, Addresses = ["10.0.0.1/32"], Mtu = 100 }), new ProxySecrets(PrivateKey))!);
        Assert.Contains("preshared", WireGuardManager.Validate(Exit(), new ProxySecrets(PrivateKey, "short"))!);
        Assert.Null(WireGuardManager.Validate(Exit(), new ProxySecrets(PrivateKey, Psk)));
    }

    [Fact]
    public void Reads_wg_show_output_for_one_peer()
    {
        Assert.Equal(1789032264, WireGuardManager.ParseHandshakeEpoch($"{PeerKey}\t1789032264\n"));
        Assert.Equal(0, WireGuardManager.ParseHandshakeEpoch($"{PeerKey}\t0\n"));
        Assert.Equal(0, WireGuardManager.ParseHandshakeEpoch(string.Empty));
        Assert.Equal((10108L, 10868L), WireGuardManager.ParseTransfer($"{PeerKey}\t10108\t10868\n"));
        Assert.Equal((0L, 0L), WireGuardManager.ParseTransfer("garbage"));
    }

    [Fact]
    public void Tunnels_get_their_own_mark_table_and_interface()
    {
        var tunnel = new WireGuardTunnel
        {
            ProxyId = Guid.NewGuid(), Name = "exit", Index = 3, Endpoint = "e", Fingerprint = "f",
            Ipv4 = System.Net.IPAddress.Parse("10.8.0.7"), Dns = [System.Net.IPAddress.Parse("10.8.0.1")],
        };

        Assert.Equal("yura-wg3", tunnel.Interface);
        Assert.Equal(PolicyRouting.TunnelMarkBase + 3, tunnel.Mark);
        Assert.Equal(PolicyRouting.TunnelTableBase + 3, tunnel.Table);
        Assert.Equal((PolicyRouting.TunnelMarkBase + 3) & PolicyRouting.TunnelMarkMask, PolicyRouting.TunnelMarkBase);
        Assert.NotEqual(PolicyRouting.MarkBase, tunnel.Mark & PolicyRouting.MarkMask); // never mistaken for a slot mark
        Assert.Null(tunnel.SourceFor(System.Net.Sockets.AddressFamily.InterNetworkV6));
        Assert.Equal("10.8.0.1", tunnel.DnsFor(System.Net.Sockets.AddressFamily.InterNetwork)!.ToString());
    }

    [Fact]
    public void A_dns_query_is_well_formed()
    {
        var query = DnsMessage.BuildQuery(0x1234, "example.com");

        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);
        Assert.Equal(0x01, query[2]); // RD
        Assert.Equal(1, query[5]);    // QDCOUNT
        Assert.Equal(7, query[12]);   // "example"
        Assert.Equal((byte)'e', query[13]);
        Assert.Equal(3, query[20]);   // "com"
        Assert.Equal(0, query[24]);   // root
        Assert.Equal([0, 1, 0, 1], query[25..29]); // A, IN
    }
}
