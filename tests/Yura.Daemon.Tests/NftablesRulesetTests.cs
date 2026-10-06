using System.Net;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Tests;

/// <summary>
/// The ruleset builder is pure, so the exact text the daemon hands to nft can be checked
/// without root. These pin the properties that keep routing correct: order, the loop
/// guards, one match per (rule, group) pair, and refusing to install what the kernel
/// cannot express.
/// </summary>
public sealed class NftablesRulesetTests
{
    private static readonly Guid ProxyA = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000001");

    private static RoutingRule Rule(string name, int order, RuleAction action,
        ProcessSelector? process = null, DestinationSelector? destination = null) =>
        new()
        {
            Id = Guid.NewGuid(),
            Order = order,
            Name = name,
            Origin = RuleOrigin.Manual,
            Lifetime = RuleLifetime.Persistent,
            Process = process ?? new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = new ProcessIdentity { Pid = 100, StartTicks = 1, Uid = 1000, BootId = "b" },
            },
            Destination = destination ?? DestinationSelector.Any,
            Action = action,
            CreatedAtUtc = DateTimeOffset.UnixEpoch,
        };

    private static ProcessGroup Group(int index, params RoutingRule[] rules) =>
        new() { Index = index, RuleIds = rules.Select(r => r.Id).ToHashSet() };

    /// <summary>
    /// The port is the one the kernel handed the listener; 17800 + index here only so the
    /// expectations below stay readable.
    /// </summary>
    private static RuleSlot Slot(int index, RoutingRule rule, SlotDisposition disposition, params ProcessGroup[] groups) =>
        new()
        {
            Index = index,
            Rule = rule,
            Disposition = disposition,
            Groups = groups,
            Port = disposition == SlotDisposition.Capture ? 17800 + index : 0,
        };

    [Fact]
    public void Always_guards_against_its_own_upstream_traffic_and_loopback()
    {
        var text = NftablesManager.Build([], []);

        Assert.Contains($"meta mark 0x{PolicyRouting.BypassMark:x} return", text);
        Assert.Contains("oifname \"lo\" return", text);
        Assert.Contains("type route hook output priority mangle", text);
        Assert.Contains("type filter hook prerouting priority mangle", text);
    }

    [Fact]
    public void Always_lets_the_daemons_tunnel_sockets_through_untouched()
    {
        var text = NftablesManager.Build([], []);

        Assert.Contains($"meta mark & 0x{PolicyRouting.TunnelMarkMask:x} == 0x{PolicyRouting.TunnelMarkBase:x} return", text);
    }

    [Fact]
    public void Never_captures_the_outer_packets_of_a_wireguard_exit()
    {
        var exit = new ProxyEndpoint
        {
            Id = ProxyA, Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "203.0.113.9", Port = 51820,
            WireGuard = new WireGuardSettings { PeerPublicKey = "k", Addresses = ["10.8.0.7/32"] },
        };

        var text = NftablesManager.Build([], [exit]);

        Assert.Contains("ip daddr 203.0.113.9 th dport 51820 return", text);
    }

    [Fact]
    public void Never_captures_traffic_addressed_to_a_configured_proxy()
    {
        var proxy = new ProxyEndpoint
        {
            Id = ProxyA, Name = "A", Protocol = ProxyProtocol.Socks5, Host = "10.0.0.5", Port = 1080,
        };

        var text = NftablesManager.Build([], [proxy]);

        Assert.Contains("ip daddr 10.0.0.5 th dport 1080 return", text);
    }

    [Fact]
    public void A_capture_slot_marks_accepts_and_gets_a_tproxy_rule_for_both_transports()
    {
        var rule = Rule("r", 0, new RuleAction.Proxy(ProxyA));
        var slot = Slot(7, rule, SlotDisposition.Capture, Group(3, rule));

        var text = NftablesManager.Build([slot], []);

        Assert.Contains("socket cgroupv2 level 2 \"yura/g003\" meta mark set 0x7107 counter accept", text);
        Assert.Contains("meta mark 0x7107 meta l4proto tcp tproxy ip to :17807 counter accept", text);
        Assert.Contains("meta mark 0x7107 meta l4proto udp tproxy ip to :17807 counter accept", text);
    }

    [Fact]
    public void A_rule_covering_several_groups_is_emitted_once_per_group()
    {
        var rule = Rule("r", 0, new RuleAction.Proxy(ProxyA));
        var slot = Slot(1, rule, SlotDisposition.Capture, Group(1, rule), Group(2, rule));

        var text = NftablesManager.Build([slot], []);

        Assert.Contains("\"yura/g001\" meta mark set 0x7101", text);
        Assert.Contains("\"yura/g002\" meta mark set 0x7101", text);
    }

    [Fact]
    public void A_process_rule_with_no_running_match_installs_nothing_but_says_so()
    {
        var rule = Rule("idle", 0, new RuleAction.Proxy(ProxyA));
        var slot = Slot(1, rule, SlotDisposition.Capture);

        var text = NftablesManager.Build([slot], []);

        Assert.Contains("no running process matches this rule yet", text);
        Assert.DoesNotContain("meta mark set", text.Split("chain capture")[0]);
    }

    [Fact]
    public void A_block_slot_resets_tcp_and_rejects_the_rest()
    {
        var rule = Rule("b", 0, RuleAction.Block.Instance);
        var slot = Slot(2, rule, SlotDisposition.Block, Group(1, rule));

        var text = NftablesManager.Build([slot], []);

        Assert.Contains("socket cgroupv2 level 2 \"yura/g001\" meta l4proto tcp counter reject with tcp reset", text);
        Assert.Contains("socket cgroupv2 level 2 \"yura/g001\" counter reject", text);
        Assert.DoesNotContain("tproxy", text.Split("chain capture")[1]);
    }

    [Fact]
    public void A_direct_slot_accepts_without_marking()
    {
        var rule = Rule("d", 0, RuleAction.Direct.Instance);
        var slot = Slot(3, rule, SlotDisposition.Direct, Group(1, rule));

        var text = NftablesManager.Build([slot], []);
        var classify = text.Split("chain capture")[0];

        Assert.Contains("socket cgroupv2 level 2 \"yura/g001\" counter accept", classify);
        Assert.DoesNotContain("meta mark set", classify);
    }

    [Fact]
    public void Slots_are_emitted_in_the_order_given_so_first_match_semantics_hold()
    {
        var a = Rule("first", 0, RuleAction.Direct.Instance);
        var b = Rule("second", 1, new RuleAction.Proxy(ProxyA));
        var group = Group(1, a, b);
        var first = Slot(5, a, SlotDisposition.Direct, group);
        var second = Slot(1, b, SlotDisposition.Capture, group);

        var text = NftablesManager.Build([first, second], []);

        Assert.True(text.IndexOf("# s005", StringComparison.Ordinal) < text.IndexOf("# s001", StringComparison.Ordinal),
            "slot order must follow rule order, not slot index");
    }

    [Fact]
    public void Destination_constraints_are_rendered_into_the_match()
    {
        var rule = Rule("dest", 0, new RuleAction.Proxy(ProxyA), destination: new DestinationSelector
        {
            Networks = [IPNetwork.Parse("203.0.113.0/24"), IPNetwork.Parse("198.51.100.7/32")],
            Ports = [new PortRange(443, 443), new PortRange(27000, 27100)],
            Protocol = TransportFilter.Tcp,
        });

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture, Group(1, rule))], []);

        Assert.Contains("meta l4proto tcp ip daddr { 203.0.113.0/24, 198.51.100.7 } th dport { 443, 27000-27100 } socket cgroupv2", text);
    }

    [Fact]
    public void A_captured_flow_is_marked_for_IPv4_only_and_IPv6_is_refused_rather_than_let_out()
    {
        // The leak this pins shut: the mark is what re-routes a packet into the listener, and
        // the rule that does the re-routing is an IPv4 rule. Marking an IPv6 packet changed
        // nothing about where it went, so it left on the ordinary route while Yura reported
        // the rule as being in effect — a silent lie, and for an exit meant to hide an address,
        // a leak of exactly the thing it was hiding.
        var rule = Rule("game", 10, new RuleAction.Proxy(ProxyA));

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture, Group(1, rule))], []);

        Assert.Contains("meta nfproto ipv4", text, StringComparison.Ordinal);
        Assert.Contains("meta nfproto ipv6", text, StringComparison.Ordinal);
        // The mark is only ever set on IPv4.
        foreach (var line in text.Split('\n').Where(l => l.Contains("meta mark set", StringComparison.Ordinal)))
        {
            Assert.Contains("meta nfproto ipv4", line, StringComparison.Ordinal);
        }

        // And IPv6 is refused, with a reset for TCP so the application fails fast and retries
        // over IPv4 instead of waiting out a timeout.
        var ipv6 = text.Split('\n').Where(l => l.Contains("meta nfproto ipv6", StringComparison.Ordinal)).ToList();
        Assert.Contains(ipv6, l => l.Contains("reject with tcp reset", StringComparison.Ordinal));
        Assert.Contains(ipv6, l => l.TrimEnd().EndsWith("counter reject", StringComparison.Ordinal));
    }

    [Fact]
    public void A_capture_rule_scoped_to_IPv4_networks_has_no_IPv6_line_for_nft_to_refuse()
    {
        // 'meta nfproto ipv6' beside 'ip daddr' is a contradiction nft rejects outright
        // ("conflicting network layer protocols"), and one rejected line fails the whole
        // transaction: no proxy rule scoped to an IPv4 network could ever be installed, and
        // every other rule went down with it. No IPv6 packet can match such a rule anyway.
        var rule = Rule("v4 net", 13, new RuleAction.Proxy(ProxyA), destination: new DestinationSelector
        {
            Networks = [IPNetwork.Parse("203.0.113.0/24")],
        });

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture, Group(1, rule))], []);

        var lines = text.Split('\n').Where(l => l.Contains("ip daddr", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(lines);
        Assert.All(lines, l => Assert.DoesNotContain("nfproto ipv6", l, StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("meta nfproto ipv4", StringComparison.Ordinal) &&
                                    l.Contains("meta mark set 0x7101", StringComparison.Ordinal));
    }

    [Fact]
    public void A_capture_rule_that_names_IPv6_destinations_is_refused_with_the_reason()
    {
        // It could only ever have blocked them, so installing it would be a rule that claims
        // to route and does the opposite.
        var rule = Rule("v6 game", 11, new RuleAction.Proxy(ProxyA), destination: new DestinationSelector
        {
            Networks = [IPNetwork.Parse("2001:db8::/32")],
        });

        var skipped = new List<string>();
        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture, Group(1, rule))], [], null, skipped);

        Assert.Contains("IPv6 destinations cannot be captured", Assert.Single(skipped), StringComparison.Ordinal);
        Assert.DoesNotContain("meta mark set 0x7101", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_blocked_rule_still_covers_both_families()
    {
        // Blocking has no capture to do, so there is nothing it cannot express for IPv6.
        var rule = Rule("blocked", 12, RuleAction.Block.Instance);

        var text = NftablesManager.Build([Slot(2, rule, SlotDisposition.Block, Group(1, rule))], []);

        Assert.DoesNotContain("meta nfproto", text, StringComparison.Ordinal);
        Assert.Contains("reject with tcp reset", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_host_name_rule_on_a_process_captures_everything_else_about_it_and_leaves_the_name_to_the_listener()
    {
        var rule = Rule("host", 0, RuleAction.Block.Instance, destination: new DestinationSelector
        {
            Hosts = [new HostPattern(HostMatchKind.Suffix, "example.com")],
            Ports = [new PortRange(443, 443)],
        });
        var skipped = new List<string>();

        // The runtime turns any host rule into a Capture slot regardless of its action.
        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture, Group(1, rule))], [], skipped: skipped);

        Assert.Empty(skipped);
        Assert.Contains("th dport { 443 } socket cgroupv2 level 2 \"yura/g001\" meta mark set 0x7101 counter accept", text);
        Assert.DoesNotContain("example.com", text.Split("chain classify")[1].Split("# s001")[1].Split('\n')[1]);
    }

    [Fact]
    public void A_host_name_rule_without_a_process_selector_is_refused_rather_than_capturing_the_machine()
    {
        var rule = Rule("host", 0, new RuleAction.Proxy(ProxyA), process: ProcessSelector.Any, destination: new DestinationSelector
        {
            Hosts = [new HostPattern(HostMatchKind.Suffix, "example.com")],
        });
        var skipped = new List<string>();

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture)], [], skipped: skipped);

        Assert.Single(skipped);
        Assert.Contains("process selector", skipped[0]);
        Assert.DoesNotContain("meta mark set", text);
    }

    [Fact]
    public void A_rule_with_no_process_and_no_destination_is_refused()
    {
        var rule = Rule("everything", 0, new RuleAction.Proxy(ProxyA), process: ProcessSelector.Any);
        var skipped = new List<string>();

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Capture)], [], skipped: skipped);

        Assert.Single(skipped);
        Assert.Contains("all traffic", skipped[0]);
        Assert.DoesNotContain("meta mark set", text);
    }

    [Fact]
    public void A_destination_only_rule_needs_no_cgroup()
    {
        var rule = Rule("dest-only", 0, new RuleAction.Proxy(ProxyA),
            process: ProcessSelector.Any,
            destination: new DestinationSelector { Ports = [new PortRange(25, 25)] });

        var text = NftablesManager.Build([Slot(4, rule, SlotDisposition.Capture)], []);

        Assert.Contains("th dport { 25 } meta mark set 0x7104 counter accept", text);
        Assert.DoesNotContain("cgroupv2", text);
    }

    [Fact]
    public void Direct_dns_policy_lets_port_53_out_before_the_capture_line_for_proxy_rules_only()
    {
        var proxied = Rule("p", 0, new RuleAction.Proxy(ProxyA));
        var blocked = Rule("b", 1, RuleAction.Block.Instance);
        var group = Group(1, proxied, blocked);
        var slots = new[]
        {
            Slot(1, proxied, SlotDisposition.Capture, group),
            Slot(2, blocked, SlotDisposition.Block, group),
        };

        var text = NftablesManager.Build(slots, [], new DaemonOptions { DnsPolicy = DnsPolicy.Direct });

        var bypass = text.IndexOf("\"yura/g001\" th dport 53 counter accept", StringComparison.Ordinal);
        var capture = text.IndexOf("\"yura/g001\" meta mark set 0x7101", StringComparison.Ordinal);
        Assert.True(bypass >= 0 && bypass < capture, "the DNS bypass must precede the capture line");
        Assert.Equal(1, text.Split("th dport 53").Length - 1);

        var defaultPolicy = NftablesManager.Build(slots, []);
        Assert.DoesNotContain("th dport 53", defaultPolicy);
    }

    [Fact]
    public void A_capture_slot_with_no_listener_is_left_out_rather_than_black_holing_traffic()
    {
        var rule = Rule("r", 0, new RuleAction.Proxy(ProxyA));
        var slot = Slot(1, rule, SlotDisposition.Capture, Group(1, rule)) with { Port = 0 };
        var skipped = new List<string>();

        var text = NftablesManager.Build([slot], [], skipped: skipped);

        Assert.Single(skipped);
        Assert.Contains("no transparent listener", skipped[0]);
        Assert.DoesNotContain("meta mark set", text);
        Assert.DoesNotContain("tproxy", text);
    }

    [Fact]
    public void Slot_marks_stay_inside_the_range_policy_routing_selects()
    {
        for (var index = 1; index <= RuleSlot.MaxSlots; index++)
        {
            var slot = Slot(index, Rule("r", 0, RuleAction.Direct.Instance), SlotDisposition.Direct);
            Assert.Equal(PolicyRouting.MarkBase, slot.Mark & PolicyRouting.MarkMask);
            Assert.NotEqual(PolicyRouting.BypassMark, slot.Mark);
        }
    }

    [Fact]
    public void Groups_with_the_same_rule_set_share_a_key_regardless_of_order()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();

        Assert.Equal(ProcessGroup.KeyFor([a, b]), ProcessGroup.KeyFor([b, a]));
        Assert.NotEqual(ProcessGroup.KeyFor([a]), ProcessGroup.KeyFor([a, b]));
    }
}
