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
/// guards, and refusing to install what the kernel cannot express.
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

    private static RuleSlot Slot(int index, RoutingRule rule, SlotDisposition disposition) =>
        new() { Index = index, Rule = rule, Disposition = disposition };

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
    public void A_proxy_slot_marks_accepts_and_gets_a_tproxy_rule_for_both_transports()
    {
        var slot = Slot(7, Rule("r", 0, new RuleAction.Proxy(ProxyA)), SlotDisposition.Proxy);

        var text = NftablesManager.Build([slot], []);

        Assert.Contains("socket cgroupv2 level 2 \"yura/s007\" meta mark set 0x7107 counter accept", text);
        Assert.Contains("meta mark 0x7107 meta l4proto tcp tproxy ip to :17807 counter accept", text);
        Assert.Contains("meta mark 0x7107 meta l4proto udp tproxy ip to :17807 counter accept", text);
    }

    [Fact]
    public void A_block_slot_resets_tcp_and_rejects_the_rest()
    {
        var slot = Slot(2, Rule("b", 0, RuleAction.Block.Instance), SlotDisposition.Block);

        var text = NftablesManager.Build([slot], []);

        Assert.Contains("socket cgroupv2 level 2 \"yura/s002\" meta l4proto tcp counter reject with tcp reset", text);
        Assert.Contains("socket cgroupv2 level 2 \"yura/s002\" counter reject", text);
        Assert.DoesNotContain("tproxy", text.Split("chain capture")[1]);
    }

    [Fact]
    public void A_direct_slot_accepts_without_marking()
    {
        var slot = Slot(3, Rule("d", 0, RuleAction.Direct.Instance), SlotDisposition.Direct);

        var text = NftablesManager.Build([slot], []);
        var classify = text.Split("chain capture")[0];

        Assert.Contains("socket cgroupv2 level 2 \"yura/s003\" counter accept", classify);
        Assert.DoesNotContain("meta mark set", classify);
    }

    [Fact]
    public void Slots_are_emitted_in_the_order_given_so_first_match_semantics_hold()
    {
        var first = Slot(5, Rule("first", 0, RuleAction.Direct.Instance), SlotDisposition.Direct);
        var second = Slot(1, Rule("second", 1, new RuleAction.Proxy(ProxyA)), SlotDisposition.Proxy);

        var text = NftablesManager.Build([first, second], []);

        Assert.True(text.IndexOf("yura/s005", StringComparison.Ordinal) < text.IndexOf("yura/s001", StringComparison.Ordinal),
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

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Proxy)], []);

        Assert.Contains("meta l4proto tcp ip daddr { 203.0.113.0/24, 198.51.100.7 } th dport { 443, 27000-27100 } socket cgroupv2", text);
    }

    [Fact]
    public void A_host_name_rule_is_skipped_and_reported_rather_than_over_capturing()
    {
        var rule = Rule("host", 0, new RuleAction.Proxy(ProxyA), destination: new DestinationSelector
        {
            Hosts = [new HostPattern(HostMatchKind.Suffix, "example.com")],
        });
        var skipped = new List<string>();

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Proxy)], [], skipped);

        Assert.Single(skipped);
        Assert.Contains("host-name", skipped[0]);
        Assert.DoesNotContain("meta mark set", text);
    }

    [Fact]
    public void A_rule_with_no_process_and_no_destination_is_refused()
    {
        var rule = Rule("everything", 0, new RuleAction.Proxy(ProxyA), process: ProcessSelector.Any);
        var skipped = new List<string>();

        var text = NftablesManager.Build([Slot(1, rule, SlotDisposition.Proxy)], [], skipped);

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

        var text = NftablesManager.Build([Slot(4, rule, SlotDisposition.Proxy)], []);

        Assert.Contains("th dport { 25 } meta mark set 0x7104 counter accept", text);
        Assert.DoesNotContain("cgroupv2", text);
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
}
