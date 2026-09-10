using System.Net;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// Covers the rule-system half of the mandatory acceptance tests: instance isolation (2),
/// Direct and Block (6), precedence between manual rules and game profiles (9), and the
/// Wine/Proton isolation requirement (10).
/// </summary>
public sealed class RuleEvaluatorTests
{
    private static readonly Guid ProxyA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid ProxyB = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private const string Boot = "8f14e45f-ceea-467a-9575-1cd0a4f1e2a0";

    private static ProcessIdentity Identity(int pid, ulong start = 1000, uint uid = 1000) =>
        new() { Pid = pid, StartTicks = start, Uid = uid, BootId = Boot };

    private static ProcessSnapshot Process(
        int pid,
        ulong start = 1000,
        string name = "curl",
        string? exe = "/usr/bin/curl",
        uint uid = 1000,
        WineContext? wine = null) =>
        new()
        {
            Identity = Identity(pid, start, uid),
            Name = name,
            ExecutablePath = exe,
            ExecutablePathState = exe is null ? ExecutablePathState.None : ExecutablePathState.Resolved,
            ParentPid = 1,
            UserName = "hakuu",
            Wine = wine,
        };

    private static RoutingRule Rule(
        int order,
        RuleAction action,
        ProcessSelector? process = null,
        DestinationSelector? destination = null,
        RuleOrigin origin = RuleOrigin.Manual,
        RuleLifetime lifetime = RuleLifetime.Persistent,
        string? name = null) =>
        new()
        {
            Id = Guid.NewGuid(),
            Order = order,
            Name = name ?? $"rule-{order}",
            Origin = origin,
            Lifetime = lifetime,
            Process = process ?? ProcessSelector.Any,
            Destination = destination ?? DestinationSelector.Any,
            Action = action,
            CreatedAtUtc = DateTimeOffset.UnixEpoch.AddSeconds(order),
        };

    private static RoutingRequest Request(
        ProcessSnapshot? process,
        string address = "203.0.113.9",
        ushort port = 443,
        TransportProtocol protocol = TransportProtocol.Tcp,
        string? host = null) =>
        new()
        {
            Process = process,
            DestinationAddress = IPAddress.Parse(address),
            DestinationPort = port,
            Protocol = protocol,
            DestinationHost = host,
        };

    // -- defaults ------------------------------------------------------------

    [Fact]
    public void Unmatched_traffic_defaults_to_direct()
    {
        var decision = RuleEvaluator.Evaluate([], Request(Process(100)));

        Assert.Equal(RuleAction.Direct.Instance, decision.Action);
        Assert.True(decision.IsDefault);
        Assert.Contains("defaults to Direct", decision.Explanation, StringComparison.Ordinal);
    }

    // -- acceptance test 2: instance isolation --------------------------------

    [Fact]
    public void An_instance_rule_does_not_affect_another_instance_of_the_same_executable()
    {
        var selected = Process(pid: 100, start: 5000);
        var other = Process(pid: 101, start: 5001);

        var rules = RuleEvaluator.Sort(
        [
            Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = selected.Identity,
            }),
        ]);

        Assert.Equal(new RuleAction.Proxy(ProxyA), RuleEvaluator.Evaluate(rules, Request(selected)).Action);

        // Same binary, same user, same everything except which instance it is.
        var otherDecision = RuleEvaluator.Evaluate(rules, Request(other));
        Assert.Equal(RuleAction.Direct.Instance, otherDecision.Action);
        Assert.True(otherDecision.IsDefault);
    }

    [Fact]
    public void An_instance_rule_never_widens_to_the_executable()
    {
        var selected = Process(pid: 100, start: 5000);
        var rules = RuleEvaluator.Sort(
        [
            Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = selected.Identity,
            }),
        ]);

        // A pid-reusing successor with the same executable path must not inherit the policy.
        var successor = Process(pid: 100, start: 9999);
        Assert.True(RuleEvaluator.Evaluate(rules, Request(successor)).IsDefault);
    }

    // -- acceptance test 5: two processes, two proxies -------------------------

    [Fact]
    public void Two_processes_can_route_through_different_proxies_simultaneously()
    {
        var first = Process(pid: 100, start: 5000);
        var second = Process(pid: 200, start: 6000);

        var rules = RuleEvaluator.Sort(
        [
            Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance, Identity = first.Identity,
            }),
            Rule(1, new RuleAction.Proxy(ProxyB), new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance, Identity = second.Identity,
            }),
        ]);

        Assert.Equal(new RuleAction.Proxy(ProxyA), RuleEvaluator.Evaluate(rules, Request(first)).Action);
        Assert.Equal(new RuleAction.Proxy(ProxyB), RuleEvaluator.Evaluate(rules, Request(second)).Action);
    }

    // -- acceptance test 6: direct and block -----------------------------------

    [Fact]
    public void Direct_and_block_actions_are_honoured_in_order()
    {
        var process = Process(pid: 100);
        var rules = RuleEvaluator.Sort(
        [
            Rule(0, RuleAction.Block.Instance,
                destination: new DestinationSelector { Ports = [new(25, 25)] }),
            Rule(1, RuleAction.Direct.Instance,
                new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/usr/bin/curl" }),
            Rule(2, new RuleAction.Proxy(ProxyA)),
        ]);

        Assert.Equal(RuleAction.Block.Instance, RuleEvaluator.Evaluate(rules, Request(process, port: 25)).Action);
        Assert.Equal(RuleAction.Direct.Instance, RuleEvaluator.Evaluate(rules, Request(process, port: 443)).Action);
        Assert.Equal(new RuleAction.Proxy(ProxyA),
            RuleEvaluator.Evaluate(rules, Request(Process(101, exe: "/usr/bin/wget"), port: 443)).Action);
    }

    // -- acceptance test 9: precedence -----------------------------------------

    [Fact]
    public void A_manual_process_rule_above_a_game_profile_wins_and_says_so()
    {
        var game = Process(pid: 100, name: "game", exe: "/games/game.bin");

        var manual = Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
        {
            Kind = ProcessSelectorKind.Instance, Identity = game.Identity,
        }, origin: RuleOrigin.ProcessSelection, name: "Proxy this instance");

        var profile = Rule(1, new RuleAction.Proxy(ProxyB), new ProcessSelector
        {
            Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/games/game.bin",
        }, origin: RuleOrigin.GameProfile, name: "Game boost");

        var decision = RuleEvaluator.Evaluate(RuleEvaluator.Sort([manual, profile]), Request(game));

        Assert.Equal(new RuleAction.Proxy(ProxyA), decision.Action);
        Assert.Equal(manual.Id, decision.MatchedRule!.Id);
        Assert.Single(decision.ShadowedRules);
        Assert.Equal(profile.Id, decision.ShadowedRules[0].Id);
        Assert.Contains("takes precedence over", decision.Explanation, StringComparison.Ordinal);
        Assert.Contains("Game boost", decision.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void A_game_profile_above_a_manual_rule_wins_instead()
    {
        var game = Process(pid: 100, name: "game", exe: "/games/game.bin");

        var profile = Rule(0, new RuleAction.Proxy(ProxyB), new ProcessSelector
        {
            Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/games/game.bin",
        }, origin: RuleOrigin.GameProfile, name: "Game boost");

        var manual = Rule(1, new RuleAction.Proxy(ProxyA), new ProcessSelector
        {
            Kind = ProcessSelectorKind.Instance, Identity = game.Identity,
        }, origin: RuleOrigin.ProcessSelection, name: "Proxy this instance");

        var decision = RuleEvaluator.Evaluate(RuleEvaluator.Sort([profile, manual]), Request(game));

        Assert.Equal(new RuleAction.Proxy(ProxyB), decision.Action);
        Assert.Equal(profile.Id, decision.MatchedRule!.Id);
    }

    // -- acceptance test 10: Wine / Proton isolation ----------------------------

    [Fact]
    public void A_wine_rule_does_not_capture_a_different_game_on_the_same_runtime()
    {
        const string Runtime = "/usr/lib/wine/wine64-preloader";

        var selected = Process(pid: 100, name: "wine64-preload", exe: Runtime,
            wine: new WineContext { TargetExecutable = "Z:\\games\\alpha\\alpha.exe" });
        var unrelated = Process(pid: 101, name: "wine64-preload", exe: Runtime,
            wine: new WineContext { TargetExecutable = "Z:\\games\\beta\\beta.exe" });

        var rules = RuleEvaluator.Sort(
        [
            Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = Runtime,
                WineTargetExecutable = "Z:\\games\\alpha\\alpha.exe",
            }),
        ]);

        Assert.Equal(new RuleAction.Proxy(ProxyA), RuleEvaluator.Evaluate(rules, Request(selected)).Action);
        Assert.True(RuleEvaluator.Evaluate(rules, Request(unrelated)).IsDefault);
    }

    // -- destination matching ---------------------------------------------------

    [Fact]
    public void A_host_rule_cannot_match_a_connection_with_no_observed_name()
    {
        var rules = RuleEvaluator.Sort(
        [
            Rule(0, new RuleAction.Proxy(ProxyA), destination: new DestinationSelector
            {
                Hosts = [new HostPattern(HostMatchKind.Suffix, "example.com")],
            }),
        ]);

        // Name observed: matches.
        Assert.False(RuleEvaluator.Evaluate(rules, Request(Process(100), host: "cdn.example.com")).IsDefault);

        // No name observed: the constraint is unsatisfiable, so the rule must not match.
        Assert.True(RuleEvaluator.Evaluate(rules, Request(Process(100), host: null)).IsDefault);
    }

    [Fact]
    public void Suffix_patterns_do_not_match_a_neighbouring_domain()
    {
        var pattern = new HostPattern(HostMatchKind.Suffix, "example.com");

        Assert.True(pattern.Matches("example.com"));
        Assert.True(pattern.Matches("cdn.example.com"));
        Assert.False(pattern.Matches("notexample.com"));
        Assert.False(pattern.Matches("example.com.evil.net"));
    }

    [Fact]
    public void Protocol_and_port_ranges_are_respected()
    {
        var rules = RuleEvaluator.Sort(
        [
            Rule(0, RuleAction.Block.Instance, destination: new DestinationSelector
            {
                Ports = [new PortRange(27015, 27050)],
                Protocol = TransportFilter.Udp,
            }),
        ]);

        Assert.Equal(RuleAction.Block.Instance,
            RuleEvaluator.Evaluate(rules, Request(Process(100), port: 27030, protocol: TransportProtocol.Udp)).Action);

        // Right port, wrong protocol.
        Assert.True(RuleEvaluator
            .Evaluate(rules, Request(Process(100), port: 27030, protocol: TransportProtocol.Tcp)).IsDefault);

        // Right protocol, outside the range.
        Assert.True(RuleEvaluator
            .Evaluate(rules, Request(Process(100), port: 27060, protocol: TransportProtocol.Udp)).IsDefault);
    }

    [Fact]
    public void A_process_that_could_not_be_attributed_only_matches_process_agnostic_rules()
    {
        var rules = RuleEvaluator.Sort(
        [
            Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/usr/bin/curl",
            }),
            Rule(1, RuleAction.Block.Instance, destination: new DestinationSelector { Ports = [new(443, 443)] }),
        ]);

        var decision = RuleEvaluator.Evaluate(rules, Request(process: null, port: 443));
        Assert.Equal(RuleAction.Block.Instance, decision.Action);
    }

    // -- classifier authority ----------------------------------------------------

    [Fact]
    public void Tree_membership_comes_from_the_classifier_not_from_a_pid_walk()
    {
        var parentIdentity = Identity(100, 5000);
        var rule = Rule(0, new RuleAction.Proxy(ProxyA), new ProcessSelector
        {
            Kind = ProcessSelectorKind.Instance,
            Identity = parentIdentity,
            Descendants = DescendantPolicy.IncludeFuture,
        });

        // A child: different pid, so it can never satisfy the instance selector on its own.
        var child = Process(pid: 512, start: 7000);

        var withoutClassifier = RuleEvaluator.Evaluate([rule], Request(child));
        Assert.True(withoutClassifier.IsDefault);

        // The kernel says this flow belongs to the rule's cgroup; that answer is authoritative.
        var withClassifier = RuleEvaluator.Evaluate([rule], Request(child) with
        {
            ClassifierMatchedRuleIds = new HashSet<Guid> { rule.Id },
        });
        Assert.Equal(new RuleAction.Proxy(ProxyA), withClassifier.Action);
    }

    [Fact]
    public void Disabled_rules_are_skipped_entirely()
    {
        var rule = Rule(0, RuleAction.Block.Instance) with { Enabled = false };
        Assert.True(RuleEvaluator.Evaluate([rule], Request(Process(100))).IsDefault);
    }

    [Fact]
    public void Ordering_is_deterministic_when_orders_collide()
    {
        var a = Rule(0, new RuleAction.Proxy(ProxyA), name: "a");
        var b = Rule(0, new RuleAction.Proxy(ProxyB), name: "b") with
        {
            CreatedAtUtc = a.CreatedAtUtc.AddSeconds(1),
        };

        // Same Order value; the earlier CreatedAtUtc must win, both times.
        Assert.Equal(a.Id, RuleEvaluator.Evaluate(RuleEvaluator.Sort([a, b]), Request(Process(1))).MatchedRule!.Id);
        Assert.Equal(a.Id, RuleEvaluator.Evaluate(RuleEvaluator.Sort([b, a]), Request(Process(1))).MatchedRule!.Id);
    }
}
