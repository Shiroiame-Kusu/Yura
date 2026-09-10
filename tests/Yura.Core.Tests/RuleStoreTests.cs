using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// The rule list the two workflows share: ordering, replacement, undo, and the route
/// abstraction that lets a rule point at a proxy or a chain interchangeably.
/// </summary>
public sealed class RuleStoreTests
{
    private static readonly Guid ProxyA = Guid.Parse("aaaaaaaa-0000-4000-8000-00000000000a");
    private static readonly Guid ProxyB = Guid.Parse("aaaaaaaa-0000-4000-8000-00000000000b");
    private static readonly Guid ChainId = Guid.Parse("cccccccc-0000-4000-8000-00000000000c");

    private static RuleStore Populated()
    {
        var store = new RuleStore();
        store.Proxies.Add(new ProxyEndpoint
        {
            Id = ProxyA, Name = "Home server", Protocol = ProxyProtocol.Socks5, Host = "127.0.0.1", Port = 1080,
        });
        store.Proxies.Add(new ProxyEndpoint
        {
            Id = ProxyB, Name = "Corporate HTTP", Protocol = ProxyProtocol.Http, Host = "proxy.example.com", Port = 8080,
        });
        store.Chains.Add(new ProxyChain { Id = ChainId, Name = "A then B", Hops = [ProxyA, ProxyB] });
        return store;
    }

    private static ProcessSnapshot Process(int pid = 100, string? exe = "/usr/bin/curl", ulong start = 500) => new()
    {
        Identity = new ProcessIdentity { Pid = pid, StartTicks = start, Uid = 1000, BootId = "b" },
        Name = "curl",
        ExecutablePath = exe,
        ExecutablePathState = ExecutablePathState.Resolved,
        ParentPid = 1,
        UserName = "hakuu",
    };

    private static RoutingRule Rule(int order, string name, RuleAction action, RuleOrigin origin = RuleOrigin.Manual) => new()
    {
        Id = Guid.NewGuid(),
        Order = order,
        Name = name,
        Origin = origin,
        Lifetime = RuleLifetime.Persistent,
        Process = new ProcessSelector { Kind = ProcessSelectorKind.ProcessName, ProcessName = name },
        Action = action,
        CreatedAtUtc = DateTimeOffset.UnixEpoch.AddSeconds(order),
    };

    [Fact]
    public void Routes_offer_proxies_and_chains_together()
    {
        var store = Populated();

        Assert.Equal(3, store.Routes.Count);
        var chain = Assert.Single(store.Routes, r => r.IsChain);
        Assert.Equal("A then B", chain.Name);
        // A chain's detail names its hops in order, because that order is its whole meaning.
        Assert.Equal("Home server → Corporate HTTP", chain.Detail);
        Assert.Equal(CapabilityState.Unsupported, chain.UdpSupport);
    }

    [Fact]
    public void A_route_becomes_the_matching_action()
    {
        var store = Populated();

        Assert.Equal(new RuleAction.Proxy(ProxyA), store.FindRoute(ProxyA)!.ToAction());
        Assert.Equal(new RuleAction.Chain(ChainId), store.FindRoute(ChainId)!.ToAction());
    }

    [Fact]
    public void Removing_a_proxy_removes_its_route_and_shows_the_chain_that_lost_a_hop()
    {
        var store = Populated();
        var unaffected = store.Routes.First(r => r.Id == ProxyA);

        store.Proxies.Remove(store.Proxies.First(p => p.Id == ProxyB));

        Assert.DoesNotContain(store.Routes, r => r.Id == ProxyB);
        // The chain stays in the list, because a rule may still point at it, but it now says
        // that one hop is gone rather than quietly dropping it.
        Assert.Equal("Home server → ?", store.Routes.First(r => r.Id == ChainId).Detail);
        // Routes that did not change keep their instance, so a selection is not lost.
        Assert.Same(unaffected, store.Routes.First(r => r.Id == ProxyA));
    }

    [Fact]
    public void Origins_get_their_own_bands_so_precedence_is_predictable()
    {
        var store = Populated();

        // A process selection the user just made must not be overridden by a game profile.
        Assert.True(store.NextOrder(RuleOrigin.ProcessSelection) < store.NextOrder(RuleOrigin.GameProfile));
        Assert.True(store.NextOrder(RuleOrigin.GameProfile) < store.NextOrder(RuleOrigin.Manual));
    }

    [Fact]
    public void Moving_a_rule_earlier_actually_reorders_evaluation()
    {
        var store = Populated();
        var first = Rule(500, "first", RuleAction.Direct.Instance);
        var second = Rule(501, "second", RuleAction.Block.Instance);
        store.Add(first);
        store.Add(second);

        var changed = store.Move(second.Id, earlier: true);

        Assert.Equal(2, changed.Count);
        Assert.Equal(second.Id, store.Rules[0].Id);
        Assert.Equal(first.Id, store.Rules[1].Id);
        // Both changed rules must be reapplied, so neither may still look confirmed.
        Assert.All(changed, r => Assert.Null(r.AppliedAtUtc));
    }

    [Fact]
    public void Moving_past_the_end_of_the_list_does_nothing()
    {
        var store = Populated();
        var only = Rule(500, "only", RuleAction.Direct.Instance);
        store.Add(only);

        Assert.Empty(store.Move(only.Id, earlier: true));
        Assert.Empty(store.Move(only.Id, earlier: false));
    }

    [Fact]
    public void A_new_selection_replaces_the_previous_one_for_the_same_subject()
    {
        var store = Populated();
        var process = Process();

        var direct = store.BuildRule(process, RuleScopeChoice.Instance, RuleAction.Direct.Instance, includeChildren: false);
        store.Add(direct);
        var proxied = store.BuildRule(process, RuleScopeChoice.Instance, new RuleAction.Proxy(ProxyA), includeChildren: false);
        store.Add(proxied);

        // Two competing overrides on one process would make the effective policy emergent.
        var kept = Assert.Single(store.Rules);
        Assert.Equal(proxied.Id, kept.Id);
    }

    [Fact]
    public void Two_rules_on_one_process_with_different_destinations_both_survive()
    {
        var store = Populated();
        var process = Process();

        store.Add(store.BuildRule(process, RuleScopeChoice.Instance, new RuleAction.Proxy(ProxyA), false));
        store.Add(store.BuildRule(process, RuleScopeChoice.Instance, RuleAction.Block.Instance, false,
            new DestinationSelector { Ports = [new Yura.Core.Net.PortRange(25, 25)] }));

        // Replacing one with the other would throw away a constraint the user asked for.
        Assert.Equal(2, store.Rules.Count);
    }

    [Fact]
    public void Undo_puts_back_what_was_replaced()
    {
        var store = Populated();
        var process = Process();
        var direct = store.BuildRule(process, RuleScopeChoice.Instance, RuleAction.Direct.Instance, false);
        store.Add(direct);
        var proxied = store.BuildRule(process, RuleScopeChoice.Instance, new RuleAction.Proxy(ProxyA), false);
        store.Add(proxied);

        var undo = store.Undo();

        Assert.NotNull(undo);
        Assert.Equal(proxied.Id, undo.Current!.Id);
        Assert.Equal(direct.Id, undo.Previous!.Id);
        Assert.Equal(direct.Id, Assert.Single(store.Rules).Id);
        // Only one step: undoing again must not resurrect anything.
        Assert.Null(store.Undo());
    }

    [Fact]
    public void Undo_of_a_removal_restores_the_rule_unapplied()
    {
        var store = Populated();
        var rule = Rule(500, "curl", new RuleAction.Proxy(ProxyA));
        store.Add(rule);
        store.MarkApplied(rule.Id, DateTimeOffset.UtcNow);
        store.Remove(rule.Id);

        store.Undo();

        var restored = Assert.Single(store.Rules);
        Assert.Equal(rule.Id, restored.Id);
        // It is not live again until the daemon says so.
        Assert.Null(restored.AppliedAtUtc);
    }

    [Fact]
    public void Only_a_daemon_reply_makes_a_rule_active()
    {
        var store = Populated();
        var rule = Rule(500, "curl", new RuleAction.Proxy(ProxyA));
        store.Add(rule);

        Assert.Equal(PolicyKind.Pending, store.DescribePolicy(Process(exe: null) with
        {
            Name = "curl",
        }).Kind);

        store.MarkApplied(rule.Id, DateTimeOffset.UtcNow);
        var (kind, detail) = store.DescribePolicy(Process(exe: null) with { Name = "curl" });
        Assert.Equal(PolicyKind.Proxied, kind);
        Assert.Equal("Home server", detail);
    }

    [Fact]
    public void An_instance_rule_expires_with_its_process()
    {
        var store = Populated();
        var process = Process();
        store.Add(store.BuildRule(process, RuleScopeChoice.Instance, new RuleAction.Proxy(ProxyA), false));

        store.ExpireInstanceRulesFor(ProcessRowViewModel.MakeKey(process.Identity));

        Assert.Empty(store.Rules);
    }

    [Fact]
    public void A_tree_rule_carries_existing_descendants_and_a_plain_one_does_not()
    {
        var store = Populated();
        var process = Process();

        var tree = store.BuildRule(process, RuleScopeChoice.Tree, new RuleAction.Proxy(ProxyA), includeChildren: false);
        var instance = store.BuildRule(process, RuleScopeChoice.Instance, new RuleAction.Proxy(ProxyA), includeChildren: false);
        var withChildren = store.BuildRule(process, RuleScopeChoice.Instance, new RuleAction.Proxy(ProxyA), includeChildren: true);

        Assert.Equal(DescendantPolicy.IncludeExistingAndFuture, tree.Process.Descendants);
        Assert.Equal(DescendantPolicy.Exclude, instance.Process.Descendants);
        Assert.Equal(DescendantPolicy.IncludeFuture, withChildren.Process.Descendants);
    }

    [Fact]
    public void An_executable_rule_is_persistent_and_an_instance_rule_is_not()
    {
        var store = Populated();
        var process = Process();

        Assert.Equal(RuleLifetime.Persistent,
            store.BuildRule(process, RuleScopeChoice.Executable, RuleAction.Direct.Instance, false).Lifetime);
        Assert.Equal(RuleLifetime.Instance,
            store.BuildRule(process, RuleScopeChoice.Instance, RuleAction.Direct.Instance, false).Lifetime);
    }

    [Fact]
    public void A_wine_process_carries_its_target_into_the_rule()
    {
        var store = Populated();
        var wine = Process(exe: "/usr/lib/wine/wine64-preloader") with
        {
            Wine = new WineContext { TargetExecutable = "Z:\\games\\alpha\\alpha.exe", Prefix = "/home/hakuu/.wine" },
        };

        var rule = store.BuildRule(wine, RuleScopeChoice.Executable, new RuleAction.Proxy(ProxyA), false);

        // Without this, a rule on a shared runtime binary would capture every other game.
        Assert.Equal("Z:\\games\\alpha\\alpha.exe", rule.Process.WineTargetExecutable);
        Assert.Equal("/home/hakuu/.wine", rule.Process.WinePrefix);
    }

    [Fact]
    public void Rules_covering_a_process_come_back_in_evaluation_order()
    {
        var store = Populated();
        var process = Process() with { Name = "curl" };
        store.Add(Rule(500, "curl", new RuleAction.Proxy(ProxyA)));
        store.Add(Rule(300, "curl", new RuleAction.Proxy(ProxyB), RuleOrigin.GameProfile));

        var covering = store.RulesFor(process);

        Assert.Equal(2, covering.Count);
        Assert.Equal(300, covering[0].Order);
    }
}
