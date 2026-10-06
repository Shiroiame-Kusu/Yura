using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// The process inspector: the panel that turns a selected process into a rule.
/// </summary>
/// <remarks>
/// Every test here pins a fault that shipped. The panel offered three scopes and a route and
/// then installed something else, and the rule it replaced was dropped from the list while
/// staying live in the daemon — which is how a process ends up labelled "Proxied" in the UI
/// and routed direct by the kernel. The assertions are about what reaches the daemon, because
/// that is the only thing that decides where traffic goes.
/// </remarks>
public sealed class ProcessInspectorTests
{
    private static readonly ProxyEndpoint Route = new()
    {
        Id = Guid.NewGuid(),
        Name = "test",
        Protocol = ProxyProtocol.Socks5,
        Host = "10.0.0.2",
        Port = 1080,
    };

    private static ProcessSnapshot Java(int pid = 112579) => new()
    {
        Identity = new ProcessIdentity
        {
            Pid = pid,
            StartTicks = 535558,
            Uid = 1000,
            BootId = "7f24e854-984a-4dfd-b17c-d04230f2c7b1",
        },
        Name = "java",
        ExecutablePath = "/usr/lib/jvm/java-25-graalvm/bin/java",
        ExecutablePathState = ExecutablePathState.Resolved,
        ParentPid = 1,
        UserName = "hakuu",
    };

    private static (ProcessesPageViewModel Page, RuleStore Rules, RecordingDaemonClient Daemon) New()
    {
        var rules = new RuleStore();
        rules.Proxies.Add(Route);
        var daemon = new RecordingDaemonClient();
        var page = new ProcessesPageViewModel(new ProcProcessSource(), daemon, rules)
        {
            SelectedProcess = new ProcessRowViewModel(Java()),
            SelectedProxy = Route,
        };

        return (page, rules, daemon);
    }

    // -- the scope the user picked is the scope that is installed ----------------

    [Fact]
    public async Task Proxying_with_the_tree_scope_selected_installs_a_tree_rule()
    {
        var (page, _, daemon) = New();
        page.ScopeChoice = RuleScopeChoice.Tree;

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        var rule = Assert.Single(daemon.Applied).Rule;
        Assert.Equal(ProcessSelectorKind.Instance, rule.Process.Kind);
        // The whole point of the tree scope: children that are already running come too.
        Assert.Equal(DescendantPolicy.IncludeExistingAndFuture, rule.Process.Descendants);
    }

    [Fact]
    public async Task Proxying_with_the_executable_scope_selected_installs_a_path_rule()
    {
        var (page, _, daemon) = New();
        page.ScopeChoice = RuleScopeChoice.Executable;

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        var rule = Assert.Single(daemon.Applied).Rule;
        Assert.Equal(ProcessSelectorKind.ExecutablePath, rule.Process.Kind);
        Assert.Equal("/usr/lib/jvm/java-25-graalvm/bin/java", rule.Process.ExecutablePath);
        Assert.Equal(RuleLifetime.Persistent, rule.Lifetime);
    }

    [Fact]
    public async Task The_instance_scope_does_not_cover_children_unless_the_box_is_ticked()
    {
        var (page, _, daemon) = New();
        page.ScopeChoice = RuleScopeChoice.Instance;
        page.IncludeChildren = false;

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        Assert.Equal(DescendantPolicy.Exclude, daemon.Applied[0].Rule.Process.Descendants);

        page.IncludeChildren = true;
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        Assert.Equal(DescendantPolicy.IncludeFuture, daemon.Applied[1].Rule.Process.Descendants);
    }

    [Fact]
    public void The_children_checkbox_is_hidden_where_the_scope_already_answers_it()
    {
        var (page, _, _) = New();

        page.ScopeChoice = RuleScopeChoice.Instance;
        Assert.True(page.ChildrenChoiceApplies);
        Assert.False(page.CoversChildren);

        page.ScopeChoice = RuleScopeChoice.Tree;
        Assert.False(page.ChildrenChoiceApplies);
        Assert.True(page.CoversChildren);
    }

    [Fact]
    public async Task Always_proxying_the_executable_moves_the_scope_with_it()
    {
        var (page, _, daemon) = New();
        page.ScopeChoice = RuleScopeChoice.Instance;

        await page.AlwaysProxyExecutableCommand.ExecuteAsync(null);

        // The button is a shortcut for choosing the scope, so the radio buttons must end up
        // describing the rule that was installed.
        Assert.Equal(RuleScopeChoice.Executable, page.ScopeChoice);
        Assert.Equal(ProcessSelectorKind.ExecutablePath, daemon.Applied[0].Rule.Process.Kind);
    }

    // -- a proxy button never installs something else ---------------------------

    [Fact]
    public async Task Proxying_with_no_route_chosen_does_nothing_and_says_why()
    {
        var (page, _, daemon) = New();
        page.SelectedProxy = null;

        Assert.False(page.CanProxy);
        Assert.False(page.ProxyThisInstanceCommand.CanExecute(null));
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        // It used to fall back to Direct: a button labelled "Proxy this instance" that
        // installed a direct rule, and then reported success.
        Assert.Empty(daemon.Applied);
        Assert.Contains("route", page.ApplyBlockedReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Routing_directly_and_blocking_need_no_route()
    {
        var (page, _, daemon) = New();
        page.SelectedProxy = null;

        await page.RouteDirectCommand.ExecuteAsync(null);
        await page.BlockCommand.ExecuteAsync(null);

        Assert.Equal(RuleAction.Direct.Instance, daemon.Applied[0].Rule.Action);
        Assert.Equal(RuleAction.Block.Instance, daemon.Applied[1].Rule.Action);
    }

    [Fact]
    public void Nothing_can_be_applied_while_the_daemon_is_away()
    {
        var rules = new RuleStore();
        rules.Proxies.Add(Route);
        var daemon = new RecordingDaemonClient { State = DaemonState.Disconnected };
        var page = new ProcessesPageViewModel(new ProcProcessSource(), daemon, rules)
        {
            SelectedProcess = new ProcessRowViewModel(Java()),
            SelectedProxy = Route,
        };

        page.NotifyDaemonStateChanged();

        Assert.False(page.CanApply);
        Assert.False(page.RouteDirectCommand.CanExecute(null));
        Assert.Equal(daemon.UnavailableReason, page.ApplyBlockedReason);
    }

    [Fact]
    public void The_proxy_button_says_what_the_chosen_scope_will_install()
    {
        // It said "Proxy this instance" whichever scope was chosen above it.
        var (page, _, _) = New();
        var raised = new List<string?>();
        page.PropertyChanged += (_, e) => raised.Add(e.PropertyName);

        page.ScopeChoice = RuleScopeChoice.Executable;
        var executable = page.ProxyButtonLabel;
        page.ScopeChoice = RuleScopeChoice.Tree;
        var tree = page.ProxyButtonLabel;
        page.ScopeChoice = RuleScopeChoice.Instance;
        var instance = page.ProxyButtonLabel;

        Assert.Equal(3, new[] { executable, tree, instance }.Distinct().Count());
        Assert.Contains(nameof(ProcessesPageViewModel.ProxyButtonLabel), raised);
    }

    // -- what the rule replaces has to leave the kernel too ---------------------

    [Fact]
    public async Task Changing_the_route_replaces_the_rule_in_place()
    {
        var (page, rules, daemon) = New();
        var second = new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "other", Protocol = ProxyProtocol.Socks5,
            Host = "10.0.0.3", Port = 1080,
        };
        rules.Proxies.Add(second);

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        var first = daemon.Applied[0].Rule;

        page.SelectedProxy = second;
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        // Same id, same position: the daemon swaps one rule for the other in a single step.
        // Installed beside the old rule and removed afterwards, the old one — earlier in the
        // order — was still winning when the daemon compared routes before and after, so
        // "apply to connections already open" never found a connection to move.
        var replacement = daemon.Applied[1];
        Assert.Equal(first.Id, replacement.Rule.Id);
        Assert.Equal(first.Order, replacement.Rule.Order);
        Assert.Equal(new RuleAction.Proxy(second.Id), replacement.Rule.Action);
        Assert.True(replacement.ResetExisting);
        Assert.Empty(daemon.Removed);

        var live = Assert.Single(daemon.Installed);
        Assert.Equal(first.Id, live.Id);
        Assert.Equal(second.Id, Assert.IsType<RuleAction.Proxy>(Assert.Single(rules.Rules).Action).EndpointId);
    }

    /// <summary>
    /// Two saved rules for one executable, the way a configuration written before destinations
    /// were compared by value can hold them.
    /// </summary>
    private static (RoutingRule First, RoutingRule Duplicate) SeedDuplicates(RuleStore rules, RecordingDaemonClient daemon)
    {
        var first = rules.BuildRule(Java(), RuleScopeChoice.Executable, new RuleAction.Proxy(Route.Id), false);
        var duplicate = rules.BuildRule(Java(), RuleScopeChoice.Executable, new RuleAction.Proxy(Route.Id), false) with
        {
            Order = first.Order + 1,
        };
        rules.LoadPersisted([first, duplicate]);
        daemon.Installed.Add((first.Id, first.Name));
        daemon.Installed.Add((duplicate.Id, duplicate.Name));
        return (first, duplicate);
    }

    [Fact]
    public async Task Every_saved_selection_for_the_executable_is_replaced_not_only_the_first()
    {
        var (page, rules, daemon) = New();
        var (first, duplicate) = SeedDuplicates(rules, daemon);

        page.ScopeChoice = RuleScopeChoice.Executable;
        await page.RouteDirectCommand.ExecuteAsync(null);

        // The first is replaced in place, and the duplicate taken out of the kernel: left
        // there, it would go on proxying the executable the user just routed direct.
        Assert.Equal(first.Id, Assert.Single(daemon.Applied).Rule.Id);
        Assert.Equal(duplicate.Id, Assert.Single(daemon.Removed));
        Assert.Equal(first.Id, Assert.Single(daemon.Installed).Id);
        Assert.Equal(RuleAction.Direct.Instance, Assert.Single(rules.Rules).Action);
    }

    [Fact]
    public async Task Switching_from_a_proxy_to_direct_leaves_exactly_one_rule_installed()
    {
        var (page, _, daemon) = New();

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        await page.RouteDirectCommand.ExecuteAsync(null);

        var live = Assert.Single(daemon.Installed);
        Assert.Equal(RuleAction.Direct.Instance, daemon.Applied[1].Rule.Action);
        Assert.Equal(daemon.Applied[1].Rule.Id, live.Id);
    }

    [Fact]
    public async Task A_failed_removal_of_the_replaced_rule_is_reported_not_hidden()
    {
        var (page, rules, daemon) = New();
        SeedDuplicates(rules, daemon);

        daemon.FailRemovals = true;
        page.ScopeChoice = RuleScopeChoice.Executable;
        await page.RouteDirectCommand.ExecuteAsync(null);

        Assert.NotNull(page.ErrorMessage);
        Assert.Contains("Rules page", page.ErrorMessage);
    }

    // -- the rule reaching connections that are already open --------------------

    [Fact]
    public async Task Applying_asks_the_daemon_to_reset_open_connections_by_default()
    {
        var (page, _, daemon) = New();

        Assert.True(page.ResetExistingConnections);
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        Assert.True(daemon.Applied[0].ResetExisting);
    }

    [Fact]
    public async Task Unticking_the_box_leaves_open_connections_where_they_are()
    {
        var (page, _, daemon) = New();
        page.ResetExistingConnections = false;

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        Assert.False(daemon.Applied[0].ResetExisting);
    }

    [Fact]
    public async Task The_notice_says_the_rule_is_in_force_when_connections_were_reset()
    {
        var (page, _, daemon) = New();
        daemon.NextApplyResult = new RuleApplyResult
        {
            Succeeded = true, PreExistingConnections = 4, ResetConnections = 4,
        };

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        var notice = Assert.IsType<AppliedRuleNotice>(page.LastApplied);
        Assert.True(notice.IsEffectiveNow);
        Assert.Contains("4", notice.Body);
        Assert.Contains("test", notice.Body);
        Assert.Null(notice.Caveat);
    }

    [Fact]
    public async Task The_notice_admits_when_open_connections_kept_their_route()
    {
        var (page, _, daemon) = New();
        page.ResetExistingConnections = false;
        daemon.NextApplyResult = new RuleApplyResult
        {
            Succeeded = true, PreExistingConnections = 3, ResetConnections = null,
        };

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        var notice = Assert.IsType<AppliedRuleNotice>(page.LastApplied);
        Assert.False(notice.IsEffectiveNow);
        Assert.Contains("3", notice.Body);
        Assert.Contains("previous route", notice.Body);
    }

    [Fact]
    public async Task A_reset_the_kernel_refused_is_shown_as_a_caveat()
    {
        var (page, _, daemon) = New();
        daemon.NextApplyResult = new RuleApplyResult
        {
            Succeeded = true,
            PreExistingConnections = 2,
            ResetConnections = 0,
            ResetFailure = "this kernel cannot abort sockets (EOPNOTSUPP)",
            Warnings = ["Agent exit 'tokyo' is not answering."],
        };

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        var notice = Assert.IsType<AppliedRuleNotice>(page.LastApplied);
        Assert.Contains("EOPNOTSUPP", notice.Caveat);
        Assert.Contains("tokyo", notice.Caveat);
    }

    // -- removing an override ---------------------------------------------------

    [Fact]
    public void Removing_an_override_is_offered_only_when_there_is_one()
    {
        var (page, _, _) = New();

        Assert.False(page.CanRemoveOverride);
        Assert.False(page.RemoveOverrideCommand.CanExecute(null));
    }

    [Fact]
    public async Task Removing_an_override_takes_the_rule_the_panel_installed()
    {
        var (page, _, daemon) = New();
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        var installed = daemon.Applied[0].Rule;

        Assert.True(page.CanRemoveOverride);
        await page.RemoveOverrideCommand.ExecuteAsync(null);

        Assert.Equal(installed.Id, Assert.Single(daemon.Removed));
        Assert.Empty(daemon.Installed);
        Assert.Null(page.LastApplied);
        Assert.False(page.CanRemoveOverride);
    }

    [Fact]
    public async Task An_executable_rule_is_not_an_override_and_stays_put()
    {
        var (page, _, daemon) = New();
        page.ScopeChoice = RuleScopeChoice.Executable;
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        // "Remove override" is about the temporary ones. A saved rule for every future run of
        // an executable is not temporary, and is removed on the Rules page.
        Assert.False(page.CanRemoveOverride);
        Assert.Empty(daemon.Removed);
    }
}
