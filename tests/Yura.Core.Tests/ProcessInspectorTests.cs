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
/// Every test here pins a fault that shipped. The assertions are about what reaches the
/// daemon, because that is the only thing that decides where traffic goes — a rule the app
/// lists and the daemon does not hold, or holds twice, is exactly how a process ends up
/// labelled "Proxied" in the UI and routed direct by the kernel.
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

    // -- what the rule replaces has to leave the kernel too ---------------------

    [Fact]
    public async Task Changing_the_route_takes_the_rule_it_replaces_out_of_the_daemon()
    {
        var (page, rules, daemon) = New();
        var second = new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "other", Protocol = ProxyProtocol.Socks5,
            Host = "10.0.0.3", Port = 1080,
        };
        rules.Proxies.Add(second);

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        var first = daemon.Applied[0];

        page.SelectedProxy = second;
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        // The superseded rule has the lower position, so leaving it installed would mean the
        // kernel kept using the first route while the panel showed the second.
        Assert.Contains(first.Id, daemon.Removed);
        var live = Assert.Single(daemon.Installed);
        Assert.Equal(daemon.Applied[1].Id, live.Id);
        Assert.Single(rules.Rules);
    }

    [Fact]
    public async Task Switching_from_a_proxy_to_direct_leaves_exactly_one_rule_installed()
    {
        var (page, _, daemon) = New();

        await page.ProxyThisInstanceCommand.ExecuteAsync(null);
        await page.RouteDirectCommand.ExecuteAsync(null);

        var live = Assert.Single(daemon.Installed);
        Assert.Equal(RuleAction.Direct.Instance, daemon.Applied[1].Action);
        Assert.Equal(daemon.Applied[1].Id, live.Id);
    }

    [Fact]
    public async Task A_failed_removal_of_the_replaced_rule_is_reported_not_hidden()
    {
        var (page, _, daemon) = New();
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        daemon.FailRemovals = true;
        page.SelectedProxy = new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "other", Protocol = ProxyProtocol.Socks5,
            Host = "10.0.0.3", Port = 1080,
        };
        await page.ProxyThisInstanceCommand.ExecuteAsync(null);

        Assert.NotNull(page.ErrorMessage);
        Assert.Contains("Rules page", page.ErrorMessage);
    }
}
