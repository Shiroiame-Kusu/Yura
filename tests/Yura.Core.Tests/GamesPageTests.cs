using System.ComponentModel;
using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Ipc;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Proxies;

namespace Yura.Core.Tests;

/// <summary>The Games page: buttons that stayed disabled, and results credited to the wrong route.</summary>
public sealed class GamesPageTests
{
    private static readonly ProxyEndpoint Tokyo = new()
    {
        Id = Guid.NewGuid(), Name = "Tokyo", Protocol = ProxyProtocol.Socks5, Host = "10.0.0.2", Port = 1080,
    };

    private static readonly ProxyEndpoint Frankfurt = new()
    {
        Id = Guid.NewGuid(), Name = "Frankfurt", Protocol = ProxyProtocol.Socks5, Host = "10.0.0.3", Port = 1080,
    };

    private static ProcessSnapshot Game() => new()
    {
        Identity = new ProcessIdentity { Pid = 31337, StartTicks = 7, Uid = 1000, BootId = "b" },
        Name = "game",
        ExecutablePath = "/opt/game/bin/game",
        ExecutablePathState = ExecutablePathState.Resolved,
        ParentPid = 1,
        UserName = "hakuu",
    };

    private static (GamesPageViewModel Page, RecordingDaemonClient Daemon) New(DaemonState state = DaemonState.Connected)
    {
        var rules = new RuleStore();
        rules.Proxies.Add(Tokyo);
        rules.Proxies.Add(Frankfurt);
        var daemon = new RecordingDaemonClient { State = state };
        var page = new GamesPageViewModel(rules, daemon, new ProcProcessSource());
        page.AddFromProcess(Game());
        page.SelectedRoute = page.Routes.First(r => r.Id == Tokyo.Id);
        return (page, daemon);
    }

    private static List<string?> Raised(INotifyPropertyChanged source)
    {
        var raised = new List<string?>();
        source.PropertyChanged += (_, e) => raised.Add(e.PropertyName);
        return raised;
    }

    [Fact]
    public void The_NAT_test_and_launch_buttons_follow_the_daemon_coming_up()
    {
        // Bound once while the daemon had not yet answered, and never raised again: the NAT
        // test stayed disabled for the whole session.
        var (page, daemon) = New(DaemonState.Disconnected);
        Assert.False(page.CanTestNat);
        var raised = Raised(page);

        daemon.State = DaemonState.Connected;
        page.NotifyDaemonStateChanged();

        Assert.True(page.CanTestNat);
        Assert.Contains(nameof(GamesPageViewModel.CanTestNat), raised);
        Assert.Contains(nameof(GamesPageViewModel.CanLaunch), raised);
    }

    [Fact]
    public void A_typed_target_is_enough_to_measure()
    {
        // Measuring is what saves a target, so requiring a saved one made the button unusable
        // for every game that did not have one yet.
        var (page, _) = New();
        Assert.False(page.CanMeasure);
        var raised = Raised(page);

        page.MeasurementTargetInput = "203.0.113.5:27015";

        Assert.True(page.CanMeasure);
        Assert.Contains(nameof(GamesPageViewModel.CanMeasure), raised);
    }

    private static NatTestResultDto RouteMakesItWorse(string routeName) => new()
    {
        Direct = new NatReportDto { Verdict = NatVerdict.Moderate },
        Routed = new NatReportDto { Verdict = NatVerdict.Strict },
        RouteName = routeName,
        TestedAtUtc = DateTimeOffset.UtcNow,
    };

    [Fact]
    public async Task A_route_that_makes_peer_to_peer_worse_is_a_warning_naming_that_route()
    {
        var (page, daemon) = New();
        daemon.NextNatResult = RouteMakesItWorse("Tokyo");

        await page.TestNatCommand.ExecuteAsync(null);

        Assert.True(page.NatComparisonIsWarning);
        Assert.False(page.HasNatComparisonInfo);
        Assert.Contains("Tokyo", page.NatComparison, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Choosing_another_route_does_not_credit_it_with_the_last_result()
    {
        var (page, daemon) = New();
        daemon.NextNatResult = RouteMakesItWorse("Tokyo");
        await page.TestNatCommand.ExecuteAsync(null);

        page.SelectedRoute = page.Routes.First(r => r.Id == Frankfurt.Id);

        // Kept, it said Frankfurt makes peer-to-peer worse — a verdict measured over Tokyo.
        Assert.False(page.HasNatResult);
        Assert.Null(page.NatComparison);
        Assert.False(page.RoutedLatency.HasValue);
    }

    [Fact]
    public async Task Measuring_a_running_session_leaves_the_session_in_charge()
    {
        // The measurement started with the session used to switch the page to "Testing": Stop
        // disappeared and Start came back for as long as the measurement ran.
        var (page, daemon) = New();
        await page.StartBoostCommand.ExecuteAsync(null);
        Assert.Equal(BoostState.Routing, page.State);

        daemon.HoldMeasurements = new TaskCompletionSource();
        page.MeasurementTargetInput = "203.0.113.5:27015";
        var measuring = page.MeasureCommand.ExecuteAsync(null);

        Assert.Equal(BoostState.Routing, page.State);
        Assert.True(page.IsRunning);
        Assert.True(page.IsMeasuring);
        Assert.False(page.CanMeasure);

        daemon.HoldMeasurements.SetResult();
        await measuring;

        Assert.Equal(BoostState.Routing, page.State);
        Assert.False(page.IsMeasuring);
        page.Dispose();
    }

    [Fact]
    public async Task Starting_again_after_a_failed_stop_replaces_the_rule_in_place()
    {
        // The stop could not take the rule out, so it is still installed and still in the list.
        // Starting again installs the new rule in its place — one step in the daemon — rather
        // than beside it, where the old one would still be deciding the game's route.
        var (page, daemon) = New();
        await page.StartBoostCommand.ExecuteAsync(null);
        var first = daemon.Applied[0].Rule;

        daemon.FailRemovals = true;
        await page.StopBoostCommand.ExecuteAsync(null);
        Assert.Equal(BoostState.Failed, page.State);
        daemon.FailRemovals = false;

        page.SelectedRoute = page.Routes.First(r => r.Id == Frankfurt.Id);
        await page.StartBoostCommand.ExecuteAsync(null);

        var second = daemon.Applied[1].Rule;
        Assert.Equal(first.Id, second.Id);
        Assert.Equal(first.Order, second.Order);
        Assert.Equal(new Yura.Core.Rules.RuleAction.Proxy(Frankfurt.Id), second.Action);
        Assert.Equal(first.Id, Assert.Single(daemon.Installed).Id);
        page.Dispose();
    }
}
