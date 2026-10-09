using System.Net;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Connections;
using Yura.Core.Games;
using Yura.Core.Ipc;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// A boost started before the game: the game found when it appears, routed, and remembered.
/// </summary>
public sealed class AutoBoostTests
{
    private const string Folder = "/mnt/games/steamapps/common/Test Game";

    private const string AppId = "999999990";

    // Steam's launch wrapper: it carries the game's app id, and so does everything under it.
    private const string Wrapper = "/home/hakuu/.local/share/Steam/ubuntu12_32/reaper";

    private static readonly ProxyEndpoint Tokyo = new()
    {
        Id = Guid.NewGuid(), Name = "Tokyo", Protocol = ProxyProtocol.Socks5, Host = "10.0.0.2", Port = 1080,
    };

    /// <summary>A game Steam knows by its folder and app id, never attached: nothing to match yet.</summary>
    private static GameProfile SteamGame() => new()
    {
        Id = Guid.NewGuid(), Name = "Test Game", SteamAppId = AppId, InstallDirectory = Folder, Source = GameSource.Steam,
    };

    private static ProcessSnapshot Process(
        int pid, string path, string? wineTarget = null, string? appId = AppId, int parent = 1) => new()
    {
        Identity = new ProcessIdentity { Pid = pid, StartTicks = (ulong)pid * 10, Uid = 1000, BootId = "b" },
        Name = Path.GetFileName(path),
        ExecutablePath = path,
        ExecutablePathState = ExecutablePathState.Resolved,
        ParentPid = parent,
        UserName = "hakuu",
        Wine = wineTarget is null ? null : new WineContext { TargetExecutable = wineTarget },
        SteamAppId = appId,
    };

    private static (GamesPageViewModel Page, RecordingDaemonClient Daemon) New(GameProfile profile)
    {
        var rules = new RuleStore();
        rules.Proxies.Add(Tokyo);
        var daemon = new RecordingDaemonClient();
        var page = new GamesPageViewModel(rules, daemon, new ProcProcessSource());
        page.LoadProfiles([profile], SteamScan.Empty);
        page.SelectedGame = page.Games.Single();
        page.SelectedRoute = page.Routes.Single(r => r.Id == Tokyo.Id);
        return (page, daemon);
    }

    private static async Task Eventually(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.True(condition());
    }

    [Fact]
    public async Task A_game_that_is_not_running_can_be_boosted_and_nothing_is_installed_until_it_appears()
    {
        var (page, daemon) = New(SteamGame());
        Assert.True(page.CanStart);
        Assert.Contains("Test Game", page.StartHint, StringComparison.Ordinal);

        await page.StartBoostCommand.ExecuteAsync(null);

        Assert.Equal(BoostState.WaitingForGame, page.State);
        Assert.Empty(daemon.Applied);
        Assert.Contains("Test Game", page.StatusMessage, StringComparison.Ordinal);
        Assert.Equal(Loc.Current["Games.Monitor.WaitingForGame"], page.MonitorStatus);
        page.Dispose();
    }

    [Fact]
    public async Task A_game_that_appears_inside_its_folder_is_routed_and_remembered()
    {
        var (page, daemon) = New(SteamGame());
        var saves = 0;
        page.ProfilesChanged += (_, _) => saves++;
        await page.StartBoostCommand.ExecuteAsync(null);

        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);

        var (rule, reset) = Assert.Single(daemon.Applied);
        Assert.Equal(ProcessSelectorKind.ExecutablePath, rule.Process.Kind);
        Assert.Equal(Folder + "/bin/game", rule.Process.ExecutablePath);
        Assert.Equal(DescendantPolicy.IncludeExistingAndFuture, rule.Process.Descendants);
        // It has been running for up to a couple of seconds: what it opened before the rule is
        // dropped, and reconnects through the route.
        Assert.True(reset);
        Assert.Equal(BoostState.Routing, page.State);
        Assert.Equal(Folder + "/bin/game", Assert.Single(page.Profiles).ExecutablePath);
        Assert.True(saves > 0);
        Assert.DoesNotContain(Loc.Current["Games.ArrivedThisRunOnly"], page.StatusMessage, StringComparison.Ordinal);
        page.Dispose();
    }

    [Fact]
    public async Task The_next_boost_has_its_rule_in_place_before_the_game_starts()
    {
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);
        await page.StopBoostCommand.ExecuteAsync(null);
        page.ApplyRunning([]);

        await page.StartBoostCommand.ExecuteAsync(null);

        Assert.Equal(BoostState.WaitingForGame, page.State);
        Assert.Equal(2, daemon.Applied.Count);
        Assert.Equal(Folder + "/bin/game", daemon.Applied[1].Rule.Process.ExecutablePath);

        // The rule catches the game as it starts, so the session just routes: no second rule.
        page.ApplyRunning([Process(4343, Folder + "/bin/game")]);

        Assert.Equal(BoostState.Routing, page.State);
        Assert.Equal(2, daemon.Applied.Count);
        page.Dispose();
    }

    [Fact]
    public async Task A_game_found_by_its_launcher_is_routed_by_process_and_learned_once_its_own_binary_runs()
    {
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        var wrapper = Process(4242, Wrapper);

        // The wrapper first: a rule for its binary would route every Steam game, so this run is
        // routed by process — the wrapper and everything it starts, the game included.
        page.ApplyRunning([wrapper]);

        var (rule, _) = Assert.Single(daemon.Applied);
        Assert.Equal(ProcessSelectorKind.Instance, rule.Process.Kind);
        Assert.Equal(wrapper.Identity, rule.Process.Identity);
        Assert.Equal(DescendantPolicy.IncludeExistingAndFuture, rule.Process.Descendants);
        Assert.Null(Assert.Single(page.Profiles).ExecutablePath);
        Assert.Contains(Loc.Current["Games.ArrivedThisRunOnly"], page.StatusMessage, StringComparison.Ordinal);

        // Then the game itself, under the wrapper: remembered, and this run's rule left alone.
        page.ApplyRunning([wrapper, Process(4250, Folder + "/bin/game")]);

        Assert.Equal(4250, page.Games.Single().Running?.Identity.Pid);
        Assert.Equal(Folder + "/bin/game", Assert.Single(page.Profiles).ExecutablePath);
        Assert.Single(daemon.Applied);
        Assert.Contains("Test Game", page.StatusMessage, StringComparison.Ordinal);
        Assert.Equal(BoostState.Routing, page.State);
        page.Dispose();
    }

    [Fact]
    public async Task Relaunched_after_it_was_learned_the_game_gets_its_learned_rule()
    {
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        var wrapper = Process(4242, Wrapper);
        page.ApplyRunning([wrapper]);
        page.ApplyRunning([wrapper, Process(4250, Folder + "/bin/game")]);
        var byProcess = daemon.Applied[0].Rule;

        page.ApplyRunning([]);
        Assert.Equal(BoostState.WaitingForGame, page.State);
        page.ApplyRunning([Process(5353, Wrapper)]);

        Assert.Contains(byProcess.Id, daemon.Removed);
        var learned = daemon.Applied[1].Rule;
        Assert.Equal(ProcessSelectorKind.ExecutablePath, learned.Process.Kind);
        Assert.Equal(Folder + "/bin/game", learned.Process.ExecutablePath);
        Assert.Equal(learned.Id, Assert.Single(daemon.Installed).Id);
        Assert.Equal(BoostState.Routing, page.State);
        page.Dispose();
    }

    [Fact]
    public async Task A_game_routed_by_process_gets_a_new_rule_in_place_of_the_last_runs_when_relaunched()
    {
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        page.ApplyRunning([Process(4242, Wrapper)]);
        var first = daemon.Applied[0].Rule;

        page.ApplyRunning([]);
        page.ApplyRunning([Process(5353, Wrapper)]);

        Assert.Contains(first.Id, daemon.Removed);
        var second = daemon.Applied[1].Rule;
        Assert.Equal(5353, second.Process.Identity?.Pid);
        Assert.Equal(second.Id, Assert.Single(daemon.Installed).Id);
        Assert.Equal(BoostState.Routing, page.State);
        page.Dispose();
    }

    [Fact]
    public async Task Stopping_while_the_arrived_games_rule_goes_in_takes_it_back_out()
    {
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        daemon.HoldApply = new TaskCompletionSource();
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);

        await page.StopBoostCommand.ExecuteAsync(null);
        Assert.Equal(BoostState.Ready, page.State);
        daemon.HoldApply.SetResult();

        // Left in, it would route the game for a session that no longer exists.
        await Eventually(() => daemon.Installed.Count == 0 && daemon.Applied.Count == 1);
        Assert.Contains(daemon.Applied[0].Rule.Id, daemon.Removed);
        Assert.Equal(BoostState.Ready, page.State);
        page.Dispose();
    }

    [Fact]
    public async Task Boosting_a_game_that_is_already_running_learns_it_too()
    {
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);

        await page.StartBoostCommand.ExecuteAsync(null);

        Assert.Equal(ProcessSelectorKind.ExecutablePath, Assert.Single(daemon.Applied).Rule.Process.Kind);
        Assert.Equal(Folder + "/bin/game", Assert.Single(page.Profiles).ExecutablePath);
        Assert.Equal(BoostState.Routing, page.State);
        page.Dispose();
    }

    [Fact]
    public void A_proton_game_is_remembered_by_its_windows_executable()
    {
        var proton = Process(4242, "/home/hakuu/.local/share/Steam/steamapps/common/Proton 9.0/files/bin/wine64-preloader",
            wineTarget: @"Z:\mnt\games\steamapps\common\Test Game\Game.exe");

        var (selector, learned) = GamesPageViewModel.LearnSelector(SteamGame(), proton);

        Assert.Equal(ProcessSelectorKind.ExecutablePath, selector.Kind);
        Assert.Equal(proton.ExecutablePath, selector.ExecutablePath);
        Assert.Equal(proton.Wine!.TargetExecutable, selector.WineTargetExecutable);
        Assert.Equal(proton.Wine.TargetExecutable, learned?.WineTargetExecutable);
        Assert.True(selector.MatchesProcess(proton));
    }

    [Fact]
    public void Steams_wrapper_stands_in_for_the_game_only_until_the_game_runs()
    {
        var profile = SteamGame();
        var wrapper = Process(4242, Wrapper);
        var game = Process(4250, Folder + "/bin/game");

        Assert.True(GamesPageViewModel.MatchRank(profile, game) > GamesPageViewModel.MatchRank(profile, wrapper));
        Assert.True(GamesPageViewModel.MatchRank(profile, wrapper) > 0);
        Assert.Equal(0, GamesPageViewModel.MatchRank(profile, Process(4300, "/usr/bin/bash", appId: null)));
    }

    [Fact]
    public void A_wine_game_is_not_taken_for_another_game_on_the_same_runtime()
    {
        // The executable of every game on one Proton is the same preloader.
        const string preloader = "/home/hakuu/.local/share/Steam/steamapps/common/Proton 9.0/files/bin/wine64-preloader";
        var profile = new GameProfile
        {
            Id = Guid.NewGuid(), Name = "Wine game", Source = GameSource.Manual,
            ExecutablePath = preloader, WineTargetExecutable = @"C:\Games\One\one.exe",
        };

        var other = Process(4242, preloader, wineTarget: @"C:\Games\Two\two.exe", appId: null);
        var itself = Process(4250, preloader, wineTarget: @"c:\games\one\ONE.exe", appId: null);

        Assert.Equal(0, GamesPageViewModel.MatchRank(profile, other));
        Assert.True(GamesPageViewModel.MatchRank(profile, itself) > 0);
    }

    // -- the monitor ------------------------------------------------------------

    private static SampleSetDto Set(double? latency) => new()
    {
        Samples = 1, Successes = latency is null ? 0 : 1, LatencyMilliseconds = latency,
    };

    private static MeasurementDto Measurement(double? routed, double? direct, RouteLegsDto? legs = null) => new()
    {
        Target = "203.0.113.50:27015",
        Method = "TCP connect",
        Direct = Set(direct),
        Routed = Set(routed),
        Legs = legs,
        MeasuredAtUtc = DateTimeOffset.UtcNow,
    };

    private static ConnectionRecord Flow(
        string remote, TransportProtocol protocol, long bytes, RouteObservation route = RouteObservation.ConfirmedProxied,
        int owner = 4242) => new()
    {
        Id = Guid.NewGuid().ToString(),
        OwnerPid = owner,
        Local = IPEndPoint.Parse("192.168.1.24:51544"),
        Remote = IPEndPoint.Parse(remote),
        Protocol = protocol,
        State = ConnectionState.Established,
        Route = route,
        BytesUp = bytes / 2,
        BytesDown = bytes / 2,
    };

    [Fact]
    public async Task With_no_target_typed_the_monitor_measures_the_server_the_game_talks_to_most()
    {
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);
        await page.StartBoostCommand.ExecuteAsync(null);
        Assert.Equal(Loc.Current["Games.Monitor.WaitingForTarget"], page.MonitorStatus);
        Assert.Empty(daemon.Measured);

        daemon.NextMeasurement = Measurement(routed: 45, direct: 80);
        daemon.Connections.AddRange([
            Flow("198.51.100.7:443", TransportProtocol.Tcp, 1_000_000),
            Flow("203.0.113.50:27015", TransportProtocol.Udp, 100_000),
        ]);
        await page.RefreshEvidenceAsync();

        Assert.Equal(("203.0.113.50", (ushort)27015, (Guid?)Tokyo.Id, (Guid?)null, 1), Assert.Single(daemon.Measured));
        var sample = Assert.Single(page.History.Samples);
        Assert.Equal((45, 80), (sample.RoutedMilliseconds, sample.DirectMilliseconds));
        Assert.Contains("203.0.113.50:27015", page.MonitorTargetDisplay, StringComparison.Ordinal);
        Assert.Null(page.MonitorStatus);

        // Kept while the game still uses it, so the chart does not hop between servers.
        daemon.Connections.Add(Flow("203.0.113.60:27016", TransportProtocol.Udp, 5_000_000));
        await page.RefreshEvidenceAsync();
        Assert.Single(daemon.Measured);

        daemon.Connections.RemoveAll(c => c.Remote.Port == 27015);
        await page.RefreshEvidenceAsync();
        Assert.Equal("203.0.113.60", daemon.Measured[^1].Host);

        // A target typed in wins.
        page.MeasurementTargetInput = "198.51.100.20:7777";
        Assert.Contains("198.51.100.20:7777", page.MonitorTargetDisplay, StringComparison.Ordinal);
        page.Dispose();
    }

    [Fact]
    public async Task A_proxy_that_answers_before_connecting_is_not_measured_rather_than_shown_as_instant()
    {
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);
        daemon.NextMeasurement = Measurement(routed: null, direct: 80) with { Routed = null, RouteAnswersBeforeConnecting = true };
        page.MeasurementTargetInput = "203.0.113.50:27015";

        await page.StartBoostCommand.ExecuteAsync(null);

        var sample = Assert.Single(page.History.Samples);
        Assert.Equal((null, 80), (sample.RoutedMilliseconds, sample.DirectMilliseconds));
        Assert.Equal(Loc.Current["Common.NotMeasured"], page.MonitorNowDisplay);
        Assert.Equal(Loc.Current["Common.NotMeasured"], page.MonitorRouteMissingLabel);
        Assert.Contains("Tokyo", page.MonitorStatus, StringComparison.Ordinal);
        Assert.Equal(Loc.Current["Common.NotMeasured"], page.MonitorLossDisplay);
        // The card under it says the same, and nothing failed: the session is not degraded.
        Assert.False(page.RoutedLatency.HasValue);
        Assert.Contains("Tokyo", page.RouteSplit, StringComparison.Ordinal);
        Assert.Equal(BoostState.Routing, page.State);
        page.Dispose();
    }

    [Fact]
    public async Task A_target_that_answers_directly_but_never_through_the_route_is_put_down_to_the_route()
    {
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);
        daemon.NextMeasurement = Measurement(routed: null, direct: 80);
        page.MeasurementTargetInput = "203.0.113.50:27015";
        await page.StartBoostCommand.ExecuteAsync(null);

        for (var i = 0; i < 3; i++)
        {
            await page.SampleAsync();
        }

        Assert.Equal(4, page.History.Samples.Count);
        Assert.DoesNotContain("Tokyo", page.MonitorStatus, StringComparison.Ordinal); // still waiting

        await page.SampleAsync();

        Assert.Contains("203.0.113.50:27015", page.MonitorStatus, StringComparison.Ordinal);
        Assert.Contains("Tokyo", page.MonitorStatus, StringComparison.Ordinal);
        page.Dispose();
    }

    [Fact]
    public async Task A_server_that_answers_no_probe_after_one_that_did_is_said_not_to_answer_not_drawn_as_loss()
    {
        // Helldivers 2 behind an agent: the monitor began on a web API the game opened at start,
        // which answered, and moved to the PlayFab relay the play went to, which drops every TCP
        // connect. The API's answers stayed in the history, and the page drew 100 % loss through
        // the route and directly alike, as if the route were losing everything.
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);
        await page.StartBoostCommand.ExecuteAsync(null);

        daemon.NextMeasurement = Measurement(routed: 45, direct: 80);
        daemon.Connections.Add(Flow("198.51.100.7:443", TransportProtocol.Tcp, 1_000_000));
        await page.RefreshEvidenceAsync();
        Assert.Equal((45, 80), (page.History.Latest?.RoutedMilliseconds, page.History.Latest?.DirectMilliseconds));

        daemon.NextMeasurement = Measurement(routed: null, direct: null);
        daemon.Connections.Clear();
        daemon.Connections.Add(Flow("20.42.240.23:31166", TransportProtocol.Udp, 100_000));
        await page.RefreshEvidenceAsync();
        for (var i = 0; i < 4; i++)
        {
            await page.SampleAsync();
        }

        Assert.Equal("20.42.240.23", daemon.Measured[^1].Host);
        Assert.Equal(5, page.History.Samples.Count);
        Assert.All(page.History.Samples, s => Assert.Null(s.RoutedMilliseconds ?? s.DirectMilliseconds));
        Assert.Equal(string.Format(Loc.Current["Games.Monitor.NotAnswering"], "20.42.240.23:31166"), page.MonitorStatus);
        Assert.Equal(Loc.Current["Common.NotMeasured"], page.MonitorLossDisplay);
        Assert.False(page.MonitorLossIsWarning);
        Assert.Empty(page.History.RouteLossBuckets(TimeSpan.FromSeconds(30)));
        page.Dispose();
    }

    [Fact]
    public async Task A_probe_still_out_when_the_monitor_moves_to_another_server_is_not_counted_for_it()
    {
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning([Process(4242, Folder + "/bin/game")]);
        daemon.NextMeasurement = Measurement(routed: 45, direct: 80);
        page.MeasurementTargetInput = "198.51.100.7:443";
        await page.StartBoostCommand.ExecuteAsync(null);
        Assert.Single(page.History.Samples);

        daemon.HoldMeasurements = new TaskCompletionSource();
        var late = page.SampleAsync();
        page.MeasurementTargetInput = "20.42.240.23:31166";
        daemon.HoldMeasurements.SetResult();
        await late;
        daemon.HoldMeasurements = null;

        daemon.NextMeasurement = Measurement(routed: null, direct: null);
        await page.SampleAsync();

        // The new server's one sample, and nothing of the old one's: neither the answer it gave
        // before the move nor the one that came back after it.
        var sample = Assert.Single(page.History.Samples);
        Assert.Equal((null, null), (sample.RoutedMilliseconds, sample.DirectMilliseconds));
        Assert.False(page.History.RouteHasAnswered);
        page.Dispose();
    }

    [Fact]
    public void Through_an_agent_the_route_is_its_two_halves_not_a_fresh_encrypted_connect()
    {
        // The connect through the agent opens a new TLS stream each time; the game's datagrams
        // never pay for those handshakes.
        var legs = new RouteLegsDto { AgentName = "Frankfurt", ToAgentMilliseconds = 20, FromAgentMilliseconds = 25 };

        var sample = GamesPageViewModel.ToSample(Measurement(routed: 140, direct: 80, legs), routeIsChain: false);

        Assert.Equal(45, sample.RoutedMilliseconds);
        Assert.Equal(80, sample.DirectMilliseconds);
    }

    [Fact]
    public void An_agent_half_that_got_no_answer_makes_the_sample_unanswered()
    {
        var legs = new RouteLegsDto { AgentName = "Frankfurt", ToAgentMilliseconds = 20, FromAgentMilliseconds = null };

        var sample = GamesPageViewModel.ToSample(Measurement(routed: 140, direct: 80, legs), routeIsChain: false);

        Assert.Null(sample.RoutedMilliseconds);
    }

    [Fact]
    public void A_chain_is_measured_end_to_end()
    {
        // The agent's own probe would skip every hop after it.
        var legs = new RouteLegsDto { AgentName = "Frankfurt", ToAgentMilliseconds = 20, FromAgentMilliseconds = 25 };

        var sample = GamesPageViewModel.ToSample(Measurement(routed: 140, direct: 80, legs), routeIsChain: true);

        Assert.Equal(140, sample.RoutedMilliseconds);
    }

    [Fact]
    public void A_side_with_no_answer_is_null_rather_than_zero()
    {
        var measurement = Measurement(routed: null, direct: null) with
        {
            Direct = new SampleSetDto { Samples = 1, Successes = 0, LatencyMilliseconds = 0 },
        };

        var sample = GamesPageViewModel.ToSample(measurement, routeIsChain: false);

        Assert.Null(sample.RoutedMilliseconds);
        Assert.Null(sample.DirectMilliseconds);
    }

    [Fact]
    public void The_game_server_is_its_busiest_datagram_flow_through_the_route()
    {
        var picked = GamesPageViewModel.PickServer([
            Flow("198.51.100.7:443", TransportProtocol.Tcp, 1_000_000),
            Flow("203.0.113.60:27016", TransportProtocol.Udp, 50_000),
            Flow("203.0.113.50:27015", TransportProtocol.Udp, 100_000),
        ]);

        Assert.Equal(IPEndPoint.Parse("203.0.113.50:27015"), picked);
    }

    [Fact]
    public void Without_datagrams_the_busiest_stream_is_the_server()
    {
        var picked = GamesPageViewModel.PickServer([
            Flow("198.51.100.7:443", TransportProtocol.Tcp, 10_000),
            Flow("198.51.100.8:443", TransportProtocol.Tcp, 1_000_000),
        ]);

        Assert.Equal(IPEndPoint.Parse("198.51.100.8:443"), picked);
    }

    [Fact]
    public void A_server_the_route_carries_is_preferred_to_one_reached_directly()
    {
        var picked = GamesPageViewModel.PickServer([
            Flow("203.0.113.60:27016", TransportProtocol.Udp, 0, RouteObservation.PreExistingPreviousRoute),
            Flow("203.0.113.50:27015", TransportProtocol.Udp, 50_000),
        ]);

        Assert.Equal(IPEndPoint.Parse("203.0.113.50:27015"), picked);
    }

    [Fact]
    public void With_nothing_routed_the_server_the_game_reaches_directly_is_measured()
    {
        // The game was running before the boost and its play is still going out directly: what
        // the route would give it is exactly the question, so the chart must not stay empty.
        var picked = GamesPageViewModel.PickServer([
            Flow("198.51.100.7:443", TransportProtocol.Tcp, 0, RouteObservation.ConfirmedDirect),
            Flow("203.0.113.60:27016", TransportProtocol.Udp, 0, RouteObservation.PreExistingPreviousRoute),
        ]);

        Assert.Equal(IPEndPoint.Parse("203.0.113.60:27016"), picked);
    }

    [Fact]
    public void Nothing_on_this_network_or_for_name_lookups_is_taken_for_the_server()
    {
        var picked = GamesPageViewModel.PickServer([
            Flow("192.168.1.1:3478", TransportProtocol.Udp, 800_000),
            Flow("10.0.0.5:27015", TransportProtocol.Udp, 700_000),
            Flow("172.20.0.5:27015", TransportProtocol.Udp, 700_000),
            Flow("100.64.0.1:27015", TransportProtocol.Udp, 600_000),
            Flow("127.0.0.1:27015", TransportProtocol.Udp, 500_000),
            Flow("224.0.0.251:5353", TransportProtocol.Udp, 400_000),
            Flow("8.8.8.8:53", TransportProtocol.Udp, 300_000),
        ]);

        Assert.Null(picked);
    }

    // -- the game as a tree of processes ------------------------------------------------

    // What Steam and Proton actually run, as last night's daemon log showed it: the reaper, whose
    // arguments name the game's .exe, then Proton's wrappers, then Wine, which runs the game from
    // the library's own drive and holds every socket.
    private const string Preloader = "/home/hakuu/.local/share/Steam/steamapps/common/Proton 9.0/files/bin/wine64-preloader";

    private static ProcessSnapshot[] ProtonTree(int root = 4242) =>
    [
        Process(root, Wrapper, wineTarget: Folder + "/Game.exe"),
        Process(root + 8, "/usr/bin/python3", wineTarget: Folder + "/Game.exe", parent: root),
        Process(root + 58, Preloader, wineTarget: @"S:\steamapps\common\Test Game\Game.exe", parent: root + 8),
        Process(root + 60, Preloader, wineTarget: @"C:\windows\system32\services.exe", parent: root + 8),
        // A child whose environment was cleared still belongs to the game.
        Process(root + 70, Preloader, wineTarget: @"S:\steamapps\common\Test Game\CrashHandler.exe", appId: null, parent: root + 58),
    ];

    private static readonly ProcessSnapshot Unrelated = Process(5000, "/usr/bin/firefox", appId: null);

    [Fact]
    public void The_game_is_every_process_of_its_tree_and_nothing_else()
    {
        var pids = GamesPageViewModel.GamePids(SteamGame(), [.. ProtonTree(), Unrelated]);

        Assert.Equal([4242, 4250, 4300, 4302, 4312], pids.Order());
    }

    [Fact]
    public void A_proton_game_is_recognised_by_its_own_process_on_the_library_drive()
    {
        // S: is the Steam library, not the filesystem root: taken for the root, no Proton game
        // was recognised by the process actually running it.
        var game = SteamGame();

        Assert.True(game.MatchesInstalledPath(@"S:\steamapps\common\Test Game\Game.exe"));
        Assert.True(game.MatchesInstalledPath(@"s:\SteamApps\Common\test game\Game.exe"));
        Assert.False(game.MatchesInstalledPath(@"S:\steamapps\common\Test Game Beta\Game.exe"));
        Assert.False(game.MatchesInstalledPath(@"C:\windows\system32\services.exe"));
        Assert.False(game.MatchesInstalledPath(@"S:\Test Game\Game.exe"));
    }

    [Fact]
    public async Task The_page_reports_the_connections_of_the_whole_game_not_only_its_launcher()
    {
        // Steam's reaper is what matched, and it never opens a socket: reading its connections
        // alone, the page said nothing from the game was captured and drew no chart, while the
        // game's own process was talking through the route.
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        page.ApplyRunning([.. ProtonTree(), Unrelated]);
        Assert.Equal(BoostState.Routing, page.State);
        Assert.Equal(4242, page.Games.Single().Running?.Identity.Pid);

        daemon.NextMeasurement = Measurement(routed: 45, direct: 80);
        daemon.Connections.AddRange([
            Flow("203.0.113.50:27015", TransportProtocol.Udp, 100_000, owner: 4300),
            // The system proxy: the game's web requests go to Clash on this machine.
            Flow("127.0.0.1:7897", TransportProtocol.Tcp, 0, RouteObservation.ConfirmedDirect, owner: 4300),
            Flow("198.51.100.99:443", TransportProtocol.Tcp, 0, RouteObservation.ConfirmedDirect, owner: 5000),
        ]);
        await page.RefreshEvidenceAsync();

        Assert.Contains(string.Format(Loc.Current["Games.Evidence.Routed"], 1, "Tokyo"), page.RoutingEvidence, StringComparison.Ordinal);
        Assert.Contains(string.Format(Loc.Current["Games.Evidence.LocalProxy"], 1), page.RoutingEvidence, StringComparison.Ordinal);
        Assert.DoesNotContain(string.Format(Loc.Current["Games.Evidence.Direct"], 1), page.RoutingEvidence, StringComparison.Ordinal);
        Assert.Equal("203.0.113.50", Assert.Single(daemon.Measured).Host);
        Assert.Single(page.History.Samples);
        page.Dispose();
    }

    [Fact]
    public async Task A_game_already_running_when_the_boost_started_is_said_to_need_a_restart()
    {
        var (page, daemon) = New(SteamGame());
        page.ApplyRunning(ProtonTree());
        Assert.Contains("Test Game", page.StartHint, StringComparison.Ordinal);
        Assert.Equal(string.Format(Loc.Current["Games.StartWhileRunning"], "Test Game"), page.StartHint);

        await page.StartBoostCommand.ExecuteAsync(null);
        daemon.Connections.Add(Flow("203.0.113.50:27015", TransportProtocol.Udp, 100_000, owner: 4300));
        await page.RefreshEvidenceAsync();

        // Some connections are routed, and still it is a warning: the play may not be.
        Assert.Contains(Loc.Current["Games.Evidence.StartedWhileRunning"], page.RoutingEvidence, StringComparison.Ordinal);
        Assert.True(page.RoutingEvidenceIsWarning);

        // Restarted under the boost, the game is routed from birth, and the warning goes.
        page.ApplyRunning([]);
        page.ApplyRunning(ProtonTree(root: 6000));
        daemon.Connections.Clear();
        daemon.Connections.Add(Flow("203.0.113.50:27015", TransportProtocol.Udp, 100_000, owner: 6058));
        await page.RefreshEvidenceAsync();

        Assert.DoesNotContain(Loc.Current["Games.Evidence.StartedWhileRunning"], page.RoutingEvidence, StringComparison.Ordinal);
        Assert.False(page.RoutingEvidenceIsWarning);
        page.Dispose();
    }

    [Fact]
    public async Task A_game_started_after_the_boost_carries_no_such_warning()
    {
        var (page, daemon) = New(SteamGame());
        await page.StartBoostCommand.ExecuteAsync(null);
        page.ApplyRunning(ProtonTree());
        daemon.Connections.Add(Flow("203.0.113.50:27015", TransportProtocol.Udp, 100_000, owner: 4300));

        await page.RefreshEvidenceAsync();

        Assert.DoesNotContain(Loc.Current["Games.Evidence.StartedWhileRunning"], page.RoutingEvidence, StringComparison.Ordinal);
        Assert.False(page.RoutingEvidenceIsWarning);
        page.Dispose();
    }
}
