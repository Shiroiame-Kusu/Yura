using System.Net;
using System.Text.Json;
using Yura.Core.Connections;
using Yura.Core.Rules;
using Yura.Daemon.Diagnostics;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Tests;

/// <summary>
/// The record the daemon writes of what it routed, which has to outlive it.
/// </summary>
/// <remarks>
/// It exists because a question could not be answered: whether a game played the night before
/// had gone through its route. The flows were held in memory, and the reboot took them.
/// </remarks>
public sealed class DaemonJournalTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"yura-journal-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static readonly Guid RuleId = Guid.NewGuid();

    private static RoutingRule Rule() => new()
    {
        Id = RuleId,
        Order = 200,
        Name = "PEAK (game boost)",
        Origin = RuleOrigin.GameProfile,
        Lifetime = RuleLifetime.Session,
        Process = new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/usr/bin/game" },
        Destination = DestinationSelector.Any,
        Action = new RuleAction.Proxy(Guid.NewGuid()),
        CreatedAtUtc = DateTimeOffset.UtcNow,
    };

    private static Flow Flow(IFlowObserver observer, int port = 51544, TransportProtocol protocol = TransportProtocol.Udp)
    {
        var flow = new Flow(
            new IPEndPoint(IPAddress.Parse("192.168.1.24"), port),
            new IPEndPoint(IPAddress.Parse("203.0.113.50"), 27015),
            protocol,
            RuleId) { Observer = observer };
        flow.Describe(new FlowPlan
        {
            Kind = FlowPlanKind.Proxy,
            RouteName = "Frankfurt agent",
            RuleId = RuleId,
            RuleName = "PEAK (game boost)",
            OwnerPid = 140136,
            ProcessName = "PEAK.exe",
        });
        return flow;
    }

    private List<JsonElement> Events() => File.ReadAllLines(Path.Combine(_directory, DaemonJournal.EventsFileName))
        .Select(line => JsonDocument.Parse(line).RootElement)
        .ToList();

    [Fact]
    public async Task A_flow_is_written_when_it_opens_and_again_with_its_bytes_when_it_ends()
    {
        var journal = DaemonJournal.Open(_directory);
        var flow = Flow(journal);

        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
        flow.AddUp(1200);
        flow.AddDown(48000);
        flow.MarkClosed();
        await journal.DisposeAsync();

        var events = Events();
        Assert.Equal(["flow-opened", "flow-ended"], events.Select(e => e.GetProperty("event").GetString()));
        var ended = events[1];
        Assert.Equal("udp", ended.GetProperty("protocol").GetString());
        Assert.Equal(140136, ended.GetProperty("pid").GetInt32());
        Assert.Equal("PEAK.exe", ended.GetProperty("process").GetString());
        Assert.Equal("PEAK (game boost)", ended.GetProperty("rule").GetString());
        Assert.Equal("Frankfurt agent", ended.GetProperty("route").GetString());
        Assert.Equal("203.0.113.50:27015", ended.GetProperty("destination").GetString());
        Assert.Equal("proxied", ended.GetProperty("outcome").GetString());
        Assert.Equal(1200, ended.GetProperty("bytesUp").GetInt64());
        Assert.Equal(48000, ended.GetProperty("bytesDown").GetInt64());
    }

    [Fact]
    public async Task A_flow_ended_twice_is_written_once_and_a_failure_keeps_its_reason()
    {
        var journal = DaemonJournal.Open(_directory);
        var flow = Flow(journal);

        // Never opened: the agent refused it.
        flow.MarkFailed("The agent could not reach 203.0.113.50:27015: timed out");
        flow.MarkClosed();
        await journal.DisposeAsync();

        var ended = Assert.Single(Events());
        Assert.Equal("flow-ended", ended.GetProperty("event").GetString());
        Assert.Equal("failed", ended.GetProperty("outcome").GetString());
        Assert.Contains("timed out", ended.GetProperty("failure").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_removed_rule_says_everything_it_carried_open_connections_included()
    {
        var journal = DaemonJournal.Open(_directory);
        var rule = Rule();
        journal.RuleApplied(rule, "Frankfurt agent", new ApplyOutcome { Succeeded = true, MigratedProcesses = 16, ResetConnections = 3 });
        var finished = Flow(journal, 1);
        finished.MarkEstablished(RouteObservation.ConfirmedProxied);
        finished.AddUp(1024 * 1024);
        finished.AddDown(3 * 1024 * 1024);
        finished.MarkClosed();
        Flow(journal, 2).MarkFailed("refused");
        var open = Flow(journal, 3);
        open.MarkEstablished(RouteObservation.ConfirmedProxied);
        open.AddDown(1024 * 1024);

        var sentence = journal.RuleRemoved(rule, "removed", [finished, open]);
        await journal.DisposeAsync();

        Assert.Equal("rule 'PEAK (game boost)' removed after 0s: 3 connection(s) (2 through Frankfurt agent, 1 failed), 1 MB sent, 4 MB received", sentence);
        var applied = Events().Single(e => e.GetProperty("event").GetString() == "rule-applied");
        Assert.Equal(16, applied.GetProperty("migrated").GetInt32());
        Assert.Equal(3, applied.GetProperty("reset").GetInt32());
        var removed = Events().Single(e => e.GetProperty("event").GetString() == "rule-removed");
        Assert.Equal(3, removed.GetProperty("flows").GetInt64());
        Assert.Equal(1, removed.GetProperty("failed").GetInt64());
        Assert.Equal(4 * 1024 * 1024, removed.GetProperty("bytesDown").GetInt64());
    }

    [Fact]
    public async Task A_flow_that_ends_after_its_rule_went_opens_no_new_account()
    {
        var time = new ManualTime();
        var journal = DaemonJournal.Open(_directory, time: time);
        var rule = Rule();
        journal.RuleApplied(rule, "Frankfurt agent", new ApplyOutcome { Succeeded = true });
        var open = Flow(journal);
        open.MarkEstablished(RouteObservation.ConfirmedProxied);
        open.AddDown(4096);
        journal.RuleRemoved(rule, "removed", [open]);

        open.AddDown(4096);
        open.MarkClosed();

        // Counted once already, as open; nothing more to report for a rule that is gone.
        time.Now += DaemonJournal.TrafficReportInterval;
        Assert.Empty(journal.ReportTraffic([rule], []));
        await journal.DisposeAsync();
        Assert.Single(Events(), e => e.GetProperty("event").GetString() == "rule-removed");
    }

    [Fact]
    public async Task Traffic_is_summed_up_every_five_minutes_and_only_when_there_was_some()
    {
        var time = new ManualTime();
        var journal = DaemonJournal.Open(_directory, time: time);
        var rule = Rule();
        journal.RuleApplied(rule, "Frankfurt agent", new ApplyOutcome { Succeeded = true });
        var flow = Flow(journal);
        flow.MarkEstablished(RouteObservation.ConfirmedProxied);
        flow.AddUp(2048);

        Assert.Empty(journal.ReportTraffic([rule], [flow]));

        time.Now += DaemonJournal.TrafficReportInterval;
        var report = Assert.Single(journal.ReportTraffic([rule], [flow]));
        Assert.Equal("rule 'PEAK (game boost)': 1 connection(s) open, 1 since it was applied (0 failed); 2 KB sent and 0 B received in the last 5 min", report);

        // Five quiet minutes say nothing.
        time.Now += DaemonJournal.TrafficReportInterval;
        Assert.Empty(journal.ReportTraffic([rule], [flow]));
        await journal.DisposeAsync();

        Assert.Single(Events(), e => e.GetProperty("event").GetString() == "rule-traffic");
    }

    [Fact]
    public async Task A_full_file_is_moved_aside_and_only_a_few_are_kept()
    {
        var journal = DaemonJournal.Open(_directory, eventsLimit: 400);
        for (var i = 0; i < 40; i++)
        {
            journal.Event("filler", json => json.WriteString("text", new string('x', 60)));
        }

        await journal.DisposeAsync();

        var files = Directory.GetFiles(_directory, DaemonJournal.EventsFileName + "*").Select(Path.GetFileName).Order().ToList();
        Assert.Equal(["events.jsonl", "events.jsonl.1", "events.jsonl.2", "events.jsonl.3"], files);
        Assert.All(files, f => Assert.True(new FileInfo(Path.Combine(_directory, f!)).Length <= 400));
    }

    [Fact]
    public async Task The_last_events_are_read_back_newest_last_across_the_newest_two_files()
    {
        var journal = DaemonJournal.Open(_directory, eventsLimit: 1000);
        for (var i = 1; i <= 30; i++)
        {
            var n = i;
            journal.Event("numbered", json => json.WriteNumber("n", n));
        }

        await journal.DisposeAsync();
        var reopened = DaemonJournal.Open(_directory);

        var tail = reopened.TailEvents(12).Select(l => JsonDocument.Parse(l).RootElement.GetProperty("n").GetInt32());
        await reopened.DisposeAsync();

        Assert.Equal(Enumerable.Range(19, 12), tail);
    }

    [Fact]
    public void A_directory_that_cannot_be_written_turns_the_record_off_and_says_why()
    {
        var journal = DaemonJournal.Open("/proc/yura-journal");

        Assert.False(journal.Enabled);
        Assert.Contains("/proc/yura-journal", journal.DisabledReason, StringComparison.Ordinal);
        journal.Event("ignored");
        Assert.Empty(journal.TailEvents(5));
    }

    [Theory]
    [InlineData(900, "900 B")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(48L * 1024 * 1024, "48 MB")]
    [InlineData(3L * 1024 * 1024 * 1024, "3 GB")]
    public void Sizes_are_said_the_way_a_person_reads_them(long bytes, string expected)
    {
        Assert.Equal(expected, DaemonJournal.Bytes(bytes));
    }
}
