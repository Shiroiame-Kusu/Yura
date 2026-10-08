using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Channels;
using Yura.Core.Connections;
using Yura.Core.Rules;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Diagnostics;

/// <summary>
/// What the daemon did, written to files that outlive it: its log, and a line for every
/// connection and every rule event.
/// </summary>
/// <remarks>
/// The flows the daemon relays live in memory, and only for a minute after they end: enough for
/// the Connections page, no use the morning after. Whether a game played the night before went
/// through its route could not be answered at all, because the reboot had taken every record
/// with it. <see cref="EventsFileName"/> keeps them, one JSON object per line:
/// <list type="bullet">
/// <item><c>flow-opened</c> and <c>flow-ended</c>: process, rule, route, destination, and at
/// the end the outcome, the duration and the bytes each way;</item>
/// <item><c>rule-applied</c> and <c>rule-removed</c>, the latter with everything the rule
/// carried, and <c>rule-traffic</c> every five minutes while a rule is carrying anything;</item>
/// <item><c>process-placed</c> and <c>sockets-reset</c>: what a rule took in, and which
/// connections it had to abort to do so;</item>
/// <item><c>daemon-started</c> and <c>daemon-stopped</c>.</item>
/// </list>
/// <see cref="LogFileName"/> is the daemon's ordinary log, the same lines the journal gets.
/// Writing is queued and done by one task, so neither the forwarder nor the kernel's process
/// events ever wait for a disk; if the disk cannot keep up, lines are dropped and counted, never
/// the other way round.
/// </remarks>
public sealed class DaemonJournal : IFlowObserver, IAsyncDisposable
{
    public const string EventsFileName = "events.jsonl";

    public const string LogFileName = "daemon.log";

    /// <summary>How often a rule that is carrying traffic has it summed up.</summary>
    public static readonly TimeSpan TrafficReportInterval = TimeSpan.FromMinutes(5);

    private const int Keep = 3;
    private const int QueueCapacity = 100_000;

    private static readonly JsonWriterOptions JsonOptions = new()
    {
        // A file, not a web page: names stay readable rather than turned into \u escapes.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly Channel<(bool IsEvent, byte[] Line)>? _queue;
    private readonly Task? _writer;
    private readonly RotatingFile? _events;
    private readonly RotatingFile? _log;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<Guid, RuleTally> _tallies = new();
    private long _dropped;

    /// <summary>Writes nothing: the daemon was not told where to.</summary>
    public static DaemonJournal None { get; } = new(
        "not configured: start the daemon with --log-dir, or install the service from Settings, " +
        "whose unit gives it /var/log/yura");

    /// <summary>Writes nothing, and says why; still keeps each rule's account for the log.</summary>
    public static DaemonJournal Unwritten(string reason) => new(reason);

    private DaemonJournal(string disabledReason)
    {
        DisabledReason = disabledReason;
        _time = TimeProvider.System;
    }

    private DaemonJournal(string directory, long eventsLimit, long logLimit, TimeProvider time)
    {
        Directory = directory;
        _time = time;
        _events = new RotatingFile(Path.Combine(directory, EventsFileName), eventsLimit, Keep);
        _log = new RotatingFile(Path.Combine(directory, LogFileName), logLimit, Keep);
        _queue = Channel.CreateBounded<(bool, byte[])>(new BoundedChannelOptions(QueueCapacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        _writer = Task.Run(WriteAsync);
    }

    /// <summary>
    /// Opens the files in <paramref name="directory"/>, creating it; or a journal that writes
    /// nothing and says why, when that fails.
    /// </summary>
    public static DaemonJournal Open(
        string directory, long eventsLimit = 16L * 1024 * 1024, long logLimit = 8L * 1024 * 1024,
        TimeProvider? time = null)
    {
        try
        {
            System.IO.Directory.CreateDirectory(directory);
            return new DaemonJournal(directory, eventsLimit, logLimit, time ?? TimeProvider.System);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new DaemonJournal($"{directory} cannot be written: {e.Message}");
        }
    }

    public bool Enabled => _queue is not null;

    /// <summary>Where the files are, when they are written.</summary>
    public string? Directory { get; }

    /// <summary>Why nothing is written, when nothing is.</summary>
    public string? DisabledReason { get; }

    /// <summary>Lines lost because the disk could not take them, or could not keep up.</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    // -- writing -----------------------------------------------------------------------------

    /// <summary>One line of the daemon's ordinary log.</summary>
    public void Log(string line)
    {
        if (_queue is not null)
        {
            Enqueue(false, Encoding.UTF8.GetBytes(line));
        }
    }

    /// <summary>One event: its time and name, then whatever <paramref name="fields"/> writes.</summary>
    public void Event(string name, Action<Utf8JsonWriter>? fields = null)
    {
        if (_queue is null)
        {
            return;
        }

        var buffer = new ArrayBufferWriter<byte>(256);
        using (var json = new Utf8JsonWriter(buffer, JsonOptions))
        {
            json.WriteStartObject();
            json.WriteString("time", _time.GetLocalNow());
            json.WriteString("event", name);
            fields?.Invoke(json);
            json.WriteEndObject();
        }

        Enqueue(true, buffer.WrittenSpan.ToArray());
    }

    private void Enqueue(bool isEvent, byte[] line)
    {
        if (!_queue!.Writer.TryWrite((isEvent, line)))
        {
            Interlocked.Increment(ref _dropped);
        }
    }

    private async Task WriteAsync()
    {
        var reader = _queue!.Reader;
        while (await reader.WaitToReadAsync().ConfigureAwait(false))
        {
            while (reader.TryRead(out var item))
            {
                try
                {
                    (item.IsEvent ? _events : _log)!.Append(item.Line);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    // A full disk, most likely. The daemon goes on routing; the loss is counted.
                    Interlocked.Increment(ref _dropped);
                }
            }

            // Flushed whenever the queue runs dry, so a crash loses at most what was in flight.
            try
            {
                _events!.Flush();
                _log!.Flush();
            }
            catch (IOException)
            {
                Interlocked.Increment(ref _dropped);
            }
        }
    }

    /// <summary>Writes out everything queued, then closes the files.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_queue is null)
        {
            return;
        }

        _queue.Writer.TryComplete();
        try
        {
            await _writer!.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // A disk that hangs at shutdown costs the last lines, not a clean exit.
            return;
        }

        _events!.Dispose();
        _log!.Dispose();
    }

    // -- reading -----------------------------------------------------------------------------

    /// <summary>The last <paramref name="count"/> events, oldest first, across the newest two files.</summary>
    public IReadOnlyList<string> TailEvents(int count)
    {
        if (_events is null || count <= 0)
        {
            return [];
        }

        var lines = TailLines(_events.FilePath, count);
        if (lines.Count < count && File.Exists(_events.FilePath + ".1"))
        {
            lines.InsertRange(0, TailLines(_events.FilePath + ".1", count - lines.Count));
        }

        return lines;
    }

    /// <summary>The last complete lines of a file, read from its end.</summary>
    internal static List<string> TailLines(string path, int count)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var end = stream.Length;
            var start = end;
            var newlines = 0;
            var chunk = new byte[64 * 1024];

            // Back from the end until there are enough line breaks, or the file runs out.
            while (start > 0 && newlines <= count)
            {
                var size = (int)Math.Min(chunk.Length, start);
                start -= size;
                stream.Position = start;
                stream.ReadExactly(chunk, 0, size);
                newlines += chunk.AsSpan(0, size).Count((byte)'\n');
            }

            var tail = new byte[end - start];
            stream.Position = start;
            stream.ReadExactly(tail);
            var lines = Encoding.UTF8.GetString(tail).Split('\n').ToList();

            // The first piece may be the end of a longer line, and the last one may still be
            // being written: only the complete lines between them are lines.
            if (start > 0)
            {
                lines.RemoveAt(0);
            }

            lines.RemoveAt(lines.Count - 1);
            return lines.Where(l => l.Length > 0).TakeLast(count).ToList();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    // -- flows -------------------------------------------------------------------------------

    public void Opened(Flow flow) => Event("flow-opened", json => WriteFlow(json, flow));

    public void Ended(Flow flow)
    {
        Tally(flow);
        Event("flow-ended", json =>
        {
            WriteFlow(json, flow);
            json.WriteString("outcome", Outcome(flow));
            json.WriteNumber("seconds", Math.Round(((flow.ClosedAtUtc ?? _time.GetUtcNow()) - flow.CreatedAtUtc).TotalSeconds, 3));
            json.WriteNumber("bytesUp", flow.BytesUp);
            json.WriteNumber("bytesDown", flow.BytesDown);
            WriteOptional(json, "failure", flow.FailureReason);
        });
    }

    private static string Outcome(Flow flow) => flow.State switch
    {
        ConnectionState.Failed => "failed",
        _ when flow.Route == RouteObservation.ConfirmedBlocked => "blocked",
        _ when flow.Route == RouteObservation.ConfirmedProxied => "proxied",
        _ when flow.Route == RouteObservation.ConfirmedDirect => "direct",
        _ => "closed",
    };

    private static void WriteFlow(Utf8JsonWriter json, Flow flow)
    {
        json.WriteNumber("flow", flow.Id);
        json.WriteString("protocol", flow.Protocol == TransportProtocol.Tcp ? "tcp" : "udp");
        if (flow.OwnerPid is { } pid)
        {
            json.WriteNumber("pid", pid);
        }

        WriteOptional(json, "process", flow.ProcessName);
        WriteOptional(json, "rule", flow.RuleName);
        if (flow.RuleId is { } rule)
        {
            json.WriteString("ruleId", rule);
        }

        WriteOptional(json, "route", flow.ProxyName ?? flow.Route switch
        {
            RouteObservation.ConfirmedDirect => "direct",
            RouteObservation.ConfirmedBlocked => "blocked",
            _ => null,
        });
        json.WriteString("destination", flow.OriginalDestination.ToString());
        WriteOptional(json, "host", flow.Host);
        json.WriteString("client", flow.Client.ToString());
        WriteOptional(json, "note", flow.Note);
    }

    private static void WriteOptional(Utf8JsonWriter json, string name, string? value)
    {
        if (value is not null)
        {
            json.WriteString(name, value);
        }
    }

    // -- rules -------------------------------------------------------------------------------

    /// <summary>What one rule has carried since it was applied.</summary>
    private sealed class RuleTally(DateTimeOffset since)
    {
        public DateTimeOffset Since { get; } = since;
        public string? Name { get; set; }
        public string? Route { get; set; }
        public long Flows { get; set; }
        public long Proxied { get; set; }
        public long Failed { get; set; }
        public long Blocked { get; set; }
        public long Up { get; set; }
        public long Down { get; set; }
        public DateTimeOffset ReportedAt { get; set; } = since;
        public long ReportedFlows { get; set; }
        public long ReportedUp { get; set; }
        public long ReportedDown { get; set; }
    }

    private RuleTally TallyFor(Guid ruleId) => _tallies.GetOrAdd(ruleId, _ => new RuleTally(_time.GetUtcNow()));

    private void Tally(Flow flow)
    {
        // A rule's account opens when it is applied. A flow that ends after its rule was removed
        // was counted then, as open, and must not start an account nobody will ever close.
        if (flow.RuleId is not { } id || !_tallies.TryGetValue(id, out var tally))
        {
            return;
        }

        lock (tally)
        {
            tally.Name ??= flow.RuleName;
            tally.Flows++;
            tally.Up += flow.BytesUp;
            tally.Down += flow.BytesDown;
            switch (Outcome(flow))
            {
                case "failed":
                    tally.Failed++;
                    break;
                case "blocked":
                    tally.Blocked++;
                    break;
                case "proxied":
                    tally.Proxied++;
                    break;
            }
        }
    }

    public void RuleApplied(RoutingRule rule, string route, ApplyOutcome outcome)
    {
        var tally = TallyFor(rule.Id);
        lock (tally)
        {
            tally.Name = rule.Name;
            tally.Route = route;
        }

        Event("rule-applied", json =>
        {
            json.WriteString("ruleId", rule.Id);
            json.WriteString("rule", rule.Name);
            json.WriteString("origin", rule.Origin.ToString());
            json.WriteString("lifetime", rule.Lifetime.ToString());
            json.WriteString("process", rule.Process.Describe());
            json.WriteString("route", route);
            json.WriteNumber("migrated", outcome.MigratedProcesses);
            if (outcome.PreExistingConnections is { } existing)
            {
                json.WriteNumber("preExisting", existing);
            }

            if (outcome.ResetConnections is { } reset)
            {
                json.WriteNumber("reset", reset);
            }

            WriteOptional(json, "resetFailure", outcome.ResetFailure);
            if (outcome.Warnings.Count > 0)
            {
                json.WriteStartArray("warnings");
                foreach (var warning in outcome.Warnings)
                {
                    json.WriteStringValue(warning);
                }

                json.WriteEndArray();
            }
        });
    }

    /// <summary>
    /// Writes what a rule carried, now that it is gone, and says it in a sentence for the log.
    /// </summary>
    /// <param name="reason">"removed", "expired", "stopped with the daemon".</param>
    /// <param name="flows">The registry's flows, for the ones still open: their bytes so far count.</param>
    public string RuleRemoved(RoutingRule rule, string reason, IReadOnlyList<Flow> flows)
    {
        _tallies.TryRemove(rule.Id, out var tally);
        tally ??= new RuleTally(_time.GetUtcNow());
        var open = flows.Where(f => f.RuleId == rule.Id && f.ClosedAtUtc is null).ToList();
        long count, proxied, failed, blocked, up, down;
        lock (tally)
        {
            count = tally.Flows + open.Count;
            proxied = tally.Proxied + open.Count(f => f.Route == RouteObservation.ConfirmedProxied);
            failed = tally.Failed;
            blocked = tally.Blocked;
            up = tally.Up + open.Sum(f => f.BytesUp);
            down = tally.Down + open.Sum(f => f.BytesDown);
        }

        var lasted = _time.GetUtcNow() - tally.Since;
        Event("rule-removed", json =>
        {
            json.WriteString("ruleId", rule.Id);
            json.WriteString("rule", rule.Name);
            json.WriteString("reason", reason);
            json.WriteNumber("seconds", Math.Round(lasted.TotalSeconds, 1));
            json.WriteNumber("flows", count);
            json.WriteNumber("proxied", proxied);
            json.WriteNumber("failed", failed);
            json.WriteNumber("blocked", blocked);
            json.WriteNumber("bytesUp", up);
            json.WriteNumber("bytesDown", down);
        });

        var through = tally.Route is { } route && proxied > 0 ? $"{proxied} through {route}" : $"{proxied} proxied";
        return string.Create(CultureInfo.InvariantCulture,
            $"rule '{rule.Name}' {reason} after {Duration(lasted)}: {count} connection(s) ({through}, {failed} failed), " +
            $"{Bytes(up)} sent, {Bytes(down)} received");
    }

    /// <summary>
    /// Sums up, every <see cref="TrafficReportInterval"/>, each rule that carried anything since
    /// the last time, and says so in a sentence each for the log.
    /// </summary>
    public IReadOnlyList<string> ReportTraffic(IReadOnlyList<RoutingRule> rules, IReadOnlyList<Flow> flows)
    {
        var now = _time.GetUtcNow();
        var sentences = new List<string>();
        foreach (var rule in rules)
        {
            if (!_tallies.TryGetValue(rule.Id, out var tally))
            {
                continue;
            }

            var open = flows.Where(f => f.RuleId == rule.Id && f.ClosedAtUtc is null).ToList();
            lock (tally)
            {
                if (now - tally.ReportedAt < TrafficReportInterval)
                {
                    continue;
                }

                var count = tally.Flows + open.Count;
                var up = tally.Up + open.Sum(f => f.BytesUp);
                var down = tally.Down + open.Sum(f => f.BytesDown);
                var minutes = (now - tally.ReportedAt).TotalMinutes;
                var (recentUp, recentDown) = (up - tally.ReportedUp, down - tally.ReportedDown);
                tally.ReportedAt = now;
                if (count == tally.ReportedFlows && recentUp == 0 && recentDown == 0)
                {
                    continue;
                }

                (tally.ReportedFlows, tally.ReportedUp, tally.ReportedDown) = (count, up, down);
                var failed = tally.Failed;
                Event("rule-traffic", json =>
                {
                    json.WriteString("ruleId", rule.Id);
                    json.WriteString("rule", rule.Name);
                    json.WriteNumber("open", open.Count);
                    json.WriteNumber("flows", count);
                    json.WriteNumber("failed", failed);
                    json.WriteNumber("bytesUp", up);
                    json.WriteNumber("bytesDown", down);
                    json.WriteNumber("recentBytesUp", recentUp);
                    json.WriteNumber("recentBytesDown", recentDown);
                    json.WriteNumber("recentSeconds", Math.Round(minutes * 60, 1));
                });
                sentences.Add(string.Create(CultureInfo.InvariantCulture,
                    $"rule '{rule.Name}': {open.Count} connection(s) open, {count} since it was applied ({failed} failed); " +
                    $"{Bytes(recentUp)} sent and {Bytes(recentDown)} received in the last {minutes:0} min"));
            }
        }

        return sentences;
    }

    // -- processes and sockets ---------------------------------------------------------------

    /// <param name="how">"moved", for a running process, or "at exec", placed before it could open a socket.</param>
    public void ProcessPlaced(int pid, string? process, string group, string how) => Event("process-placed", json =>
    {
        json.WriteNumber("pid", pid);
        WriteOptional(json, "process", process);
        json.WriteString("group", group);
        json.WriteString("how", how);
    });

    /// <summary>The connections aborted so a rule would apply to them, one by one.</summary>
    public void SocketsReset(
        IReadOnlyList<(int Pid, string? Process, TransportProtocol Protocol, IPEndPoint Local, IPEndPoint Remote)> sockets,
        int reset, string? failure) => Event("sockets-reset", json =>
    {
        json.WriteNumber("reset", reset);
        WriteOptional(json, "failure", failure);
        json.WriteStartArray("sockets");
        foreach (var socket in sockets)
        {
            json.WriteStartObject();
            json.WriteNumber("pid", socket.Pid);
            WriteOptional(json, "process", socket.Process);
            json.WriteString("protocol", socket.Protocol == TransportProtocol.Tcp ? "tcp" : "udp");
            json.WriteString("local", socket.Local.ToString());
            json.WriteString("remote", socket.Remote.ToString());
            json.WriteEndObject();
        }

        json.WriteEndArray();
    });

    // -- words -------------------------------------------------------------------------------

    internal static string Bytes(long bytes) => bytes switch
    {
        < 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes} B"),
        < 1024 * 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes / 1024.0:0.#} KB"),
        < 1024L * 1024 * 1024 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024):0.#} MB"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024 * 1024):0.##} GB"),
    };

    internal static string Duration(TimeSpan span) => span.TotalHours >= 1
        ? string.Create(CultureInfo.InvariantCulture, $"{(int)span.TotalHours}h {span.Minutes:00}m")
        : span.TotalMinutes >= 1
            ? string.Create(CultureInfo.InvariantCulture, $"{(int)span.TotalMinutes}m {span.Seconds:00}s")
            : string.Create(CultureInfo.InvariantCulture, $"{span.TotalSeconds:0}s");
}
