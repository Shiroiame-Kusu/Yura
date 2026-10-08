namespace Yura.App.ViewModels;

/// <summary>
/// One tick of a session's monitor: the target probed once through the route and once directly.
/// </summary>
/// <param name="RoutedMilliseconds">The round trip through the route, or null when it got no answer.</param>
/// <param name="DirectMilliseconds">The round trip on the direct path, or null when it got no answer.</param>
public readonly record struct LatencySample(DateTimeOffset At, double? RoutedMilliseconds, double? DirectMilliseconds);

/// <summary>One row of the monitor's table view, the chart's readable twin.</summary>
public sealed record BoostSampleRow(string Time, string Route, string Direct);

/// <summary>How many probes went unanswered in one slice of the session.</summary>
public readonly record struct LossBucket(DateTimeOffset Start, TimeSpan Width, int Probes, int Lost)
{
    public double Percent => Probes == 0 ? 0 : 100.0 * Lost / Probes;
}

/// <summary>
/// What a session's monitor has seen over the last ten minutes, and what it adds up to.
/// </summary>
/// <remarks>
/// Loss is counted from the first answer on. A target that has never answered is not a route
/// dropping every packet; it is a target that does not answer probes, such as a server behind a
/// firewall that drops them, and the page says so instead of drawing a wall of 100 %. Probes lost
/// before the first answer, while an agent session was still being set up, say nothing about the
/// route either.
/// </remarks>
public sealed class BoostHistory
{
    /// <summary>How much of the session is kept, and drawn.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(10);

    /// <summary>The span the headline loss figure covers.</summary>
    public static readonly TimeSpan LossSpan = TimeSpan.FromMinutes(1);

    private readonly List<LatencySample> _samples = [];

    public IReadOnlyList<LatencySample> Samples => _samples;

    /// <summary>Changes whenever a sample is added or the history is cleared, for whatever draws it.</summary>
    public int Version { get; private set; }

    public bool IsEmpty => _samples.Count == 0;

    public LatencySample? Latest => _samples.Count == 0 ? null : _samples[^1];

    /// <summary>When the route first answered, or null if it never has.</summary>
    public DateTimeOffset? RouteFirstAnswered { get; private set; }

    /// <summary>When the direct path first answered, or null if it never has.</summary>
    public DateTimeOffset? DirectFirstAnswered { get; private set; }

    public bool RouteHasAnswered => RouteFirstAnswered is not null;

    public void Add(LatencySample sample)
    {
        _samples.Add(sample);
        if (sample.RoutedMilliseconds is not null)
        {
            RouteFirstAnswered ??= sample.At;
        }

        if (sample.DirectMilliseconds is not null)
        {
            DirectFirstAnswered ??= sample.At;
        }

        var cutoff = sample.At - Window;
        var keepFrom = _samples.FindIndex(s => s.At >= cutoff);
        if (keepFrom > 0)
        {
            _samples.RemoveRange(0, keepFrom);
        }

        Version++;
    }

    public void Clear()
    {
        _samples.Clear();
        RouteFirstAnswered = null;
        DirectFirstAnswered = null;
        Version++;
    }

    public double? RouteAverage => Average(s => s.RoutedMilliseconds);

    public double? DirectAverage => Average(s => s.DirectMilliseconds);

    /// <summary>The mean change between consecutive answers through the route.</summary>
    public double? RouteJitter => Jitter(s => s.RoutedMilliseconds);

    public double? DirectJitter => Jitter(s => s.DirectMilliseconds);

    /// <summary>Unanswered probes through the route over the last minute, in percent.</summary>
    public double? RouteLossPercent => Loss(LossSpan, s => s.RoutedMilliseconds, RouteFirstAnswered);

    public double? DirectLossPercent => Loss(LossSpan, s => s.DirectMilliseconds, DirectFirstAnswered);

    /// <summary>
    /// Loss through the route in slices of <paramref name="width"/>, oldest first.
    /// </summary>
    /// <remarks>
    /// The slices sit on multiples of the width, not on the latest sample, so a bar stays where it
    /// is as new samples arrive instead of shifting a little at every tick.
    /// </remarks>
    public IReadOnlyList<LossBucket> RouteLossBuckets(TimeSpan width)
    {
        if (RouteFirstAnswered is not { } since)
        {
            return [];
        }

        var buckets = new List<LossBucket>();
        foreach (var sample in _samples)
        {
            if (sample.At < since)
            {
                continue;
            }

            var start = new DateTimeOffset(sample.At.UtcTicks - (sample.At.UtcTicks % width.Ticks), TimeSpan.Zero);
            var lost = sample.RoutedMilliseconds is null ? 1 : 0;
            if (buckets.Count > 0 && buckets[^1].Start == start)
            {
                var last = buckets[^1];
                buckets[^1] = last with { Probes = last.Probes + 1, Lost = last.Lost + lost };
            }
            else
            {
                buckets.Add(new LossBucket(start, width, 1, lost));
            }
        }

        return buckets;
    }

    private double? Average(Func<LatencySample, double?> value)
    {
        var answered = _samples.Select(value).OfType<double>().ToList();
        return answered.Count == 0 ? null : answered.Average();
    }

    private double? Jitter(Func<LatencySample, double?> value)
    {
        var answered = _samples.Select(value).OfType<double>().ToList();
        if (answered.Count < 2)
        {
            return null;
        }

        return answered.Zip(answered.Skip(1), (a, b) => Math.Abs(b - a)).Average();
    }

    private double? Loss(TimeSpan span, Func<LatencySample, double?> value, DateTimeOffset? firstAnswer)
    {
        if (firstAnswer is not { } since || Latest is not { } latest)
        {
            return null;
        }

        var from = latest.At - span;
        var counted = _samples.Where(s => s.At >= from && s.At >= since).ToList();
        return counted.Count == 0 ? null : 100.0 * counted.Count(s => value(s) is null) / counted.Count;
    }
}
