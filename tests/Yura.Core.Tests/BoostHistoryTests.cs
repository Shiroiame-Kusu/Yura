using Yura.App.ViewModels;
using Yura.App.Views;

namespace Yura.Core.Tests;

/// <summary>
/// What a session's monitor adds its samples up to: the figures in the tiles and the loss bars.
/// </summary>
public sealed class BoostHistoryTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 7, 20, 0, 0, TimeSpan.Zero);

    private static LatencySample At(int seconds, double? routed, double? direct = 80) =>
        new(Start.AddSeconds(seconds), routed, direct);

    [Fact]
    public void Probes_lost_before_the_route_first_answered_are_not_loss()
    {
        // An agent session still being set up, or a rule not yet in force: nothing about the route.
        var history = new BoostHistory();
        history.Add(At(0, null));
        history.Add(At(3, null));
        history.Add(At(6, 45));
        history.Add(At(9, 47));

        Assert.Equal(0, history.RouteLossPercent);
        Assert.Equal(Start.AddSeconds(6), history.RouteFirstAnswered);
        Assert.All(history.RouteLossBuckets(TimeSpan.FromSeconds(30)), b => Assert.Equal(0, b.Lost));
    }

    [Fact]
    public void A_target_that_never_answered_has_no_loss_figure_rather_than_all_of_it()
    {
        // A server behind a firewall that drops probes is not a route losing every packet.
        var history = new BoostHistory();
        for (var i = 0; i < 10; i++)
        {
            history.Add(At(i * 3, null, null));
        }

        Assert.False(history.RouteHasAnswered);
        Assert.Null(history.RouteLossPercent);
        Assert.Null(history.DirectLossPercent);
        Assert.Null(history.RouteAverage);
        Assert.Empty(history.RouteLossBuckets(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void The_headline_loss_covers_the_last_minute_only()
    {
        var history = new BoostHistory();
        history.Add(At(0, 45));
        history.Add(At(3, null));   // more than a minute before the latest: not counted
        history.Add(At(6, null));
        for (var s = 70; s <= 130; s += 3)
        {
            history.Add(At(s, s == 100 ? null : 46));
        }

        // 21 samples from 70 to 130 s, all within a minute of the last; one of them unanswered.
        Assert.Equal(100.0 / 21, history.RouteLossPercent!.Value, 6);
    }

    [Fact]
    public void Samples_older_than_the_window_are_dropped()
    {
        var history = new BoostHistory();
        history.Add(At(0, 45));
        history.Add(At(60, 46));
        var version = history.Version;

        history.Add(At((int)BoostHistory.Window.TotalSeconds + 30, 47));

        Assert.Equal([60, (int)BoostHistory.Window.TotalSeconds + 30],
            history.Samples.Select(s => (int)(s.At - Start).TotalSeconds));
        Assert.True(history.Version > version);
    }

    [Fact]
    public void Jitter_is_the_mean_change_between_consecutive_answers()
    {
        var history = new BoostHistory();
        history.Add(At(0, 40));
        history.Add(At(3, 50));
        history.Add(At(6, null));   // skipped, not counted as a jump to or from nothing
        history.Add(At(9, 44));

        Assert.Equal((10 + 6) / 2.0, history.RouteJitter);
        Assert.Equal((40 + 50 + 44) / 3.0, history.RouteAverage);
        Assert.Equal(0, history.DirectJitter);
    }

    [Fact]
    public void One_answer_has_no_jitter_yet()
    {
        var history = new BoostHistory();
        history.Add(At(0, 40));

        Assert.Null(history.RouteJitter);
    }

    [Fact]
    public void Loss_buckets_sit_on_multiples_of_their_width()
    {
        // Aligned to the clock rather than to the latest sample, so a bar does not shift a
        // little at every tick.
        var history = new BoostHistory();
        history.Add(At(25, 45));   // 20:00:00 – 20:00:30
        history.Add(At(28, null));
        history.Add(At(31, 46));   // 20:00:30 – 20:01:00
        history.Add(At(34, 46));
        history.Add(At(61, null)); // 20:01:00 – 20:01:30

        var buckets = history.RouteLossBuckets(TimeSpan.FromSeconds(30));

        Assert.Equal([Start, Start.AddSeconds(30), Start.AddSeconds(60)], buckets.Select(b => b.Start));
        Assert.Equal([(2, 1), (2, 0), (1, 1)], buckets.Select(b => (b.Probes, b.Lost)));
        Assert.Equal([50.0, 0, 100], buckets.Select(b => b.Percent));
    }

    [Fact]
    public void Clearing_forgets_when_the_route_first_answered()
    {
        var history = new BoostHistory();
        history.Add(At(0, 45));

        history.Clear();
        history.Add(At(3, null));

        Assert.False(history.RouteHasAnswered);
        Assert.Null(history.RouteLossPercent);
    }

    [Theory]
    [InlineData(117, 150, 50)]  // not 200, which left the top two fifths of the panel empty
    [InlineData(48, 60, 20)]
    [InlineData(9, 10, 2.5)]
    [InlineData(260, 300, 100)]
    public void The_latency_axis_tops_out_at_the_next_round_step(double peak, double top, double step)
    {
        Assert.Equal((top, step), BoostChart.NiceScale(peak));
    }
}
