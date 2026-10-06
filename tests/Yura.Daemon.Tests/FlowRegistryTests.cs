using System.Net;
using Yura.Core.Connections;
using Yura.Core.Rules;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Tests;

/// <summary>
/// The registry of flows the daemon relays, and that it does not grow for as long as the
/// daemon runs.
/// </summary>
/// <remarks>
/// It used to shrink only when the Connections page listed it. The daemon runs as a service
/// for days with the app closed, and every connection and DNS lookup it relayed in that time
/// stayed in memory.
/// </remarks>
public sealed class FlowRegistryTests
{
    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => Now;

        public override long GetTimestamp() => Now.UtcTicks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }

    private static Flow NewFlow(int port = 50000) => new(
        new IPEndPoint(IPAddress.Parse("10.0.0.5"), port),
        new IPEndPoint(IPAddress.Parse("203.0.113.7"), 443),
        TransportProtocol.Tcp,
        Guid.NewGuid());

    [Fact]
    public void Finished_flows_leave_without_anyone_listing_them()
    {
        var time = new ManualTime();
        var registry = new FlowRegistry(time);
        var finished = NewFlow();
        finished.MarkClosed();
        registry.Add(finished);

        time.Now += TimeSpan.FromMinutes(2);
        registry.Add(NewFlow(50001));

        // Only the new arrival is left; nothing listed the registry in between.
        Assert.Equal(1, registry.Count);
    }

    [Fact]
    public void A_flow_kept_while_it_is_recent_is_still_shown_with_its_reason()
    {
        var time = new ManualTime();
        var registry = new FlowRegistry(time);
        var failed = NewFlow();
        failed.MarkFailed("The proxy refused the connection.");
        registry.Add(failed);

        time.Now += TimeSpan.FromSeconds(10);

        var shown = Assert.Single(registry.Snapshot());
        Assert.Equal("The proxy refused the connection.", shown.FailureReason);
    }

    [Fact]
    public void A_flow_whose_setup_never_finished_does_not_stay_forever()
    {
        // A flow whose setup threw used to stay "establishing" for the daemon's lifetime, and
        // counted as active in every status the app asked for.
        var time = new ManualTime();
        var registry = new FlowRegistry(time);
        registry.Add(NewFlow());
        Assert.Equal(1, registry.ActiveCount);

        time.Now += TimeSpan.FromMinutes(3);

        Assert.Equal(0, registry.ActiveCount);
        Assert.Empty(registry.Snapshot());
    }

    [Fact]
    public void A_burst_of_finished_flows_is_capped_whatever_their_age()
    {
        var registry = new FlowRegistry();
        for (var i = 0; i < 5000; i++)
        {
            var flow = NewFlow(i % 60000 + 1024);
            flow.MarkClosed();
            registry.Add(flow);
        }

        Assert.Equal(4096, registry.Snapshot().Count);
    }

    [Fact]
    public void A_live_flow_is_never_pruned()
    {
        var time = new ManualTime();
        var registry = new FlowRegistry(time);
        var live = NewFlow();
        live.MarkEstablished(RouteObservation.ConfirmedProxied);
        registry.Add(live);

        time.Now += TimeSpan.FromHours(6);

        Assert.Equal(1, registry.ActiveCount);
        Assert.Same(live, Assert.Single(registry.Snapshot()));
    }
}
