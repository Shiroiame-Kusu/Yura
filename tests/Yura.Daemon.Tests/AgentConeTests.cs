using System.Net;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Tests;

/// <summary>
/// The daemon's half of a full-cone agent channel: which flow hears what, and when the channel
/// lets go.
/// </summary>
/// <remarks>
/// Routing by sender is what decides whether a peer's datagram reaches the game as that peer,
/// reaches it as somebody else, or opens a flow of its own; getting it wrong is a game that
/// hears its peers under the wrong names. The listener around it needs root, so the routing is
/// pinned here on its own.
/// </remarks>
public sealed class AgentConeTests
{
    private static readonly IPEndPoint Game = IPEndPoint.Parse("192.168.1.24:51820");
    private static readonly IPEndPoint Matchmaker = IPEndPoint.Parse("203.0.113.10:3478");
    private static readonly IPEndPoint Peer = IPEndPoint.Parse("198.51.100.7:61000");

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => Now;

        public override long GetTimestamp() => Now.UtcTicks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }

    private sealed class Route : IConeRoute
    {
        public List<string> Heard { get; } = [];

        public void Answer(ReadOnlyMemory<byte> payload) => Heard.Add(System.Text.Encoding.UTF8.GetString(payload.Span));
    }

    private sealed class Fixture
    {
        public List<(IPEndPoint Target, string Text)> Sent { get; } = [];

        public List<(IPEndPoint From, string Text)> Unsolicited { get; } = [];

        public int Closes { get; set; }

        public bool Alive { get; set; } = true;

        public ManualTime Time { get; } = new();

        public AgentCone Cone { get; }

        public Fixture()
        {
            Cone = new AgentCone(
                owner: this,
                Game,
                plan: null,
                send: (target, payload, _) =>
                {
                    Sent.Add((target, System.Text.Encoding.UTF8.GetString(payload.Span)));
                    return Task.CompletedTask;
                },
                close: () => Closes++,
                alive: () => Alive,
                unsolicited: (_, from, payload) =>
                    Unsolicited.Add((from, System.Text.Encoding.UTF8.GetString(payload.Span))),
                Time);
        }
    }

    private static ReadOnlyMemory<byte> Bytes(string text) => System.Text.Encoding.UTF8.GetBytes(text);

    [Fact]
    public void What_arrives_from_an_address_goes_to_the_flow_that_sends_there()
    {
        var fixture = new Fixture();
        var toMatchmaker = new Route();
        var toPeer = new Route();
        fixture.Cone.Attach(Matchmaker, toMatchmaker);
        fixture.Cone.Attach(Peer, toPeer);

        fixture.Cone.Receive(Matchmaker, Bytes("you are 203.0.113.99:40123"));
        fixture.Cone.Receive(Peer, Bytes("hello"));

        Assert.Equal(["you are 203.0.113.99:40123"], toMatchmaker.Heard);
        Assert.Equal(["hello"], toPeer.Heard);
        Assert.Empty(fixture.Unsolicited);
    }

    [Fact]
    public void A_peer_nobody_sends_to_is_handed_over_as_unsolicited()
    {
        // Another player, told the game's address by the matchmaker, writing first.
        var fixture = new Fixture();
        fixture.Cone.Attach(Matchmaker, new Route());

        fixture.Cone.Receive(Peer, Bytes("join me"));

        Assert.Equal((Peer, "join me"), Assert.Single(fixture.Unsolicited));
    }

    [Fact]
    public void A_flow_that_ends_takes_only_its_own_route_with_it()
    {
        // A flow that ended after another took its address over must not unhook the newer one.
        var fixture = new Fixture();
        var older = new Route();
        var newer = new Route();
        fixture.Cone.Attach(Peer, older);
        fixture.Cone.Attach(Peer, newer);

        fixture.Cone.Detach(Peer, older);
        fixture.Cone.Receive(Peer, Bytes("still here"));

        Assert.Empty(older.Heard);
        Assert.Equal(["still here"], newer.Heard);

        fixture.Cone.Detach(Peer, newer);
        fixture.Cone.Receive(Peer, Bytes("anyone?"));
        Assert.Equal((Peer, "anyone?"), Assert.Single(fixture.Unsolicited));
    }

    [Fact]
    public async Task Only_the_applications_own_sending_keeps_the_channel()
    {
        var fixture = new Fixture();
        fixture.Cone.Attach(Peer, new Route());

        fixture.Time.Now += TimeSpan.FromMinutes(3);
        fixture.Cone.Receive(Peer, Bytes("a peer talking"));
        Assert.Equal(TimeSpan.FromMinutes(3), fixture.Cone.SinceLastSent);

        await fixture.Cone.SendAsync(Peer, Bytes("the game talking"), CancellationToken.None);
        Assert.Equal(TimeSpan.Zero, fixture.Cone.SinceLastSent);
        Assert.Equal((Peer, "the game talking"), Assert.Single(fixture.Sent));
    }

    [Fact]
    public void A_closed_channel_hears_nothing_and_closes_once()
    {
        var fixture = new Fixture();
        var route = new Route();
        fixture.Cone.Attach(Peer, route);

        fixture.Cone.Close();
        fixture.Cone.Close();
        fixture.Cone.Receive(Peer, Bytes("late"));
        fixture.Cone.Receive(Matchmaker, Bytes("later"));

        Assert.Equal(1, fixture.Closes);
        Assert.Empty(route.Heard);
        Assert.Empty(fixture.Unsolicited);
        Assert.False(fixture.Cone.IsAlive);
    }

    [Fact]
    public void A_channel_whose_agent_session_has_gone_is_not_alive()
    {
        var fixture = new Fixture();
        Assert.True(fixture.Cone.IsAlive);

        fixture.Alive = false;

        Assert.False(fixture.Cone.IsAlive);
    }

    [Fact]
    public void The_daemon_lets_a_channel_go_before_the_agent_does()
    {
        // Sending on a channel the agent had already closed would quietly open a new socket
        // there, with a new port, under the address the game's peers still hold.
        Assert.True(TransparentUdpListener.ConeIdleTimeout < Yura.Core.Agent.AgentProtocol.ConeMappingLifetime);
        Assert.True(TransparentUdpListener.ConeIdleTimeout >= TimeSpan.FromMinutes(2), "RFC 4787 asks for two minutes at least");
    }
}
