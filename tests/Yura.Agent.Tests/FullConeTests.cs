using System.Net;
using System.Net.Sockets;
using System.Text;
using Yura.Core.Agent;

namespace Yura.Agent.Tests;

/// <summary>
/// Full-cone UDP through a real agent: what a peer-to-peer game needs from a route.
/// </summary>
/// <remarks>
/// Two properties, which together are what a game calls an Open NAT: every peer sees the game at
/// one address (endpoint-independent mapping), and a peer the game never sent to can still reach
/// it there (endpoint-independent filtering). Without them — a socket per destination — a game's
/// peers each see a different port and nobody new gets in, which is a Strict NAT.
/// </remarks>
public sealed class FullConeTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private static Task<AgentSession> ConeSessionAsync(AgentHarness harness) =>
        AgentSession.ConnectAsync(harness.Client() with { FullCone = true }, Token);

    /// <summary>Collects what a channel hears, with who it came from.</summary>
    private sealed class Heard
    {
        private readonly List<(IPEndPoint From, string Text)> _heard = [];
        private TaskCompletionSource _next = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Add(IPEndPoint from, ReadOnlyMemory<byte> payload)
        {
            lock (_heard)
            {
                _heard.Add((from, Encoding.UTF8.GetString(payload.Span)));
                _next.TrySetResult();
            }
        }

        public async Task<(IPEndPoint From, string Text)> WaitForAsync(string text)
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (true)
            {
                Task next;
                lock (_heard)
                {
                    foreach (var item in _heard)
                    {
                        if (item.Text == text)
                        {
                            return item;
                        }
                    }

                    _next = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    next = _next.Task;
                }

                var left = deadline - DateTime.UtcNow;
                if (left <= TimeSpan.Zero)
                {
                    throw new TimeoutException($"nothing saying '{text}' arrived");
                }

                await next.WaitAsync(left, Token).ContinueWith(_ => { }, TaskScheduler.Default);
            }
        }

        public bool Contains(string text)
        {
            lock (_heard)
            {
                return _heard.Any(h => h.Text == text);
            }
        }
    }

    [Fact]
    public async Task An_agent_grants_full_cone_to_a_client_that_asks()
    {
        await using var harness = AgentHarness.Start();
        await using var asked = await ConeSessionAsync(harness);
        await using var didNotAsk = await harness.SessionAsync(Token);

        Assert.True(asked.FullCone);
        Assert.False(didNotAsk.FullCone);
        Assert.Throws<AgentProtocolException>(() => didNotAsk.OpenChannel((_, _) => { }, fullCone: true));
    }

    [Fact]
    public async Task An_agent_started_without_full_cone_does_not_grant_it()
    {
        await using var harness = AgentHarness.Start(fullCone: false);
        await using var session = await ConeSessionAsync(harness);

        Assert.True(session.UdpAvailable);
        Assert.False(session.FullCone);
    }

    [Fact]
    public async Task Every_destination_sees_one_address_for_a_full_cone_channel()
    {
        // The address a matchmaking server sees is the address the other players are told, so
        // it has to be the address they see too.
        await using var harness = AgentHarness.Start();
        using var matchmaker = new UdpEchoServer();
        using var player = new UdpEchoServer();
        await using var session = await ConeSessionAsync(harness);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add, fullCone: true);

        await session.SendDatagramAsync(channel, matchmaker.EndPoint, "hello matchmaker"u8.ToArray(), Token);
        await session.SendDatagramAsync(channel, player.EndPoint, "hello player"u8.ToArray(), Token);

        // Each answer is labelled with the address it really came from.
        Assert.Equal(matchmaker.EndPoint, (await heard.WaitForAsync("hello matchmaker")).From);
        Assert.Equal(player.EndPoint, (await heard.WaitForAsync("hello player")).From);

        var seenByMatchmaker = Assert.Single(matchmaker.Snapshot()).From;
        var seenByPlayer = Assert.Single(player.Snapshot()).From;
        Assert.Equal(seenByMatchmaker, seenByPlayer);
        Assert.True(AgentHarness.TestConePorts.Contains((ushort)seenByMatchmaker.Port), seenByMatchmaker.ToString());
    }

    [Fact]
    public async Task A_peer_the_game_never_sent_to_can_reach_it()
    {
        // The case all of this exists for: another player, told the game's address by the
        // matchmaker, sends to it first.
        await using var harness = AgentHarness.Start();
        using var matchmaker = new UdpEchoServer();
        await using var session = await ConeSessionAsync(harness);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add, fullCone: true);

        await session.SendDatagramAsync(channel, matchmaker.EndPoint, "register"u8.ToArray(), Token);
        await heard.WaitForAsync("register");
        var advertised = Assert.Single(matchmaker.Snapshot()).From;

        using var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        stranger.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await stranger.SendToAsync("join me"u8.ToArray(), SocketFlags.None, advertised, Token);

        var knock = await heard.WaitForAsync("join me");
        Assert.Equal(stranger.LocalEndPoint, knock.From);

        // And the game can answer it on the same channel, from the same address.
        var buffer = new byte[64];
        await session.SendDatagramAsync(channel, (IPEndPoint)stranger.LocalEndPoint!, "welcome"u8.ToArray(), Token);
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(Token);
        wait.CancelAfter(TimeSpan.FromSeconds(5));
        var answer = await stranger.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), wait.Token);
        Assert.Equal("welcome", Encoding.UTF8.GetString(buffer, 0, answer.ReceivedBytes));
        Assert.Equal(advertised, answer.RemoteEndPoint);
    }

    [Fact]
    public async Task Without_full_cone_each_destination_gets_its_own_port_and_strangers_stay_out()
    {
        // The ordinary channel, unchanged: what a game calls a Strict NAT, and still what a
        // session gets when it does not ask.
        await using var harness = AgentHarness.Start();
        using var matchmaker = new UdpEchoServer();
        using var player = new UdpEchoServer();
        await using var session = await harness.SessionAsync(Token);
        var heard = new Heard();
        var toMatchmaker = session.OpenChannel(heard.Add);
        var toPlayer = session.OpenChannel(heard.Add);

        await session.SendDatagramAsync(toMatchmaker, matchmaker.EndPoint, "hello matchmaker"u8.ToArray(), Token);
        await session.SendDatagramAsync(toPlayer, player.EndPoint, "hello player"u8.ToArray(), Token);
        await heard.WaitForAsync("hello matchmaker");
        await heard.WaitForAsync("hello player");

        var advertised = Assert.Single(matchmaker.Snapshot()).From;
        Assert.NotEqual(advertised, Assert.Single(player.Snapshot()).From);

        using var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        await stranger.SendToAsync("join me"u8.ToArray(), SocketFlags.None, advertised, Token);
        await Task.Delay(300, Token);
        Assert.False(heard.Contains("join me"));
    }

    [Fact]
    public async Task The_policy_holds_for_who_may_send_in()
    {
        // The agent's own network cannot write into a client's game any more than the client
        // can reach into that network: a sender the policy refuses is dropped.
        await using var harness = AgentHarness.Start(policy: new DestinationPolicy
        {
            AllowPrivate = true,
            Denied = [IPNetwork.Parse("127.0.0.2/32")],
        });
        using var matchmaker = new UdpEchoServer();
        await using var session = await ConeSessionAsync(harness);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add, fullCone: true);
        await session.SendDatagramAsync(channel, matchmaker.EndPoint, "register"u8.ToArray(), Token);
        await heard.WaitForAsync("register");
        var advertised = Assert.Single(matchmaker.Snapshot()).From;

        using var refused = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        refused.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
        await refused.SendToAsync("from a denied network"u8.ToArray(), SocketFlags.None, advertised, Token);

        using var allowed = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        allowed.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await allowed.SendToAsync("from anywhere else"u8.ToArray(), SocketFlags.None, advertised, Token);

        await heard.WaitForAsync("from anywhere else");
        Assert.False(heard.Contains("from a denied network"));
    }

    [Fact]
    public async Task A_full_range_falls_back_to_a_port_the_kernel_chooses()
    {
        // Still one address for every peer, so still endpoint-independent; only a firewall that
        // opens nothing but the range would keep strangers from it, and the agent says so.
        using var squatter = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        squatter.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var taken = (ushort)((IPEndPoint)squatter.LocalEndPoint!).Port;

        await using var harness = AgentHarness.Start(conePorts: new Core.Net.PortRange(taken, taken));
        using var matchmaker = new UdpEchoServer();
        await using var session = await ConeSessionAsync(harness);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add, fullCone: true);

        await session.SendDatagramAsync(channel, matchmaker.EndPoint, "register"u8.ToArray(), Token);
        await heard.WaitForAsync("register");

        Assert.NotEqual(taken, Assert.Single(matchmaker.Snapshot()).From.Port);
        Assert.Contains(harness.Log, line => line.Contains("every full-cone port", StringComparison.Ordinal));
    }
}
