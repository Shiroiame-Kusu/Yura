using System.Net;
using System.Net.Sockets;
using System.Text;
using Yura.Core.Agent;

namespace Yura.Agent.Tests;

/// <summary>
/// End-to-end tests of the agent: a real server, a real client, real sockets.
/// </summary>
/// <remarks>
/// These are the tests that decide whether the protocol works. Everything else about the
/// agent — the CLI, the unit file, the policy — can be read and reasoned about; whether a
/// flow actually arrives at the other end cannot.
/// </remarks>
public sealed class AgentServerTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_tcp_flow_reaches_its_destination_through_the_agent()
    {
        await using var harness = AgentHarness.Start();
        using var destination = new EchoServer();

        await using var stream = await AgentClient.OpenStreamAsync(
            harness.Client(), AgentAddress.From(destination.EndPoint), Token);

        // Past the Opened frame the connection is the tunnel itself, so this is the
        // application's own bytes with nothing wrapped around them.
        await stream.Stream.WriteAsync(Encoding.UTF8.GetBytes("hello agent"), Token);
        await stream.Stream.FlushAsync(Token);

        var buffer = new byte[64];
        await stream.Stream.ReadExactlyAsync(buffer.AsMemory(0, "hello agent".Length), Token);
        Assert.Equal("hello agent", Encoding.UTF8.GetString(buffer, 0, "hello agent".Length));

        // The agent reports what the destination sees as the source, and its own connect time.
        Assert.StartsWith("127.0.0.1:", stream.Opened.LocalEndpoint, StringComparison.Ordinal);
        Assert.True(stream.Opened.ConnectMicroseconds > 0);
    }

    [Fact]
    public async Task A_destination_that_answers_and_closes_ends_the_stream_at_the_client_too()
    {
        // The bug this exists for: the reply arrived and the end of it never did, so every
        // client that reads to end-of-stream — which is most of them, and every HTTP client
        // with "Connection: close" — waited for its own timeout and then reported a failure,
        // having had the answer in hand all along.
        await using var harness = AgentHarness.Start();
        using var destination = new OneShotServer("HTTP/1.1 200 OK\r\n\r\nMARKER");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            await using var stream = await AgentClient.OpenStreamAsync(
                harness.Client(), AgentAddress.From(destination.EndPoint), Token);

            await stream.Stream.WriteAsync(Encoding.UTF8.GetBytes("GET / HTTP/1.1\r\n\r\n"), Token);
            await stream.Stream.FlushAsync(Token);

            // Reads to the end, and never closes its own sending half — exactly what an
            // ordinary client does, and what makes the missing end of stream fatal.
            var body = new MemoryStream();
            var buffer = new byte[4096];
            while (true)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                int read;
                try
                {
                    read = await stream.Stream.ReadAsync(buffer, timeout.Token);
                }
                catch (OperationCanceledException) when (!Token.IsCancellationRequested)
                {
                    Assert.Fail($"attempt {attempt}: the stream never ended; {body.Length} byte(s) arrived");
                    return;
                }

                if (read == 0)
                {
                    break;
                }

                body.Write(buffer, 0, read);
            }

            Assert.Contains("MARKER", Encoding.UTF8.GetString(body.ToArray()), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_half_close_is_carried_through_to_the_destination()
    {
        // A protocol that says everything and then waits — a login handshake, HTTP without
        // keepalive — hangs forever if the end of the request is not carried through. TLS 1.3
        // can signal it, which an HTTPS proxy cannot.
        await using var harness = AgentHarness.Start();
        using var destination = new EchoServer();

        await using var stream = await AgentClient.OpenStreamAsync(
            harness.Client(), AgentAddress.From(destination.EndPoint), Token);

        await stream.Stream.WriteAsync(Encoding.UTF8.GetBytes("question"), Token);
        await stream.Stream.FlushAsync(Token);
        var buffer = new byte[64];
        await stream.Stream.ReadExactlyAsync(buffer.AsMemory(0, "question".Length), Token);

        await stream.Stream.ShutdownAsync();

        await destination.SawEndOfStream.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

        // And the answer that came after the half close still arrives.
        await stream.Stream.ReadExactlyAsync(buffer.AsMemory(0, 3), Token);
        Assert.Equal("bye", Encoding.UTF8.GetString(buffer, 0, 3));
    }

    [Fact]
    public async Task A_token_that_does_not_match_relays_nothing()
    {
        await using var harness = AgentHarness.Start();
        using var destination = new EchoServer();

        var wrong = harness.Client() with
        {
            Token = AgentConnection.Encode(new byte[AgentProtocol.TokenBytes]),
        };

        var refused = await Assert.ThrowsAsync<AgentRefusedException>(() =>
            AgentClient.OpenStreamAsync(wrong, AgentAddress.From(destination.EndPoint), Token));

        Assert.Equal(AgentRejection.Unauthorised, refused.Code);
        // The refusal says nothing about the token beyond that it was not accepted.
        Assert.DoesNotContain("token is", refused.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_agent_whose_key_is_not_the_pinned_one_is_refused_by_the_client()
    {
        // The check that makes a certificate authority unnecessary: the client trusts one key
        // and nothing else, so a substituted server fails before a byte is relayed.
        await using var harness = AgentHarness.Start();
        using var destination = new EchoServer();

        var elsewhere = harness.Client() with
        {
            Fingerprint = AgentConnection.Encode(new byte[32]),
        };

        var problem = await Assert.ThrowsAsync<AgentProtocolException>(() =>
            AgentClient.OpenStreamAsync(elsewhere, AgentAddress.From(destination.EndPoint), Token));

        Assert.Contains("not the one this exit was configured with", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_private_destination_is_refused_unless_the_agent_was_told_otherwise()
    {
        // The default: a token holder can accelerate a game and cannot use the agent as a way
        // into the server's own network.
        await using var harness = AgentHarness.Start(policy: DestinationPolicy.Default);
        using var destination = new EchoServer();

        var refused = await Assert.ThrowsAsync<AgentRefusedException>(() =>
            AgentClient.OpenStreamAsync(harness.Client(), AgentAddress.From(destination.EndPoint), Token));

        Assert.Equal(AgentRejection.DestinationRefused, refused.Code);
        Assert.Contains("private or loopback", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_destination_outside_the_allowed_ports_is_refused()
    {
        using var destination = new EchoServer();
        await using var harness = AgentHarness.Start(policy: new DestinationPolicy
        {
            AllowPrivate = true,
            Ports = [new Core.Net.PortRange(27015, 27050)],
        });

        var refused = await Assert.ThrowsAsync<AgentRefusedException>(() =>
            AgentClient.OpenStreamAsync(harness.Client(), AgentAddress.From(destination.EndPoint), Token));

        Assert.Equal(AgentRejection.DestinationRefused, refused.Code);
    }

    [Fact]
    public async Task A_destination_that_is_not_listening_is_reported_as_such()
    {
        await using var harness = AgentHarness.Start();

        // Port 1 on loopback: reachable network, nothing behind it.
        var refused = await Assert.ThrowsAsync<AgentRefusedException>(() =>
            AgentClient.OpenStreamAsync(harness.Client(), new AgentAddress("127.0.0.1", 1), Token));

        Assert.Equal(AgentRejection.ConnectFailed, refused.Code);
        Assert.Contains("could not reach", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_session_reports_what_the_agent_is_and_what_it_offers()
    {
        await using var harness = AgentHarness.Start();
        await using var session = await harness.SessionAsync(Token);

        Assert.Equal("test-agent", session.AgentName);
        Assert.True(session.Welcome.Available.HasFlag(AgentProtocol.Features.Udp));
        Assert.True(session.UdpAvailable);
        Assert.True(session.IsOpen);
        Assert.Null(session.Failure);
    }

    [Fact]
    public async Task An_agent_started_without_udp_says_so_rather_than_failing_later()
    {
        await using var harness = AgentHarness.Start(udp: false);
        await using var session = await harness.SessionAsync(Token);

        Assert.False(session.Welcome.Available.HasFlag(AgentProtocol.Features.Udp));
        Assert.False(session.UdpAvailable);
        Assert.Null(await session.EchoAsync(Token));

        // TCP still works: an agent without UDP is degraded, not useless.
        using var destination = new EchoServer();
        await using var stream = await AgentClient.OpenStreamAsync(
            harness.Client(), AgentAddress.From(destination.EndPoint), Token);
        Assert.NotNull(stream.Opened);
    }

    [Fact]
    public async Task The_datagram_path_is_proved_by_a_round_trip_of_its_own()
    {
        // Nothing external is involved, so this answers "does UDP reach this agent at all"
        // without depending on a third party being up.
        await using var harness = AgentHarness.Start();
        await using var session = await harness.SessionAsync(Token);

        var elapsed = await session.EchoAsync(Token);

        Assert.NotNull(elapsed);
        Assert.True(elapsed >= TimeSpan.Zero);
    }

    [Fact]
    public async Task A_udp_flow_reaches_its_destination_through_the_agent()
    {
        await using var harness = AgentHarness.Start();
        using var destination = new UdpEchoServer();
        await using var session = await harness.SessionAsync(Token);

        var answers = new List<string>();
        var arrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var channel = session.OpenChannel((_, payload) =>
        {
            lock (answers)
            {
                answers.Add(Encoding.UTF8.GetString(payload.Span));
            }

            arrived.TrySetResult();
        });

        await session.SendDatagramAsync(channel, destination.EndPoint, Encoding.UTF8.GetBytes("ping"), Token);
        await arrived.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

        lock (answers)
        {
            Assert.Equal("ping", Assert.Single(answers));
        }

        // It arrived from the agent, not from here.
        var seen = Assert.Single(destination.Snapshot());
        Assert.Equal("ping", seen.Text);
        Assert.NotEqual(session.Welcome.DatagramPort, seen.From.Port);
    }

    [Fact]
    public async Task One_channel_keeps_one_source_port_at_the_destination()
    {
        // Some game servers tie session state to the source port, so a channel that changed
        // ports between packets would look like a new client each time.
        await using var harness = AgentHarness.Start();
        using var destination = new UdpEchoServer();
        await using var session = await harness.SessionAsync(Token);

        var arrived = 0;
        var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var channel = session.OpenChannel((_, _) =>
        {
            if (Interlocked.Increment(ref arrived) == 2)
            {
                both.TrySetResult();
            }
        });

        await session.SendDatagramAsync(channel, destination.EndPoint, Encoding.UTF8.GetBytes("one"), Token);
        await session.SendDatagramAsync(channel, destination.EndPoint, Encoding.UTF8.GetBytes("two"), Token);
        await both.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

        var seen = destination.Snapshot();
        Assert.Equal(2, seen.Count);
        Assert.Equal(seen[0].From.Port, seen[1].From.Port);
    }

    [Fact]
    public async Task Two_channels_are_two_conversations()
    {
        await using var harness = AgentHarness.Start();
        using var first = new UdpEchoServer();
        using var second = new UdpEchoServer();
        await using var session = await harness.SessionAsync(Token);

        var answers = new System.Collections.Concurrent.ConcurrentDictionary<ushort, string>();
        var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        ushort one = 0;
        ushort two = 0;
        one = session.OpenChannel((_, payload) =>
        {
            answers[one] = Encoding.UTF8.GetString(payload.Span);
            if (answers.Count == 2)
            {
                both.TrySetResult();
            }
        });
        two = session.OpenChannel((_, payload) =>
        {
            answers[two] = Encoding.UTF8.GetString(payload.Span);
            if (answers.Count == 2)
            {
                both.TrySetResult();
            }
        });

        await session.SendDatagramAsync(one, first.EndPoint, Encoding.UTF8.GetBytes("first"), Token);
        await session.SendDatagramAsync(two, second.EndPoint, Encoding.UTF8.GetBytes("second"), Token);
        await both.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);

        Assert.Equal("first", answers[one]);
        Assert.Equal("second", answers[two]);
        Assert.NotEqual(one, two);
    }

    [Fact]
    public async Task Rubbish_sent_to_the_datagram_port_is_ignored()
    {
        // The port is on the internet, so it will be scanned and probed. Nothing about it may
        // answer, and nothing about it may fall over.
        await using var harness = AgentHarness.Start();
        await using var session = await harness.SessionAsync(Token);

        using var stranger = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var agentDatagrams = new IPEndPoint(IPAddress.Loopback, session.Welcome.DatagramPort);
        for (var i = 0; i < 5; i++)
        {
            await stranger.SendToAsync(new byte[64 + i], SocketFlags.None, agentDatagrams, Token);
        }

        // Nothing comes back, and the session still works afterwards.
        stranger.ReceiveTimeout = 200;
        Assert.NotNull(await session.EchoAsync(Token));
    }

    [Fact]
    public async Task A_probe_reports_the_round_trip_from_where_the_agent_is()
    {
        await using var harness = AgentHarness.Start();
        using var destination = new EchoServer();
        await using var session = await harness.SessionAsync(Token);

        var reply = await session.ProbeAsync(AgentAddress.From(destination.EndPoint), 3, Token);

        Assert.Null(reply.Failure);
        Assert.Equal(3, reply.Microseconds.Length);
        Assert.Equal(destination.EndPoint.ToString(), reply.Resolved);
    }

    /// <summary>
    /// A listener whose accept queue is full, so the kernel drops every further connection
    /// attempt: a destination that does not answer, without leaving loopback.
    /// </summary>
    private sealed class Blackhole : IDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly List<Socket> _queued = [];

        public Blackhole()
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(1);
            for (var i = 0; i < 4; i++)
            {
                var filler = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                _queued.Add(filler);
                using var wait = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
                try
                {
                    filler.ConnectAsync(EndPoint, wait.Token).AsTask().GetAwaiter().GetResult();
                }
                catch (OperationCanceledException)
                {
                    // The queue is full: this one is the first to be dropped.
                }
            }
        }

        public IPEndPoint EndPoint => (IPEndPoint)_listener.LocalEndPoint!;

        public void Dispose()
        {
            foreach (var socket in _queued)
            {
                socket.Dispose();
            }

            _listener.Dispose();
        }
    }

    [Fact]
    public async Task A_probe_slower_than_the_session_timeout_leaves_the_session_open()
    {
        // Every sample of a destination that drops connection attempts waits out the agent's
        // connect timeout. The session's ordinary timeout was applied to the whole probe, and
        // when it ran out the session closed — taking every UDP flow through the agent with it.
        await using var harness = AgentHarness.Start();
        using var blackhole = new Blackhole();
        await using var session = await AgentSession.ConnectAsync(
            harness.Client() with { Timeout = TimeSpan.FromSeconds(1) }, Token);

        var probing = session.ProbeAsync(AgentAddress.From(blackhole.EndPoint), 1, Token);

        // And the agent goes on answering while it measures: a request behind the probe would
        // have waited for it, and timed out.
        var stats = await session.StatsAsync(Token);
        Assert.False(probing.IsCompleted);

        var reply = await probing;
        Assert.Empty(reply.Microseconds);
        Assert.NotNull(reply.Failure);
        Assert.True(session.IsOpen, session.Failure);
        Assert.True(stats.Sessions >= 1);
    }

    [Fact]
    public async Task A_probe_of_something_unreachable_says_so_instead_of_reporting_zero()
    {
        await using var harness = AgentHarness.Start();
        await using var session = await harness.SessionAsync(Token);

        var reply = await session.ProbeAsync(new AgentAddress("127.0.0.1", 1), 2, Token);

        Assert.Empty(reply.Microseconds);
        Assert.NotNull(reply.Failure);
    }

    [Fact]
    public async Task A_probe_obeys_the_same_policy_as_a_flow()
    {
        // Otherwise the probe would be a port scanner for the server's own network.
        await using var harness = AgentHarness.Start(policy: DestinationPolicy.Default);
        using var destination = new EchoServer();
        await using var session = await harness.SessionAsync(Token);

        var reply = await session.ProbeAsync(AgentAddress.From(destination.EndPoint), 2, Token);

        Assert.Empty(reply.Microseconds);
        Assert.Contains("private or loopback", reply.Failure ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_ping_measures_the_control_connection()
    {
        await using var harness = AgentHarness.Start();
        await using var session = await harness.SessionAsync(Token);

        var elapsed = await session.PingAsync(Token);

        Assert.True(elapsed >= TimeSpan.Zero);
        Assert.Equal(elapsed, session.LastRoundTrip);
    }

    [Fact]
    public async Task Stats_say_what_the_agent_is_carrying()
    {
        await using var harness = AgentHarness.Start();
        using var destination = new EchoServer();
        await using var session = await harness.SessionAsync(Token);

        await using var stream = await AgentClient.OpenStreamAsync(
            harness.Client(), AgentAddress.From(destination.EndPoint), Token);
        await stream.Stream.WriteAsync(Encoding.UTF8.GetBytes("counted"), Token);
        await stream.Stream.FlushAsync(Token);
        var buffer = new byte[32];
        await stream.Stream.ReadExactlyAsync(buffer.AsMemory(0, "counted".Length), Token);

        var stats = await session.StatsAsync(Token);

        Assert.Equal(1u, stats.Sessions);
        Assert.Equal(1u, stats.Streams);
        Assert.True(stats.BytesUp >= 7);
        Assert.True(stats.BytesDown >= 7);
    }

    [Fact]
    public async Task Stats_count_the_destinations_the_policy_turned_away()
    {
        using var destination = new EchoServer();
        await using var harness = AgentHarness.Start(policy: DestinationPolicy.Default);
        await using var session = await harness.SessionAsync(Token);

        await Assert.ThrowsAsync<AgentRefusedException>(() =>
            AgentClient.OpenStreamAsync(harness.Client(), AgentAddress.From(destination.EndPoint), Token));

        // A game that will not work through an agent whose policy forbids its servers looks
        // like a network fault; this is what shows it is not one.
        Assert.Equal(1u, (await session.StatsAsync(Token)).Refused);
    }

    [Fact]
    public async Task A_session_notices_when_the_agent_goes_away()
    {
        var harness = AgentHarness.Start();
        var session = await harness.SessionAsync(Token);
        var closed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        session.Closed += reason => closed.TrySetResult(reason);

        await harness.DisposeAsync();

        var reason = await closed.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);
        Assert.False(session.IsOpen);
        Assert.Equal(reason, session.Failure);
        await session.DisposeAsync();
    }

    [Fact]
    public async Task A_client_that_sends_something_other_than_a_hello_is_dropped()
    {
        await using var harness = AgentHarness.Start();

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, harness.Server.Port), Token);
        await socket.SendAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Token);

        // Not a TLS client hello, so the handshake fails and the connection ends. The agent
        // stays up, which is the part that matters.
        var buffer = new byte[16];
        var read = await socket.ReceiveAsync(buffer, Token);
        Assert.Equal(0, read);

        await using var session = await harness.SessionAsync(Token);
        Assert.True(session.IsOpen);
    }

    [Fact]
    public async Task The_agent_holds_to_its_session_limit()
    {
        await using var harness = AgentHarness.Start();
        var server = new AgentServer(
            new AgentOptions { Listen = IPAddress.Loopback, Port = 0, MaxSessions = 1 },
            harness.Identity,
            _ => { });
        server.Start();

        await using (server.ConfigureAwait(false))
        {
            var options = harness.Client() with { Port = server.Port };
            await using var first = await AgentSession.ConnectAsync(options, Token);

            var refused = await Assert.ThrowsAsync<AgentRefusedException>(() =>
                AgentSession.ConnectAsync(options, Token));
            Assert.Equal(AgentRejection.TooMany, refused.Code);
        }
    }
}
