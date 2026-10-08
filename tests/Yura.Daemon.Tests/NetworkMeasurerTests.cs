using System.Net;
using System.Net.Sockets;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Tests;

/// <summary>
/// What counts as an answer when the daemon times a connect to a game's server.
/// </summary>
/// <remarks>
/// A refusal is an answer: the destination's own stack sent it, one round trip away. Game servers
/// mostly listen on UDP and refuse a TCP connect to their port, and counting those refusals as
/// loss showed a perfect route losing every probe.
/// </remarks>
public sealed class NetworkMeasurerTests
{
    private static Func<CancellationToken, Task> Throwing(Exception e) => async _ =>
    {
        await Task.Yield();
        throw e;
    };

    [Fact]
    public async Task A_refused_connect_is_an_answer_with_a_round_trip()
    {
        var set = await NetworkMeasurer.SampleAsync(
            2, Throwing(new SocketException((int)SocketError.ConnectionRefused)), CancellationToken.None);

        Assert.Equal(2, set.Successes);
        Assert.Equal(0, set.LossPercent);
        Assert.NotNull(set.LatencyMilliseconds);
        Assert.Null(set.FailureReason);
    }

    [Fact]
    public async Task A_closed_port_is_measured_rather_than_lost()
    {
        int port;
        using (var listener = new TcpListener(IPAddress.Loopback, 0))
        {
            listener.Start();
            port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        var set = await NetworkMeasurer.SampleAsync(1, async ct =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), ct);
        }, CancellationToken.None);

        Assert.Equal(1, set.Successes);
    }

    [Fact]
    public async Task The_destination_refusing_through_a_proxy_is_an_answer_too()
    {
        var set = await NetworkMeasurer.SampleAsync(
            1, Throwing(new DestinationRefusedException("refused")), CancellationToken.None);

        Assert.Equal(1, set.Successes);
    }

    [Fact]
    public async Task A_proxy_that_will_not_connect_is_loss_and_says_why()
    {
        var set = await NetworkMeasurer.SampleAsync(
            1, Throwing(new ProxyHandshakeException("The proxy's ruleset does not allow this connection.")),
            CancellationToken.None);

        Assert.Equal(0, set.Successes);
        Assert.Equal(100, set.LossPercent);
        Assert.Null(set.LatencyMilliseconds);
        Assert.Equal("The proxy's ruleset does not allow this connection.", set.FailureReason);
    }

    [Fact]
    public async Task An_unreachable_host_is_loss()
    {
        var set = await NetworkMeasurer.SampleAsync(
            1, Throwing(new SocketException((int)SocketError.HostUnreachable)), CancellationToken.None);

        Assert.Equal(0, set.Successes);
        Assert.Equal(nameof(SocketError.HostUnreachable), set.FailureReason);
    }

    /// <summary>A CONNECT through a SOCKS5 server on loopback that answers with <paramref name="reply"/>.</summary>
    private static async Task<Exception?> ConnectThroughProxyReplying(byte reply)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using var server = await listener.AcceptTcpClientAsync();

        var proxy = Task.Run(async () =>
        {
            var stream = server.GetStream();
            var buffer = new byte[16];
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 3));   // version, one method: none
            await stream.WriteAsync(new byte[] { 0x05, 0x00 });
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 10));  // CONNECT to an IPv4 address and port
            await stream.WriteAsync(new byte[] { 0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
        });

        try
        {
            await ProxyDialer.Socks5ConnectAsync(client.GetStream(), null, null, "203.0.113.50", 27015, CancellationToken.None);
            return null;
        }
        catch (Exception e)
        {
            return e;
        }
        finally
        {
            await proxy;
        }
    }

    [Fact]
    public async Task A_proxy_reporting_connection_refused_is_reporting_the_destination_answered()
    {
        var e = await ConnectThroughProxyReplying(0x05);

        Assert.IsType<DestinationRefusedException>(e);
        Assert.True(NetworkMeasurer.IsAnswer(e));
    }

    [Theory]
    [InlineData(0x02)] // not allowed by the proxy's own rules
    [InlineData(0x04)] // host unreachable
    [InlineData(0x06)] // timed out
    public async Task Any_other_refusal_from_the_proxy_is_not_an_answer(byte reply)
    {
        var e = await ConnectThroughProxyReplying(reply);

        Assert.IsType<ProxyHandshakeException>(e);
        Assert.False(NetworkMeasurer.IsAnswer(e));
    }

    [Fact]
    public async Task A_proxy_that_connects_raises_nothing()
    {
        Assert.Null(await ConnectThroughProxyReplying(0x00));
    }

    // -- proxies that answer before they connect ------------------------------------------

    private sealed class Opened : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Fact]
    public async Task A_proxy_that_says_a_closed_port_is_open_answers_before_connecting()
    {
        // mihomo does this: success at once, the dial afterwards. Its answer times loopback.
        IPEndPoint? asked = null;
        var early = await NetworkMeasurer.ProbeEarlyAnswerAsync((target, _) =>
        {
            asked = target;
            return Task.FromResult<IAsyncDisposable>(new Opened());
        }, CancellationToken.None);

        Assert.True(early);
        Assert.Equal(new IPEndPoint(IPAddress.Loopback, 1), asked);
    }

    [Theory]
    [InlineData(true)]  // the closed port, reported as refused
    [InlineData(false)] // the proxy's own rules refusing loopback
    public async Task A_proxy_that_reports_the_refusal_connects_first(bool destination)
    {
        var early = await NetworkMeasurer.ProbeEarlyAnswerAsync((_, _) => throw (destination
            ? new DestinationRefusedException("refused")
            : new ProxyHandshakeException("The proxy's ruleset does not allow this connection.")), CancellationToken.None);

        Assert.False(early);
    }

    [Fact]
    public async Task A_proxy_that_could_not_be_reached_teaches_nothing()
    {
        var early = await NetworkMeasurer.ProbeEarlyAnswerAsync(
            (_, _) => throw new SocketException((int)SocketError.ConnectionRefused), CancellationToken.None);

        Assert.Null(early);
    }
}
