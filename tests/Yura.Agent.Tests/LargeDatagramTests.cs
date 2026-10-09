using System.Net;
using System.Net.Sockets;
using System.Text;
using Yura.Core.Agent;

namespace Yura.Agent.Tests;

/// <summary>
/// Datagrams too large for one packet of the agent's channel, through a real agent.
/// </summary>
/// <remarks>
/// Helldivers 2 stuck at "Establishing up-link to host ship" behind an agent: the PlayFab Party
/// relay's certificate came in a datagram over the 1350 bytes the channel carries, the agent read
/// it into a 1350-byte buffer, and the game was handed the first 1350 bytes of it. A truncated
/// DTLS record is discarded, so the handshake never finished, relay after relay. Now such a
/// datagram travels in pieces to a client that takes them, and is dropped, never cut short, for
/// one that does not.
/// </remarks>
public sealed class LargeDatagramTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    /// <summary>A payload that says how long it is, so a truncated one cannot pass for whole.</summary>
    private static byte[] Payload(int length)
    {
        var text = new StringBuilder($"{length}:");
        while (text.Length < length)
        {
            text.Append((char)('a' + (text.Length % 26)));
        }

        return Encoding.ASCII.GetBytes(text.ToString(0, length));
    }

    /// <summary>Everything a channel hears, in order.</summary>
    private sealed class Heard
    {
        private readonly List<(IPEndPoint From, byte[] Payload)> _heard = [];
        private readonly SemaphoreSlim _arrived = new(0);

        public void Add(IPEndPoint from, ReadOnlyMemory<byte> payload)
        {
            lock (_heard)
            {
                _heard.Add((from, payload.ToArray()));
            }

            _arrived.Release();
        }

        public async Task<(IPEndPoint From, byte[] Payload)?> NextAsync(TimeSpan within)
        {
            if (!await _arrived.WaitAsync(within, Token))
            {
                return null;
            }

            lock (_heard)
            {
                var first = _heard[0];
                _heard.RemoveAt(0);
                return first;
            }
        }
    }

    private static async Task<(AgentSession Session, Heard Heard, ushort Channel, IPEndPoint Advertised, UdpEchoServer Matchmaker)>
        RegisteredAsync(AgentHarness harness, bool fragments)
    {
        var session = await AgentSession.ConnectAsync(harness.Client() with { FullCone = true, Fragments = fragments }, Token);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add, fullCone: true);
        var matchmaker = new UdpEchoServer();
        await session.SendDatagramAsync(channel, matchmaker.EndPoint, "register"u8.ToArray(), Token);
        Assert.NotNull(await heard.NextAsync(TimeSpan.FromSeconds(5)));
        return (session, heard, channel, Assert.Single(matchmaker.Snapshot()).From, matchmaker);
    }

    [Fact]
    public async Task An_agent_takes_pieces_from_a_client_that_asks_and_only_then()
    {
        await using var harness = AgentHarness.Start();
        await using var asked = await harness.SessionAsync(Token);
        await using var older = await AgentSession.ConnectAsync(harness.Client() with { Fragments = false }, Token);

        Assert.True(asked.Fragments);
        Assert.False(older.Fragments);
    }

    [Theory]
    [InlineData(1472)]
    [InlineData(4000)]
    public async Task A_datagram_too_large_for_one_packet_reaches_the_game_whole_from_a_peer(int length)
    {
        // The relay's certificate, as it reached Helldivers 2: a stranger's datagram at the
        // game's full-cone address, larger than the agent's channel carries in one packet.
        await using var harness = AgentHarness.Start();
        var (session, heard, _, advertised, matchmaker) = await RegisteredAsync(harness, fragments: true);
        await using var _session = session;
        using var _matchmaker = matchmaker;
        using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        var sent = Payload(length);
        await peer.SendToAsync(sent, SocketFlags.None, advertised, Token);

        var arrived = await heard.NextAsync(TimeSpan.FromSeconds(5));
        Assert.NotNull(arrived);
        Assert.Equal(peer.LocalEndPoint, arrived.Value.From);
        Assert.Equal(sent, arrived.Value.Payload);
        Assert.Equal(0, harness.Server.OversizeDropped);
    }

    [Fact]
    public async Task A_large_datagram_goes_out_and_its_large_answer_comes_back_on_an_ordinary_channel()
    {
        await using var harness = AgentHarness.Start();
        using var server = new UdpEchoServer();
        await using var session = await harness.SessionAsync(Token);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add);

        var sent = Payload(4000);
        await session.SendDatagramAsync(channel, server.EndPoint, sent, Token);

        var echoed = await heard.NextAsync(TimeSpan.FromSeconds(5));
        Assert.NotNull(echoed);
        Assert.Equal(sent, echoed.Value.Payload);
        Assert.Equal(Encoding.ASCII.GetString(sent), Assert.Single(server.Snapshot()).Text);
    }

    [Fact]
    public async Task The_largest_datagram_carried_goes_through_and_one_byte_more_is_refused_with_a_reason()
    {
        await using var harness = AgentHarness.Start();
        using var server = new UdpEchoServer();
        await using var session = await harness.SessionAsync(Token);
        var heard = new Heard();
        var channel = session.OpenChannel(heard.Add);

        var largest = Payload(AgentProtocol.MaxFragmentedPayload);
        await session.SendDatagramAsync(channel, server.EndPoint, largest, Token);
        Assert.Equal(largest, (await heard.NextAsync(TimeSpan.FromSeconds(5)))?.Payload);

        var e = await Assert.ThrowsAsync<AgentProtocolException>(() =>
            session.SendDatagramAsync(channel, server.EndPoint, Payload(AgentProtocol.MaxFragmentedPayload + 1), Token));
        Assert.Contains($"limit of {AgentProtocol.MaxFragmentedPayload}", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_client_that_cannot_take_pieces_is_sent_nothing_rather_than_a_datagram_cut_short()
    {
        await using var harness = AgentHarness.Start();
        var (session, heard, _, advertised, matchmaker) = await RegisteredAsync(harness, fragments: false);
        await using var _session = session;
        using var _matchmaker = matchmaker;
        using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        await peer.SendToAsync(Payload(1472), SocketFlags.None, advertised, Token);
        Assert.Null(await heard.NextAsync(TimeSpan.FromSeconds(1)));
        Assert.Equal(1, harness.Server.OversizeDropped);
        Assert.Contains(harness.Log, line => line.Contains("dropped a 1472-byte datagram", StringComparison.Ordinal));

        // And the channel carries on: the next datagram that fits arrives.
        var small = Payload(200);
        await peer.SendToAsync(small, SocketFlags.None, advertised, Token);
        Assert.Equal(small, (await heard.NextAsync(TimeSpan.FromSeconds(5)))?.Payload);

        // Nor does it send one it cannot take in one packet itself.
        await Assert.ThrowsAsync<AgentProtocolException>(() =>
            session.SendDatagramAsync(1, matchmaker.EndPoint, Payload(AgentProtocol.MaxDatagramPayload + 1), Token));
    }
}
