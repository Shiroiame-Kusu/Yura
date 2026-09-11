using System.Net;
using System.Security.Cryptography;
using Yura.Core.Agent;

namespace Yura.Core.Tests;

/// <summary>
/// The wire format, checked at the level where a mistake is silent: a frame that decodes to
/// the wrong thing, or a datagram that is accepted when it should not be.
/// </summary>
public sealed class AgentProtocolTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_frame_survives_the_round_trip()
    {
        var stream = new MemoryStream();
        var payload = RandomNumberGenerator.GetBytes(1000);

        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Opened, payload, Token);
        stream.Position = 0;
        var (kind, read) = await AgentProtocol.ReadFrameAsync(stream, Token);

        Assert.Equal(AgentFrameKind.Opened, kind);
        Assert.Equal(payload, read);
    }

    [Fact]
    public async Task An_empty_frame_is_a_frame()
    {
        var stream = new MemoryStream();
        await AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Stats, ReadOnlyMemory<byte>.Empty, Token);
        stream.Position = 0;

        var (kind, payload) = await AgentProtocol.ReadFrameAsync(stream, Token);

        Assert.Equal(AgentFrameKind.Stats, kind);
        Assert.Empty(payload);
    }

    [Fact]
    public async Task An_oversized_frame_is_refused_at_both_ends()
    {
        var stream = new MemoryStream();
        await Assert.ThrowsAsync<AgentProtocolException>(() =>
            AgentProtocol.WriteFrameAsync(stream, AgentFrameKind.Ping,
                new byte[AgentProtocol.MaxFramePayload + 1], Token));

        // And a header that claims more than the limit is refused without allocating it.
        var hostile = new MemoryStream([(byte)AgentFrameKind.Ping, 0xFF, 0xFF, 0xFF]);
        await Assert.ThrowsAsync<AgentProtocolException>(() => AgentProtocol.ReadFrameAsync(hostile, Token));
    }

    [Fact]
    public async Task A_frame_cut_off_part_way_through_is_refused()
    {
        var stream = new MemoryStream([(byte)AgentFrameKind.Ping, 0, 0, 8, 1, 2, 3]);

        var problem = await Assert.ThrowsAsync<AgentProtocolException>(() =>
            AgentProtocol.ReadFrameAsync(stream, Token));

        Assert.Contains("part way through", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_hello_carries_the_role_the_token_and_the_label()
    {
        var token = RandomNumberGenerator.GetBytes(AgentProtocol.TokenBytes);
        var hello = new AgentHello(AgentRole.Stream, token, AgentProtocol.Features.Udp, "yura-daemon/0.3.0");

        var decoded = AgentHello.Decode(hello.Encode());

        Assert.Equal(AgentRole.Stream, decoded.Role);
        Assert.Equal(token, decoded.Token);
        Assert.Equal(AgentProtocol.Features.Udp, decoded.Wanted);
        Assert.Equal("yura-daemon/0.3.0", decoded.Label);
    }

    [Fact]
    public void Something_that_is_not_a_yura_client_is_told_so_rather_than_misparsed()
    {
        var wrong = new byte[64];
        "HTTP"u8.CopyTo(wrong);

        var problem = Assert.Throws<AgentProtocolException>(() => AgentHello.Decode(wrong));

        Assert.Contains("not a Yura agent client", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_different_protocol_version_is_named_in_the_refusal()
    {
        var hello = new AgentHello(AgentRole.Control, new byte[AgentProtocol.TokenBytes],
            AgentProtocol.Features.None, "x").Encode();
        hello[4] = 99;

        var problem = Assert.Throws<AgentProtocolException>(() => AgentHello.Decode(hello));

        Assert.Contains("99", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_role_is_refused_rather_than_defaulted()
    {
        var hello = new AgentHello(AgentRole.Control, new byte[AgentProtocol.TokenBytes],
            AgentProtocol.Features.None, "x").Encode();
        hello[5] = 7;

        Assert.Throws<AgentProtocolException>(() => AgentHello.Decode(hello));
    }

    [Theory]
    [InlineData("203.0.113.9", 27015)]
    [InlineData("2001:db8::1", 443)]
    [InlineData("gateway.example.com", 7311)]
    public void An_address_survives_the_round_trip_in_all_three_forms(string host, ushort port)
    {
        var encoded = new AgentOpen(new AgentAddress(host, port)).Encode();

        var decoded = AgentOpen.Decode(encoded);

        Assert.Equal(host, decoded.Target.Host);
        Assert.Equal(port, decoded.Target.Port);
    }

    [Fact]
    public void An_unknown_address_type_is_refused()
    {
        var problem = Assert.Throws<AgentProtocolException>(() => AgentOpen.Decode([0x09, 1, 2, 3, 4, 0, 80]));

        Assert.Contains("address type", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_welcome_carries_everything_the_session_needs()
    {
        var welcome = new AgentWelcome(
            RandomNumberGenerator.GetBytes(AgentProtocol.SessionIdBytes),
            RandomNumberGenerator.GetBytes(AgentProtocol.KeyBytes),
            7311,
            1400,
            AgentProtocol.Features.Udp | AgentProtocol.Features.Probe,
            "0.3.0",
            "frankfurt-1");

        var decoded = AgentWelcome.Decode(welcome.Encode());

        // Compared field by field: the record holds arrays, so its own equality is by
        // reference and would pass whatever the bytes were.
        Assert.Equal(welcome.SessionId, decoded.SessionId);
        Assert.Equal(welcome.DatagramKey, decoded.DatagramKey);
        Assert.Equal(welcome.DatagramPort, decoded.DatagramPort);
        Assert.Equal(welcome.MaxDatagramPayload, decoded.MaxDatagramPayload);
        Assert.Equal(welcome.Available, decoded.Available);
        Assert.Equal(welcome.AgentVersion, decoded.AgentVersion);
        Assert.Equal(welcome.AgentName, decoded.AgentName);
    }

    [Fact]
    public void A_probe_reply_distinguishes_no_samples_from_a_zero()
    {
        var measured = AgentProbeReply.Decode(new AgentProbeReply(7, "203.0.113.9:27015", [1200, 1300], null).Encode());
        Assert.Equal([1200u, 1300u], measured.Microseconds);
        Assert.Null(measured.Failure);

        var failed = AgentProbeReply.Decode(new AgentProbeReply(8, "203.0.113.9:27015", [], "timed out").Encode());
        Assert.Empty(failed.Microseconds);
        Assert.Equal("timed out", failed.Failure);
    }

    [Fact]
    public void Stats_survive_the_round_trip()
    {
        var stats = new AgentStats(3, 12, 40, 1_000_000, 2_000_000, 86_400, 5);

        Assert.Equal(stats, AgentStats.Decode(stats.Encode()));
    }

    // -- the datagram channel --------------------------------------------------

    private static (AgentDatagramCrypto Client, AgentDatagramCrypto Agent) Pair()
    {
        var sessionId = RandomNumberGenerator.GetBytes(AgentProtocol.SessionIdBytes);
        var master = RandomNumberGenerator.GetBytes(AgentProtocol.KeyBytes);
        return (AgentDatagramCrypto.ForClient(sessionId, master), AgentDatagramCrypto.ForAgent(sessionId, master));
    }

    [Fact]
    public void A_datagram_survives_the_round_trip_in_both_directions()
    {
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var plaintext = RandomNumberGenerator.GetBytes(200);
            var packet = new byte[AgentDatagramCrypto.SealedSize(plaintext.Length)];
            var opened = new byte[packet.Length];

            var sealedLength = client.Seal(plaintext, packet);
            Assert.True(agent.TryOpen(packet.AsSpan(0, sealedLength), opened, out var length));
            Assert.Equal(plaintext, opened[..length]);

            sealedLength = agent.Seal(plaintext, packet);
            Assert.True(client.TryOpen(packet.AsSpan(0, sealedLength), opened, out length));
            Assert.Equal(plaintext, opened[..length]);
        }
    }

    [Fact]
    public void A_datagram_cannot_be_reflected_back_at_its_sender()
    {
        // Each direction has its own key and its own direction byte, so a packet replayed at
        // the side that sent it does not decrypt.
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var packet = new byte[AgentDatagramCrypto.SealedSize(8)];
            var length = client.Seal(new byte[8], packet);

            Assert.False(client.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
            Assert.True(agent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
        }
    }

    [Fact]
    public void A_tampered_datagram_is_refused()
    {
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var packet = new byte[AgentDatagramCrypto.SealedSize(16)];
            var length = client.Seal(RandomNumberGenerator.GetBytes(16), packet);

            for (var index = 0; index < length; index++)
            {
                var copy = packet[..length];
                copy[index] ^= 0xFF;
                Assert.False(agent.TryOpen(copy, new byte[64], out _));
            }
        }
    }

    [Fact]
    public void A_datagram_from_another_session_is_refused()
    {
        var (client, _) = Pair();
        var (_, otherAgent) = Pair();
        using (client)
        using (otherAgent)
        {
            var packet = new byte[AgentDatagramCrypto.SealedSize(8)];
            var length = client.Seal(new byte[8], packet);

            Assert.False(otherAgent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
        }
    }

    [Fact]
    public void A_replayed_datagram_is_accepted_once_and_never_again()
    {
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var packet = new byte[AgentDatagramCrypto.SealedSize(8)];
            var length = client.Seal(new byte[8], packet);

            Assert.True(agent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
            Assert.False(agent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
            Assert.False(agent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
        }
    }

    [Fact]
    public void Datagrams_that_arrive_out_of_order_are_still_delivered()
    {
        // Reordering is normal on any path worth accelerating; only repeats are rejected.
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var packets = new List<byte[]>();
            for (var i = 0; i < 20; i++)
            {
                var packet = new byte[AgentDatagramCrypto.SealedSize(4)];
                var length = client.Seal(BitConverter.GetBytes(i), packet);
                packets.Add(packet[..length]);
            }

            foreach (var packet in packets.AsEnumerable().Reverse())
            {
                Assert.True(agent.TryOpen(packet, new byte[64], out _));
            }

            // And every one of them is now a replay.
            Assert.All(packets, packet => Assert.False(agent.TryOpen(packet, new byte[64], out _)));
        }
    }

    [Fact]
    public void A_datagram_from_far_behind_the_window_is_refused()
    {
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var first = new byte[AgentDatagramCrypto.SealedSize(4)];
            var firstLength = client.Seal(new byte[4], first);

            // Move the window well past it.
            for (var i = 0; i < 200; i++)
            {
                var packet = new byte[AgentDatagramCrypto.SealedSize(4)];
                var length = client.Seal(new byte[4], packet);
                Assert.True(agent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
            }

            Assert.False(agent.TryOpen(first.AsSpan(0, firstLength), new byte[64], out _));
        }
    }

    [Fact]
    public void A_forged_datagram_cannot_move_the_window_and_lock_out_real_ones()
    {
        // If the window advanced before the tag was checked, anyone who could guess a counter
        // could make the real datagrams look like replays.
        var (client, agent) = Pair();
        using (client)
        using (agent)
        {
            var packet = new byte[AgentDatagramCrypto.SealedSize(8)];
            var length = client.Seal(new byte[8], packet);

            var forged = packet[..length];
            // A far-future counter, with a tag that cannot possibly match.
            forged[AgentProtocol.SessionIdBytes + 1] = 0x7F;
            Assert.False(agent.TryOpen(forged, new byte[64], out _));

            Assert.True(agent.TryOpen(packet.AsSpan(0, length), new byte[64], out _));
        }
    }

    [Fact]
    public void The_two_directions_do_not_share_a_key()
    {
        var sessionId = RandomNumberGenerator.GetBytes(AgentProtocol.SessionIdBytes);
        var master = RandomNumberGenerator.GetBytes(AgentProtocol.KeyBytes);

        var toAgent = AgentDatagramCrypto.DeriveKey(master, sessionId, "c2a");
        var toClient = AgentDatagramCrypto.DeriveKey(master, sessionId, "a2c");

        Assert.NotEqual(toAgent, toClient);
        Assert.Equal(AgentProtocol.KeyBytes, toAgent.Length);
        // Deriving again gives the same key, or the two ends would never agree.
        Assert.Equal(toAgent, AgentDatagramCrypto.DeriveKey(master, sessionId, "c2a"));
        // And the session id is part of it, so keys cannot be carried between sessions.
        Assert.NotEqual(toAgent, AgentDatagramCrypto.DeriveKey(
            master, RandomNumberGenerator.GetBytes(AgentProtocol.SessionIdBytes), "c2a"));
    }

    [Fact]
    public void A_relay_body_names_its_channel_and_destination()
    {
        foreach (var target in new[]
                 {
                     new IPEndPoint(IPAddress.Parse("203.0.113.9"), 27015),
                     new IPEndPoint(IPAddress.Parse("2001:db8::5"), 443),
                 })
        {
            var payload = RandomNumberGenerator.GetBytes(64);
            var body = new byte[AgentDatagram.MaxRelayHeaderBytes + payload.Length];
            var length = AgentDatagram.WriteRelay(body, 4242, target, payload);

            Assert.Equal(AgentDatagramKind.Relay, AgentDatagram.KindOf(body.AsSpan(0, length)));
            Assert.True(AgentDatagram.TryReadRelay(
                body.AsSpan(0, length), out var channel, out var read, out var readPayload));
            Assert.Equal(4242, channel);
            Assert.Equal(target, read);
            Assert.Equal(payload, readPayload.ToArray());
        }
    }

    [Fact]
    public void A_truncated_relay_body_is_refused_rather_than_half_read()
    {
        var body = new byte[AgentDatagram.MaxRelayHeaderBytes];
        var length = AgentDatagram.WriteRelay(body, 1, new IPEndPoint(IPAddress.Loopback, 80), []);

        for (var cut = 0; cut < length; cut++)
        {
            Assert.False(AgentDatagram.TryReadRelay(body.AsSpan(0, cut), out _, out _, out _));
        }

        Assert.True(AgentDatagram.TryReadRelay(body.AsSpan(0, length), out _, out _, out _));
    }

    [Fact]
    public void A_full_size_datagram_fits_inside_a_normal_path()
    {
        // The whole point of the limit: a game packet plus the agent's overhead plus IPv6 and
        // UDP headers has to fit in 1500 bytes, because a fragmented game packet is worse than
        // a smaller one.
        var largest = AgentProtocol.MaxDatagramPayload + AgentDatagram.MaxRelayHeaderBytes +
                      AgentProtocol.DatagramOverheadBytes + 40 + 8;

        Assert.True(largest <= 1500, $"a full datagram needs {largest} bytes on the wire");
    }
}
