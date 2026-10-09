using System.Buffers.Binary;
using System.Net;
using System.Threading.Channels;
using Yura.Core.Ipc;
using Yura.Core.Net;
using Yura.Daemon.Diagnostics;

namespace Yura.Daemon.Tests;

/// <summary>
/// The NAT probe against a simulated NAT and simulated STUN servers, kind by kind.
/// </summary>
/// <remarks>
/// What decides NAT2 from NAT3 is an answer that does not arrive, so the danger is a silence
/// that is not the NAT's: a server that names a second address and never answers from it, or
/// an earlier request that had already opened the way. Each is simulated here.
/// </remarks>
public sealed class NatProbeTests
{
    private static readonly TimeSpan[] OneShortTry = [TimeSpan.FromMilliseconds(30)];

    private static readonly IPAddress Public = IPAddress.Parse("203.0.113.44");
    private static readonly IPEndPoint Local = IPEndPoint.Parse("192.168.1.24:51820");

    // Two addresses, honours CHANGE-REQUEST: like stun.miwifi.com.
    private static readonly SimulatedServer Capable = new()
    {
        Primary = IPEndPoint.Parse("198.18.10.3:3478"),
        Other = IPEndPoint.Parse("198.18.10.2:3479"),
    };

    private static readonly SimulatedServer AlsoCapable = new()
    {
        Primary = IPEndPoint.Parse("198.18.20.186:3478"),
        Other = IPEndPoint.Parse("198.18.20.187:3479"),
    };

    // One address: like Google's.
    private static readonly SimulatedServer MappingOnly = new() { Primary = IPEndPoint.Parse("198.18.30.1:19302") };

    // Names a second address and never answers from it.
    private static readonly SimulatedServer NeverAnswersFromElsewhere = new()
    {
        Primary = IPEndPoint.Parse("198.18.40.1:3478"),
        Other = IPEndPoint.Parse("198.18.40.2:3479"),
        Changes = Change.Silent,
    };

    // Names a second address and answers from wherever it was asked.
    private static readonly SimulatedServer IgnoresTheRequest = new()
    {
        Primary = IPEndPoint.Parse("198.18.50.1:3478"),
        Other = IPEndPoint.Parse("198.18.50.2:3479"),
        Changes = Change.Ignored,
    };

    private static async Task<NatReportDto> Probe(SimulatedNat nat, params SimulatedServer[] servers)
    {
        nat.Servers.AddRange(servers);
        return await NatProbe.ProbeAsync(nat, servers.Select(s => s.Primary).ToList(), CancellationToken.None, OneShortTry);
    }

    [Fact]
    public async Task Anything_getting_in_from_anywhere_is_NAT1()
    {
        var report = await Probe(new SimulatedNat(NatFiltering.EndpointIndependent), Capable, MappingOnly);

        Assert.Equal(NatVerdict.Open, report.Verdict);
        Assert.Equal(NatFiltering.EndpointIndependent, report.Filtering);
        Assert.Equal(1, report.TypeNumber());
        Assert.Equal([Capable.Primary.ToString(), MappingOnly.Primary.ToString()], report.Servers);
    }

    [Fact]
    public async Task An_answer_from_another_port_of_a_host_already_sent_to_is_NAT2()
    {
        var report = await Probe(new SimulatedNat(NatFiltering.AddressDependent), Capable, MappingOnly);

        Assert.Equal(NatVerdict.Moderate, report.Verdict);
        Assert.Equal(NatFiltering.AddressDependent, report.Filtering);
        Assert.Equal(2, report.TypeNumber());
    }

    [Fact]
    public async Task Only_the_exact_address_and_port_sent_to_is_NAT3_once_the_server_has_answered_from_its_other_port()
    {
        var nat = new SimulatedNat(NatFiltering.AddressAndPortDependent);
        var report = await Probe(nat, Capable, MappingOnly);

        Assert.Equal(NatVerdict.Moderate, report.Verdict);
        Assert.Equal(NatFiltering.AddressAndPortDependent, report.Filtering);
        Assert.Equal(3, report.TypeNumber());

        // The other port was sent to only after both requests had gone unanswered.
        var otherPort = new IPEndPoint(Capable.Primary.Address, Capable.Other!.Port);
        var opened = nat.Requests.FindIndex(r => r.To.Equals(otherPort));
        Assert.True(opened > nat.Requests.FindIndex(r => r.Change == 6), string.Join(", ", nat.Requests));
        Assert.True(opened > nat.Requests.FindIndex(r => r.Change == 2), string.Join(", ", nat.Requests));
        Assert.Contains(nat.Requests.Skip(opened), r => r.To.Equals(Capable.Primary) && r.Change == 2);
    }

    [Fact]
    public async Task A_server_that_never_answers_from_its_other_port_is_not_taken_for_a_NAT3()
    {
        // The NAT would let the answers in. A probe that took silence for filtering would still
        // say NAT3, about a NAT that is really NAT2.
        var report = await Probe(new SimulatedNat(NatFiltering.AddressDependent), NeverAnswersFromElsewhere, MappingOnly);

        Assert.Equal(NatVerdict.Moderate, report.Verdict);
        Assert.Equal(NatFiltering.Unknown, report.Filtering);
        Assert.Null(report.TypeNumber());
        Assert.Contains("the silence is the server's", report.Diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task When_the_first_server_proves_nothing_the_next_that_can_is_asked()
    {
        var report = await Probe(
            new SimulatedNat(NatFiltering.AddressAndPortDependent), NeverAnswersFromElsewhere, AlsoCapable, MappingOnly);

        Assert.Equal(NatFiltering.AddressAndPortDependent, report.Filtering);
        Assert.Equal(3, report.TypeNumber());
        Assert.Contains(AlsoCapable.Primary.ToString(), report.Servers);
        Assert.Contains($"tested against {AlsoCapable.Primary}", report.Diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_server_answering_from_where_it_was_asked_is_not_credited()
    {
        // Every answer gets in, because each comes from the address it was sent to. Counting them
        // would call any NAT behind such a server Open.
        var report = await Probe(new SimulatedNat(NatFiltering.AddressAndPortDependent), IgnoresTheRequest, MappingOnly);

        Assert.Equal(NatVerdict.Moderate, report.Verdict);
        Assert.Equal(NatFiltering.Unknown, report.Filtering);
        Assert.Null(report.TypeNumber());
    }

    [Fact]
    public async Task A_first_server_with_one_address_hands_the_filtering_to_one_with_two()
    {
        var report = await Probe(new SimulatedNat(NatFiltering.AddressDependent), MappingOnly, Capable);

        Assert.Equal(NatVerdict.Moderate, report.Verdict);
        Assert.Equal(2, report.TypeNumber());
        Assert.Equal([MappingOnly.Primary.ToString(), Capable.Primary.ToString()], report.Servers);
    }

    [Fact]
    public async Task A_symmetric_NAT_is_NAT4_and_no_time_goes_on_its_filtering()
    {
        var nat = new SimulatedNat(NatFiltering.AddressAndPortDependent, NatMapping.AddressAndPortDependent);
        var report = await Probe(nat, Capable, MappingOnly);

        Assert.Equal(NatVerdict.Strict, report.Verdict);
        Assert.Equal(4, report.TypeNumber());
        Assert.DoesNotContain(nat.Requests, r => r.Change != 0);
        Assert.Contains("makes no difference", report.Diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nothing_goes_to_the_first_servers_other_address_before_its_filtering_is_known()
    {
        // The second server shares the first one's other address. Asked first, for the mapping,
        // it would open a NAT2 to the answer from that address, and the NAT2 would pass for NAT1.
        var sharing = new SimulatedServer { Primary = new IPEndPoint(Capable.Other!.Address, 3478) };
        var nat = new SimulatedNat(NatFiltering.AddressDependent);
        var report = await Probe(nat, Capable, sharing);

        Assert.Equal(2, report.TypeNumber());
        Assert.Equal(NatMapping.EndpointIndependent, report.Mapping);
        Assert.True(
            nat.Requests.FindIndex(r => r.To.Equals(sharing.Primary)) > nat.Requests.FindLastIndex(r => r.Change != 0),
            string.Join(", ", nat.Requests));
    }

    [Fact]
    public async Task An_address_nothing_translates_is_open_without_a_filtering_test()
    {
        var nat = new SimulatedNat(NatFiltering.AddressAndPortDependent) { Local = new IPEndPoint(Public, 40000) };
        var report = await Probe(nat, Capable, MappingOnly);

        Assert.Equal(NatVerdict.Open, report.Verdict);
        Assert.False(report.BehindNat);
        Assert.DoesNotContain(nat.Requests, r => r.Change != 0);
    }

    [Fact]
    public async Task No_server_answering_is_no_UDP()
    {
        var silent = new SimulatedServer { Primary = IPEndPoint.Parse("198.18.60.1:3478"), Answers = false };
        var report = await Probe(new SimulatedNat(NatFiltering.EndpointIndependent), silent);

        Assert.Equal(NatVerdict.Blocked, report.Verdict);
        Assert.Empty(report.Servers);
    }

    private enum Change
    {
        Honoured,
        Ignored,
        Silent,
    }

    private sealed class SimulatedServer
    {
        public required IPEndPoint Primary { get; init; }

        /// <summary>The second address and port it names in OTHER-ADDRESS, and listens on.</summary>
        public IPEndPoint? Other { get; init; }

        public Change Changes { get; init; } = Change.Honoured;

        public bool Answers { get; init; } = true;

        public bool Listens(IPEndPoint at) =>
            at.Equals(Primary) || (Other is { } other &&
                                   (at.Equals(other) ||
                                    at.Equals(new IPEndPoint(Primary.Address, other.Port)) ||
                                    at.Equals(new IPEndPoint(other.Address, Primary.Port))));

        /// <summary>Where the answer to a request that reached <paramref name="at"/> comes from, or null for none.</summary>
        public IPEndPoint? AnswerFrom(IPEndPoint at, int change)
        {
            if (!Answers)
            {
                return null;
            }

            if (change == 0 || Other is not { } other || Changes == Change.Ignored)
            {
                return at;
            }

            if (Changes == Change.Silent)
            {
                return null;
            }

            var address = (change & 4) == 0 ? at.Address
                : at.Address.Equals(Primary.Address) ? other.Address : Primary.Address;
            var port = (change & 2) == 0 ? at.Port
                : at.Port == Primary.Port ? other.Port : Primary.Port;
            return new IPEndPoint(address, port);
        }

        public byte[] Response(ReadOnlySpan<byte> transactionId, IPEndPoint mapped)
        {
            var attributes = new List<byte[]> { Address(0x0020, mapped, transactionId) };
            if (Other is { } other)
            {
                attributes.Add(Address(0x802C, other, default));
            }

            var body = attributes.SelectMany(a => a).ToArray();
            var message = new byte[20 + body.Length];
            BinaryPrimitives.WriteUInt16BigEndian(message, 0x0101);
            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)body.Length);
            BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4), Stun.MagicCookie);
            transactionId.CopyTo(message.AsSpan(8));
            body.CopyTo(message, 20);
            return message;
        }

        private static byte[] Address(ushort type, IPEndPoint endpoint, ReadOnlySpan<byte> xorWith)
        {
            var value = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(value, type);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), 8);
            value[5] = 0x01;
            var port = (ushort)endpoint.Port;
            var address = endpoint.Address.GetAddressBytes();
            if (!xorWith.IsEmpty)
            {
                port ^= (ushort)(Stun.MagicCookie >> 16);
                Span<byte> cookie = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(cookie, Stun.MagicCookie);
                for (var i = 0; i < 4; i++)
                {
                    address[i] ^= cookie[i];
                }
            }

            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(6), port);
            address.CopyTo(value, 8);
            return value;
        }
    }

    /// <summary>
    /// A NAT in front of one socket, with the STUN servers beyond it, answering in the same call.
    /// </summary>
    private sealed class SimulatedNat(NatFiltering filtering, NatMapping mapping = NatMapping.EndpointIndependent)
        : INatTransport
    {
        private readonly Channel<NatDatagram> _inbox = Channel.CreateUnbounded<NatDatagram>();
        private readonly List<IPEndPoint> _sentTo = [];
        private readonly Dictionary<IPEndPoint, int> _ports = [];

        public IPEndPoint? Local { get; init; } = NatProbeTests.Local;

        public List<SimulatedServer> Servers { get; } = [];

        /// <summary>Every request, in order, with its CHANGE-REQUEST flags.</summary>
        public List<(IPEndPoint To, int Change)> Requests { get; } = [];

        public IPEndPoint? LocalEndpoint => Local;

        public string? Detail => null;

        public Task SendAsync(IPEndPoint destination, byte[] payload, CancellationToken ct)
        {
            var change = payload.Length >= 28 ? (int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(24)) : 0;
            Requests.Add((destination, change));
            _sentTo.Add(destination);

            var mapped = MappingFor(destination);
            var server = Servers.FirstOrDefault(s => s.Listens(destination));
            if (server?.AnswerFrom(destination, change) is { } from && Admits(from, destination))
            {
                _inbox.Writer.TryWrite(new NatDatagram(from, server.Response(payload.AsSpan(8, 12), mapped)));
            }

            return Task.CompletedTask;
        }

        private IPEndPoint MappingFor(IPEndPoint destination)
        {
            if (Local is { } local && local.Address.Equals(Public))
            {
                return local;
            }

            if (mapping == NatMapping.EndpointIndependent)
            {
                return new IPEndPoint(Public, 40000);
            }

            if (!_ports.TryGetValue(destination, out var port))
            {
                _ports[destination] = port = 40000 + _ports.Count;
            }

            return new IPEndPoint(Public, port);
        }

        /// <summary>Whether an answer from <paramref name="from"/> gets in to the mapping made for <paramref name="destination"/>.</summary>
        private bool Admits(IPEndPoint from, IPEndPoint destination) => mapping != NatMapping.EndpointIndependent
            ? from.Equals(destination)
            : filtering switch
            {
                NatFiltering.EndpointIndependent => true,
                NatFiltering.AddressDependent => _sentTo.Any(sent => sent.Address.Equals(from.Address)),
                _ => _sentTo.Contains(from),
            };

        public async Task<NatDatagram?> ReceiveAsync(TimeSpan within, CancellationToken ct)
        {
            if (within <= TimeSpan.Zero)
            {
                return null;
            }

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(within);
            try
            {
                return await _inbox.Reader.ReadAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                return null;
            }
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
