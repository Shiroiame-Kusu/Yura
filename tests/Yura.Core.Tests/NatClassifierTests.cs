using System.Net;
using Yura.Core.Net;

namespace Yura.Core.Tests;

/// <summary>
/// The NAT verdict, case by case.
/// </summary>
/// <remarks>
/// This is the one place in Yura where a wrong answer is worse than no answer: a player told
/// "Open" who is behind a symmetric NAT will spend the evening blaming the game. So the table
/// is explicit, the conservative direction is asserted, and every case that cannot be
/// established stays Unknown rather than being rounded to the flattering side.
/// </remarks>
public sealed class NatClassifierTests
{
    private static readonly IPEndPoint Local = IPEndPoint.Parse("192.168.1.24:51820");
    private static readonly IPEndPoint Mapped = IPEndPoint.Parse("203.0.113.44:41001");
    private static readonly IPEndPoint OtherMapped = IPEndPoint.Parse("203.0.113.44:41002");

    [Fact]
    public void Nothing_answering_means_UDP_is_not_getting_out()
    {
        var assessment = NatClassifier.Classify(new NatObservations());

        Assert.Equal(NatVerdict.Blocked, assessment.Verdict);
        Assert.False(assessment.SupportsPeerToPeer);
        Assert.Contains("peer-to-peer", assessment.Diagnostics, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_stated_failure_is_unknown_and_not_blocked()
    {
        // "We could not test" and "UDP does not work" are different claims, and the second
        // would send someone off to reconfigure a router that is fine.
        var assessment = NatClassifier.Classify(new NatObservations { Failure = "no route" });

        Assert.Equal(NatVerdict.Unknown, assessment.Verdict);
        Assert.Equal("no route", assessment.Diagnostics);
    }

    [Fact]
    public void A_public_address_with_nothing_translating_it_is_open()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Mapped,
            FirstMapped = Mapped,
        });

        Assert.Equal(NatVerdict.Open, assessment.Verdict);
        Assert.False(assessment.BehindNat);
        Assert.Equal(NatMapping.EndpointIndependent, assessment.Mapping);
        Assert.Equal(NatFiltering.EndpointIndependent, assessment.Filtering);
    }

    [Fact]
    public void One_mapping_for_two_servers_is_moderate_while_filtering_is_untested()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
        });

        // Not Open: it might be, but nothing tested whether unsolicited packets get in, and
        // claiming the better of the two would be guessing in the user's favour.
        Assert.Equal(NatVerdict.Moderate, assessment.Verdict);
        Assert.Equal(NatMapping.EndpointIndependent, assessment.Mapping);
        Assert.Equal(NatFiltering.Unknown, assessment.Filtering);
        Assert.True(assessment.SupportsPeerToPeer);
        Assert.True(assessment.BehindNat);
    }

    [Fact]
    public void One_mapping_with_anything_reaching_it_is_open()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
            AnsweredFromOtherAddressAndPort = true,
        });

        Assert.Equal(NatVerdict.Open, assessment.Verdict);
        Assert.Equal(NatFiltering.EndpointIndependent, assessment.Filtering);
    }

    [Fact]
    public void One_mapping_with_address_filtering_is_moderate()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
            AnsweredFromOtherAddressAndPort = false,
            AnsweredFromOtherPort = true,
        });

        Assert.Equal(NatVerdict.Moderate, assessment.Verdict);
        Assert.Equal(NatFiltering.AddressDependent, assessment.Filtering);
        Assert.True(assessment.SupportsPeerToPeer);
    }

    [Fact]
    public void One_mapping_with_exact_peer_filtering_is_still_moderate()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
            AnsweredFromOtherAddressAndPort = false,
            AnsweredFromOtherPort = false,
            OtherPortAnswersOnceSentTo = true,
        });

        // Port-restricted cone: hole punching still works, because the peer's own packet
        // opens the mapping from the other side.
        Assert.Equal(NatVerdict.Moderate, assessment.Verdict);
        Assert.Equal(NatFiltering.AddressAndPortDependent, assessment.Filtering);
        Assert.True(assessment.SupportsPeerToPeer);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public void Silence_from_the_other_port_is_not_filtering_unless_the_server_answers_from_there(bool? onceSentTo)
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
            AnsweredFromOtherAddressAndPort = false,
            AnsweredFromOtherPort = false,
            OtherPortAnswersOnceSentTo = onceSentTo,
        });

        // A server that names a second address and never answers from it is silent too. Taken for
        // the NAT, that silence would call a NAT2 a NAT3.
        Assert.Equal(NatVerdict.Moderate, assessment.Verdict);
        Assert.Equal(NatFiltering.Unknown, assessment.Filtering);
        Assert.Null(NatClassifier.TypeNumber(assessment.Verdict, assessment.Filtering));
        Assert.Contains("NAT", assessment.Diagnostics, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(NatVerdict.Open, NatFiltering.EndpointIndependent, 1)]
    [InlineData(NatVerdict.Open, NatFiltering.Unknown, 1)]
    [InlineData(NatVerdict.Moderate, NatFiltering.AddressDependent, 2)]
    [InlineData(NatVerdict.Moderate, NatFiltering.AddressAndPortDependent, 3)]
    [InlineData(NatVerdict.Moderate, NatFiltering.Unknown, null)]
    [InlineData(NatVerdict.Strict, NatFiltering.Unknown, 4)]
    [InlineData(NatVerdict.Strict, NatFiltering.AddressAndPortDependent, 4)]
    [InlineData(NatVerdict.Blocked, NatFiltering.Unknown, null)]
    [InlineData(NatVerdict.Unknown, NatFiltering.AddressDependent, null)]
    public void The_number_players_use_is_given_only_where_the_measurement_settles_it(
        NatVerdict verdict, NatFiltering filtering, int? expected)
    {
        Assert.Equal(expected, NatClassifier.TypeNumber(verdict, filtering));
    }

    [Fact]
    public void A_varying_mapping_does_not_claim_the_filtering_went_untested_for_want_of_a_server()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = OtherMapped,
            SecondServerDistinct = true,
        });

        Assert.Equal(NatVerdict.Strict, assessment.Verdict);
        Assert.Contains("makes no difference", assessment.Diagnostics, StringComparison.Ordinal);
        Assert.DoesNotContain("none answered", assessment.Diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void A_mapping_that_differs_between_servers_is_strict()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = OtherMapped,
            SecondServerDistinct = true,
        });

        Assert.Equal(NatVerdict.Strict, assessment.Verdict);
        Assert.Equal(NatMapping.DestinationDependent, assessment.Mapping);
        Assert.False(assessment.SupportsPeerToPeer);
        Assert.Contains("hole punching cannot work", assessment.Diagnostics, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_mapping_that_differs_by_destination_port_alone_is_the_strictest_kind()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = OtherMapped,
            SecondServerDistinct = true,
            SecondServerDiffersOnlyByPort = true,
        });

        Assert.Equal(NatVerdict.Strict, assessment.Verdict);
        Assert.Equal(NatMapping.AddressAndPortDependent, assessment.Mapping);
    }

    [Fact]
    public void One_mapping_for_two_ports_of_one_server_says_nothing_about_the_address()
    {
        // A second port of the same server rules out a mapping keyed on the destination port
        // and leaves untested the one keyed on the address, which breaks hole punching just as
        // surely. This used to read as endpoint-independent, and the page said Moderate.
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
            SecondServerDiffersOnlyByPort = true,
            AnsweredFromOtherAddressAndPort = true,
        });

        Assert.Equal(NatMapping.Unknown, assessment.Mapping);
        Assert.Equal(NatVerdict.Unknown, assessment.Verdict);
        Assert.False(assessment.SupportsPeerToPeer);
        Assert.Contains("could not be established", assessment.Diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public void One_server_answering_leaves_the_mapping_unknown_rather_than_assumed_good()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
        });

        Assert.Equal(NatVerdict.Unknown, assessment.Verdict);
        Assert.Equal(NatMapping.Unknown, assessment.Mapping);
        Assert.Equal(Mapped, assessment.MappedEndpoint);
        Assert.False(assessment.SupportsPeerToPeer);
    }

    [Fact]
    public void Two_probes_that_reached_the_same_server_prove_nothing_about_the_mapping()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = false,
        });

        // Two names for one address is the trap this guards: the mappings match because it is
        // the same destination, which says nothing at all.
        Assert.Equal(NatMapping.Unknown, assessment.Mapping);
        Assert.Equal(NatVerdict.Unknown, assessment.Verdict);
    }

    [Fact]
    public void A_route_with_no_local_address_to_compare_does_not_claim_to_know_about_a_NAT()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
        });

        // Through a proxy the socket that faces the internet is somewhere else, so whether
        // anything translates it is not ours to say.
        Assert.Null(assessment.BehindNat);
        Assert.Equal(NatVerdict.Moderate, assessment.Verdict);
    }

    [Fact]
    public void A_measured_varying_mapping_beats_the_no_NAT_inference()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Mapped,
            FirstMapped = Mapped,
            SecondMapped = OtherMapped,
            SecondServerDistinct = true,
        });

        // Contradictory: the first server saw this socket's own address, the second saw
        // something else. Something is translating after all, and the measurement wins.
        Assert.Equal(NatVerdict.Strict, assessment.Verdict);
    }

    [Fact]
    public void The_diagnostics_always_name_the_address_a_peer_would_be_told()
    {
        var assessment = NatClassifier.Classify(new NatObservations
        {
            Local = Local,
            FirstMapped = Mapped,
            SecondMapped = Mapped,
            SecondServerDistinct = true,
        });

        Assert.Contains(Mapped.ToString(), assessment.Diagnostics, StringComparison.Ordinal);
    }
}
