using System.Net;

namespace Yura.Core.Net;

/// <summary>How the NAT chooses the outside address a socket appears to come from.</summary>
/// <remarks>
/// This is the half that decides whether peer-to-peer works at all. Hole punching works by
/// each side learning its own outside address from a third party and telling the other; that
/// only helps if the address the third party saw is the address the peer will see.
/// </remarks>
public enum NatMapping
{
    /// <summary>Not established. Never rendered as if it were one of the answers below.</summary>
    Unknown,

    /// <summary>One outside address for every destination. What hole punching needs.</summary>
    EndpointIndependent,

    /// <summary>
    /// Proven to differ between two destinations, without establishing whether the address or
    /// the port is what it keys on. Both are "symmetric" as far as a game is concerned.
    /// </summary>
    DestinationDependent,

    /// <summary>A different outside address per destination address.</summary>
    AddressDependent,

    /// <summary>A different outside address per destination address and port. The strictest.</summary>
    AddressAndPortDependent,
}

/// <summary>Which unsolicited packets the NAT lets back in.</summary>
public enum NatFiltering
{
    /// <summary>Not established — the usual case, since it needs a server with two addresses.</summary>
    Unknown,

    /// <summary>Anything may reach an open mapping. A "full cone" NAT.</summary>
    EndpointIndependent,

    /// <summary>Only a host already sent to, from any of its ports.</summary>
    AddressDependent,

    /// <summary>Only the exact address and port already sent to.</summary>
    AddressAndPortDependent,
}

/// <summary>The verdict in the words a game shows its players.</summary>
public enum NatVerdict
{
    Unknown,

    /// <summary>No UDP reached the other side at all, so peer-to-peer cannot work.</summary>
    Blocked,

    /// <summary>Type 1 / Open. Direct connections in both directions.</summary>
    Open,

    /// <summary>Type 2 / Moderate. Hole punching works; unsolicited traffic does not.</summary>
    Moderate,

    /// <summary>Type 3 / Strict. A different mapping per peer, so hole punching fails.</summary>
    Strict,
}

/// <summary>What was actually observed, from which everything else is derived.</summary>
public sealed record NatObservations
{
    /// <summary>Why nothing could be measured, when that is the outcome.</summary>
    public string? Failure { get; init; }

    /// <summary>
    /// The address the route's own socket has locally, when that is knowable. Equal to
    /// <see cref="FirstMapped"/> exactly when nothing translates the traffic.
    /// </summary>
    public IPEndPoint? Local { get; init; }

    /// <summary>What the first server saw.</summary>
    public IPEndPoint? FirstMapped { get; init; }

    /// <summary>What a second, different server saw on the same socket.</summary>
    public IPEndPoint? SecondMapped { get; init; }

    /// <summary>
    /// False when the second probe did not reach a genuinely different server address, which
    /// makes comparing the two mappings meaningless rather than reassuring.
    /// </summary>
    public bool SecondServerDistinct { get; init; }

    /// <summary>
    /// True when the second server differed only in port, so a difference in the mapping
    /// proves port dependence and a match proves nothing about address dependence.
    /// </summary>
    public bool SecondServerDiffersOnlyByPort { get; init; }

    /// <summary>An answer arrived from the server's other address and port, or null if untested.</summary>
    public bool? AnsweredFromOtherAddressAndPort { get; init; }

    /// <summary>An answer arrived from the server's other port, or null if untested.</summary>
    public bool? AnsweredFromOtherPort { get; init; }
}

/// <summary>A NAT verdict and the behaviour it was derived from.</summary>
public sealed record NatAssessment
{
    public required NatVerdict Verdict { get; init; }

    public NatMapping Mapping { get; init; }

    public NatFiltering Filtering { get; init; }

    /// <summary>The outside address the far side sees, when a server answered.</summary>
    public IPEndPoint? MappedEndpoint { get; init; }

    /// <summary>
    /// Whether anything translates this route's traffic. Null when it could not be told —
    /// which is the case for every route where the local address is not ours to read.
    /// </summary>
    public bool? BehindNat { get; init; }

    /// <summary>Technical detail for the expandable section: what was tried and what came back.</summary>
    public string Diagnostics { get; init; } = string.Empty;

    /// <summary>True when peer-to-peer traffic can be expected to work with most peers.</summary>
    public bool SupportsPeerToPeer => Verdict is NatVerdict.Open or NatVerdict.Moderate;
}

/// <summary>
/// Turns STUN observations into a NAT verdict.
/// </summary>
/// <remarks>
/// Pure and separate from the probing so the table of cases can be tested directly, which
/// matters because this is the one place where a wrong answer is worse than no answer: a
/// player told "Open" who is actually behind a symmetric NAT will blame the game.
///
/// The vocabulary is the one consoles and games use, because that is what a player is
/// comparing against. The mapping of behaviour to verdict is the conventional one:
/// endpoint-independent mapping with endpoint-independent filtering is Open, endpoint-
/// independent mapping with any narrower filtering is Moderate, and anything that changes its
/// mapping per destination is Strict. Filtering that could not be tested is reported as
/// unknown and the verdict is the more conservative Moderate, never the flattering Open.
/// </remarks>
public static class NatClassifier
{
    public static NatAssessment Classify(NatObservations observations)
    {
        ArgumentNullException.ThrowIfNull(observations);

        if (observations.Failure is { Length: > 0 } failure)
        {
            return new NatAssessment
            {
                Verdict = NatVerdict.Unknown,
                Diagnostics = failure,
            };
        }

        if (observations.FirstMapped is null)
        {
            return new NatAssessment
            {
                Verdict = NatVerdict.Blocked,
                Diagnostics = "No STUN server answered, so nothing carried UDP out and back. " +
                              "Peer-to-peer traffic cannot work on this route.",
            };
        }

        var mapped = observations.FirstMapped;
        var behindNat = observations.Local is { } local ? !local.Equals(mapped) : (bool?)null;
        var mapping = ClassifyMapping(observations, out var mappingDetail);
        var filtering = ClassifyFiltering(observations, out var filteringDetail);

        var verdict = (mapping, filtering) switch
        {
            (NatMapping.Unknown, _) => NatVerdict.Unknown,
            (NatMapping.EndpointIndependent, NatFiltering.EndpointIndependent) => NatVerdict.Open,
            (NatMapping.EndpointIndependent, _) => NatVerdict.Moderate,
            _ => NatVerdict.Strict,
        };

        // Nothing between this socket and the server rewrote anything: the address the far
        // side sees is this socket's own. That is Open whatever the filtering test managed,
        // because there is no NAT to filter. Guarded by the mapping having not been seen to
        // vary — if it did, something is translating after all, and the measurement wins over
        // the inference.
        if (behindNat == false && mapping is NatMapping.EndpointIndependent or NatMapping.Unknown)
        {
            verdict = NatVerdict.Open;
            mapping = NatMapping.EndpointIndependent;
            filtering = NatFiltering.EndpointIndependent;
            mappingDetail = "The far side sees this route's own address and port, so nothing " +
                            "is translating it.";
            filteringDetail = string.Empty;
        }

        var parts = new List<string> { $"The far side sees {mapped}." };
        if (mappingDetail is { Length: > 0 })
        {
            parts.Add(mappingDetail);
        }

        if (filteringDetail is { Length: > 0 })
        {
            parts.Add(filteringDetail);
        }

        return new NatAssessment
        {
            Verdict = verdict,
            Mapping = mapping,
            Filtering = filtering,
            MappedEndpoint = mapped,
            BehindNat = behindNat,
            Diagnostics = string.Join(" ", parts),
        };
    }

    private static NatMapping ClassifyMapping(NatObservations observations, out string detail)
    {
        if (observations.SecondMapped is null || !observations.SecondServerDistinct)
        {
            detail = "Only one server answered, so whether the mapping changes per destination " +
                     "could not be established.";
            return NatMapping.Unknown;
        }

        if (observations.FirstMapped!.Equals(observations.SecondMapped))
        {
            detail = observations.SecondServerDiffersOnlyByPort
                ? "Two servers on the same address but different ports saw the same mapping, so " +
                  "the mapping does not depend on the destination port."
                : "Two different servers saw the same mapping, so it does not depend on the " +
                  "destination. Hole punching can work.";
            return NatMapping.EndpointIndependent;
        }

        if (observations.SecondServerDiffersOnlyByPort)
        {
            detail = "A different destination port produced a different mapping.";
            return NatMapping.AddressAndPortDependent;
        }

        detail = "Two different servers saw two different mappings, so the address a peer " +
                 "would be told is not the address it would see. Hole punching cannot work.";
        return NatMapping.DestinationDependent;
    }

    private static NatFiltering ClassifyFiltering(NatObservations observations, out string detail)
    {
        if (observations.AnsweredFromOtherAddressAndPort is true)
        {
            detail = "An answer arrived from an address that had never been sent to, so anything " +
                     "can reach an open mapping.";
            return NatFiltering.EndpointIndependent;
        }

        if (observations.AnsweredFromOtherAddressAndPort is null)
        {
            detail = "Whether unsolicited packets get in was not tested: it needs a STUN server " +
                     "with two addresses, and none was available.";
            return NatFiltering.Unknown;
        }

        if (observations.AnsweredFromOtherPort is true)
        {
            detail = "An answer from another port of a host already sent to got through, so " +
                     "filtering is by address only.";
            return NatFiltering.AddressDependent;
        }

        if (observations.AnsweredFromOtherPort is null)
        {
            detail = "Only exact-peer filtering could be ruled in, not ruled out.";
            return NatFiltering.Unknown;
        }

        detail = "Only the exact address and port already sent to can answer.";
        return NatFiltering.AddressAndPortDependent;
    }
}
