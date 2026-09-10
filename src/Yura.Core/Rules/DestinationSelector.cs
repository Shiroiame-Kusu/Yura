using System.Net;
using Yura.Core.Net;

namespace Yura.Core.Rules;

/// <summary>Transport a rule applies to.</summary>
public enum TransportFilter
{
    Any,
    Tcp,
    Udp,
}

/// <summary>How a host pattern is compared against a connection's destination name.</summary>
public enum HostMatchKind
{
    /// <summary>Exact, case-insensitive equality.</summary>
    Exact,

    /// <summary>The name equals the pattern or ends with <c>"." + pattern</c>.</summary>
    Suffix,

    /// <summary>The pattern occurs anywhere in the name.</summary>
    Keyword,
}

public sealed record HostPattern(HostMatchKind Kind, string Value)
{
    public bool Matches(string host) => Kind switch
    {
        HostMatchKind.Exact => string.Equals(host, Value, StringComparison.OrdinalIgnoreCase),
        HostMatchKind.Suffix =>
            string.Equals(host, Value, StringComparison.OrdinalIgnoreCase) ||
            (host.Length > Value.Length &&
             host[host.Length - Value.Length - 1] == '.' &&
             host.EndsWith(Value, StringComparison.OrdinalIgnoreCase)),
        HostMatchKind.Keyword => host.Contains(Value, StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    public override string ToString() => Kind switch
    {
        HostMatchKind.Exact => Value,
        HostMatchKind.Suffix => $"*.{Value}",
        HostMatchKind.Keyword => $"*{Value}*",
        _ => Value,
    };
}

/// <summary>The destination side of a rule's match condition.</summary>
/// <remarks>
/// All populated facets must match (AND); within a facet any entry matches (OR). An empty
/// facet is not a constraint.
/// </remarks>
public sealed record DestinationSelector
{
    public static readonly DestinationSelector Any = new();

    public IReadOnlyList<HostPattern> Hosts { get; init; } = [];

    public IReadOnlyList<IPNetwork> Networks { get; init; } = [];

    public IReadOnlyList<PortRange> Ports { get; init; } = [];

    public TransportFilter Protocol { get; init; } = TransportFilter.Any;

    public bool IsUnconstrained =>
        Hosts.Count == 0 && Networks.Count == 0 && Ports.Count == 0 && Protocol == TransportFilter.Any;

    /// <summary>
    /// True when this selector can only be evaluated once a destination host name is known.
    /// </summary>
    /// <remarks>
    /// Yura learns names from DNS answers and from TLS SNI / HTTP Host sniffing. A
    /// connection opened straight to a literal address has no name, and a host rule must
    /// then report "not applicable" rather than quietly failing to match.
    /// </remarks>
    public bool RequiresHostName => Hosts.Count > 0;

    public bool MatchesDestination(IPAddress address, ushort port, TransportProtocol protocol, string? hostName)
    {
        if (Protocol != TransportFilter.Any)
        {
            var wanted = Protocol == TransportFilter.Tcp ? TransportProtocol.Tcp : TransportProtocol.Udp;
            if (protocol != wanted)
            {
                return false;
            }
        }

        if (Ports.Count > 0)
        {
            var hit = false;
            foreach (var range in Ports)
            {
                if (range.Contains(port))
                {
                    hit = true;
                    break;
                }
            }

            if (!hit)
            {
                return false;
            }
        }

        if (Networks.Count > 0)
        {
            var hit = false;
            foreach (var network in Networks)
            {
                if (network.Contains(address))
                {
                    hit = true;
                    break;
                }
            }

            if (!hit)
            {
                return false;
            }
        }

        if (Hosts.Count > 0)
        {
            // No name learned for this connection: a host constraint cannot be satisfied.
            // Falling through to "match" here would route traffic the user never asked for.
            if (hostName is not { Length: > 0 })
            {
                return false;
            }

            var hit = false;
            foreach (var pattern in Hosts)
            {
                if (pattern.Matches(hostName))
                {
                    hit = true;
                    break;
                }
            }

            if (!hit)
            {
                return false;
            }
        }

        return true;
    }

    public string Describe()
    {
        if (IsUnconstrained)
        {
            return "Any destination";
        }

        var parts = new List<string>(4);
        if (Hosts.Count > 0)
        {
            parts.Add(string.Join(", ", Hosts));
        }

        if (Networks.Count > 0)
        {
            parts.Add(string.Join(", ", Networks));
        }

        if (Ports.Count > 0)
        {
            parts.Add("port " + string.Join(", ", Ports));
        }

        if (Protocol != TransportFilter.Any)
        {
            parts.Add(Protocol.ToString().ToUpperInvariant());
        }

        return string.Join(" · ", parts);
    }
}

/// <summary>Transport protocol of an observed connection.</summary>
public enum TransportProtocol
{
    Tcp,
    Udp,
}
