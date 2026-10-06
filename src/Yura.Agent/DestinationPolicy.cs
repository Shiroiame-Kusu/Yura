using System.Net;
using System.Net.Sockets;
using Yura.Core.Net;

namespace Yura.Agent;

/// <summary>
/// What the agent is willing to dial.
/// </summary>
/// <remarks>
/// <para>
/// An agent is a relay on a machine with an address, and a relay that will connect anywhere
/// is a way into whatever that machine can reach. So private, loopback and link-local ranges
/// are refused by default: a token holder can accelerate a game, and cannot use the agent to
/// reach the server's own management interface or the rest of its provider's network.
/// </para>
/// <para>
/// Every part of it is overridable, because an agent deliberately run inside a private
/// network to reach a private game server is a legitimate deployment — but it has to be asked
/// for, and the agent says so at startup when it is.
/// </para>
/// </remarks>
public sealed record DestinationPolicy
{
    public static readonly DestinationPolicy Default = new();

    /// <summary>Allow the ranges that are otherwise refused. Off unless asked for.</summary>
    public bool AllowPrivate { get; init; }

    /// <summary>When non-empty, only these networks may be dialled.</summary>
    public IReadOnlyList<IPNetwork> Allowed { get; init; } = [];

    /// <summary>Networks refused even when they would otherwise be allowed.</summary>
    public IReadOnlyList<IPNetwork> Denied { get; init; } = [];

    /// <summary>When non-empty, only these destination ports may be dialled.</summary>
    public IReadOnlyList<PortRange> Ports { get; init; } = [];

    /// <summary>
    /// The agent's own resolver, which may be reached on port 53 whatever the rest of the
    /// policy says.
    /// </summary>
    /// <remarks>
    /// The one exception, and a narrow one: this exact address, this one port. A resolver is
    /// what a client needs for the acceleration to be worth anything — a game's servers are
    /// chosen by DNS — and on most machines it is <c>127.0.0.53</c> or a LAN address, which the
    /// rest of this policy exists to refuse. Anything else in those ranges stays refused.
    /// </remarks>
    public IPAddress? Resolver { get; init; }

    /// <summary>
    /// The addresses of the machine the agent runs on, public ones included.
    /// </summary>
    /// <remarks>
    /// Refused like loopback, because that is what they are: a connection from the agent to its
    /// own public address never leaves the machine, so it reaches every service listening on
    /// it — an SSH daemon, a database, an admin panel — past any firewall rule that only lets
    /// the machine talk to itself. Kept current by the server, since an address can change
    /// under a running agent.
    /// </remarks>
    public IReadOnlySet<IPAddress> LocalAddresses { get; init; } = new HashSet<IPAddress>();

    /// <summary>
    /// Why this destination is refused, or null when it is allowed. The text goes back to the
    /// client, so it says what the agent's rule is without describing the server's network.
    /// </summary>
    public string? Refuse(IPEndPoint target)
    {
        if (target.Port == 0)
        {
            return "Port 0 is not a destination.";
        }

        var address = target.Address;

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
        {
            // Otherwise ::ffff:127.0.0.1 would walk straight past an IPv4 range check.
            address = address.MapToIPv4();
        }

        if (Denied.Any(network => network.Contains(address)))
        {
            return "The agent's policy refuses this destination.";
        }

        // The resolver the agent advertised, on port 53 only. Checked before the range rules
        // because it is usually an address they refuse.
        if (target.Port == 53 && Resolver is not null && Resolver.Equals(address))
        {
            return null;
        }

        if (Allowed.Count > 0 && !Allowed.Any(network => network.Contains(address)))
        {
            return "The agent only relays to specific networks, and this is not one of them.";
        }

        if (Ports.Count > 0 && !Ports.Any(range => range.Contains((ushort)target.Port)))
        {
            return $"The agent does not relay to port {target.Port}.";
        }

        if (!AllowPrivate && (IPAddress.IsLoopback(address) || IsPrivate(address)))
        {
            return "The agent does not relay to private or loopback addresses.";
        }

        if (!AllowPrivate && LocalAddresses.Contains(address))
        {
            return "The agent does not relay to its own addresses.";
        }

        if (IsMulticastOrUnspecified(address))
        {
            return "That is not an address the agent can relay to.";
        }

        return null;
    }

    /// <summary>
    /// Every unicast address on this machine's interfaces, in the form <see cref="Refuse"/>
    /// compares: IPv4 as IPv4, and without a scope id.
    /// </summary>
    public static IReadOnlySet<IPAddress> ReadLocalAddresses()
    {
        var addresses = new HashSet<IPAddress>();
        try
        {
            foreach (var network in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var unicast in network.GetIPProperties().UnicastAddresses)
                {
                    var address = unicast.Address;
                    if (address.IsIPv4MappedToIPv6)
                    {
                        address = address.MapToIPv4();
                    }
                    else if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
                    {
                        address = new IPAddress(address.GetAddressBytes());
                    }

                    addresses.Add(address);
                }
            }
        }
        catch (System.Net.NetworkInformation.NetworkInformationException)
        {
            // Nothing extra to refuse; the range rules still apply.
        }

        return addresses;
    }

    /// <summary>
    /// True for the ranges that belong to somebody's internal network rather than the internet.
    /// </summary>
    public static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                return IsPrivate(address.MapToIPv4());
            }

            return address.IsIPv6LinkLocal
                   || address.IsIPv6SiteLocal
                   || address.IsIPv6UniqueLocal
                   || IPAddress.IPv6Loopback.Equals(address);
        }

        Span<byte> raw = stackalloc byte[4];
        if (!address.TryWriteBytes(raw, out _))
        {
            return false;
        }

        return raw[0] switch
        {
            0 => true,                                       // 0.0.0.0/8, "this network"
            10 => true,                                      // 10.0.0.0/8
            127 => true,                                     // loopback
            100 => raw[1] >= 64 && raw[1] <= 127,            // 100.64.0.0/10, carrier NAT
            169 => raw[1] == 254,                            // 169.254.0.0/16, link local
            172 => raw[1] >= 16 && raw[1] <= 31,             // 172.16.0.0/12
            192 => (raw[1] == 168) || (raw[1] == 0 && raw[2] == 0), // 192.168/16 and 192.0.0/24
            198 => raw[1] == 18 || raw[1] == 19,             // 198.18.0.0/15, benchmarking
            _ => false,
        };
    }

    private static bool IsMulticastOrUnspecified(IPAddress address)
    {
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6Multicast;
        }

        Span<byte> raw = stackalloc byte[4];
        return address.TryWriteBytes(raw, out _) && raw[0] >= 224;
    }

    /// <summary>Describes the policy in one line, for the startup log.</summary>
    public string Describe()
    {
        var parts = new List<string>();
        parts.Add(AllowPrivate ? "private ranges ALLOWED" : "private ranges refused");
        if (Allowed.Count > 0)
        {
            parts.Add($"only to {string.Join(", ", Allowed)}");
        }

        if (Denied.Count > 0)
        {
            parts.Add($"never to {string.Join(", ", Denied)}");
        }

        if (Ports.Count > 0)
        {
            parts.Add($"ports {string.Join(", ", Ports)}");
        }

        parts.Add(Resolver is { } resolver ? $"dns to {resolver}" : "no resolver to offer");

        return string.Join("; ", parts);
    }
}
