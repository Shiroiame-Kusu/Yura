using System.Net;

namespace Yura.Agent.Tests;

/// <summary>What the agent refuses to dial, case by case.</summary>
public sealed class DestinationPolicyTests
{
    private static readonly IPAddress OwnPublic = IPAddress.Parse("198.51.100.20");

    [Fact]
    public void The_agents_own_public_address_is_refused_like_loopback()
    {
        // A connection to the machine's own public address never leaves it, so it reaches
        // every service listening there — SSH, a database, an admin panel — past firewall
        // rules that only let the machine talk to itself. The range checks never saw it,
        // because a public address is not in any private range.
        var policy = DestinationPolicy.Default with { LocalAddresses = new HashSet<IPAddress> { OwnPublic } };

        Assert.Equal("The agent does not relay to its own addresses.", policy.Refuse(new IPEndPoint(OwnPublic, 22)));
        Assert.NotNull(policy.Refuse(new IPEndPoint(OwnPublic.MapToIPv6(), 22)));
        Assert.Null(policy.Refuse(new IPEndPoint(IPAddress.Parse("198.51.100.21"), 27015)));
    }

    [Fact]
    public void An_agent_told_to_allow_private_destinations_may_reach_its_own_addresses()
    {
        var policy = new DestinationPolicy
        {
            AllowPrivate = true,
            LocalAddresses = new HashSet<IPAddress> { OwnPublic },
        };

        Assert.Null(policy.Refuse(new IPEndPoint(OwnPublic, 27015)));
    }

    [Fact]
    public void The_machines_addresses_are_read_in_the_form_they_are_compared_in()
    {
        var addresses = DestinationPolicy.ReadLocalAddresses();

        Assert.Contains(IPAddress.Loopback, addresses);
        Assert.DoesNotContain(addresses, a => a.IsIPv4MappedToIPv6);
        Assert.DoesNotContain(addresses, a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && a.ScopeId != 0);
    }
}
