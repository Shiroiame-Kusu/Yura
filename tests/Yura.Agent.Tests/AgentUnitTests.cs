using System.Net;
using Yura.Core.Net;

namespace Yura.Agent.Tests;

/// <summary>
/// The systemd unit <c>install</c> writes: it has to run the agent the way it was asked for.
/// </summary>
/// <remarks>
/// An option given to <c>install</c> and missing from the unit is silently not in effect — the
/// service starts with the default instead, and nothing says so.
/// </remarks>
public sealed class AgentUnitTests
{
    private static string ExecStart(AgentOptions options) =>
        AgentUnit.Generate(options).Split('\n').Single(l => l.StartsWith("ExecStart=", StringComparison.Ordinal));

    [Fact]
    public void The_defaults_need_no_options_beyond_where_to_listen()
    {
        var line = ExecStart(new AgentOptions());

        Assert.DoesNotContain("--no-full-cone", line, StringComparison.Ordinal);
        Assert.DoesNotContain("--cone-ports", line, StringComparison.Ordinal);
        Assert.DoesNotContain("--max-sessions", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_chosen_cone_range_reaches_the_service()
    {
        var line = ExecStart(new AgentOptions { ConePorts = new PortRange(50000, 50099) });

        Assert.Contains(" --cone-ports 50000-50099", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Turning_full_cone_off_reaches_the_service()
    {
        var line = ExecStart(new AgentOptions { FullCone = false, ConePorts = new PortRange(50000, 50099) });

        Assert.Contains(" --no-full-cone", line, StringComparison.Ordinal);
        Assert.DoesNotContain("--cone-ports", line, StringComparison.Ordinal);
    }

    [Fact]
    public void A_session_limit_reaches_the_service()
    {
        // It never did: install accepted --max-sessions and the service ran with 64.
        var line = ExecStart(new AgentOptions { MaxSessions = 8 });

        Assert.Contains(" --max-sessions 8", line, StringComparison.Ordinal);
    }

    [Fact]
    public void Declared_own_addresses_reach_the_service()
    {
        var line = ExecStart(new AgentOptions
        {
            Policy = new DestinationPolicy { LocalAddresses = new HashSet<IPAddress> { IPAddress.Parse("203.0.113.5") } },
        });

        Assert.Contains(" --own-address 203.0.113.5", line, StringComparison.Ordinal);
    }

    [Fact]
    public void The_unit_keeps_its_listening_address_and_port()
    {
        var line = ExecStart(new AgentOptions { Listen = IPAddress.Parse("203.0.113.5"), Port = 9000 });

        Assert.Contains(" --listen 203.0.113.5 --port 9000", line, StringComparison.Ordinal);
    }
}
