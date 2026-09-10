using System.Net;
using Yura.Core.Rules;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Runtime;

/// <summary>Configuration the app pushes that is not a rule or a proxy.</summary>
public sealed record DaemonOptions
{
    public DnsPolicy DnsPolicy { get; init; } = DnsPolicy.ThroughProxy;
}

public enum FlowPlanKind
{
    Proxy,
    Direct,
    Block,

    /// <summary>The rule asked for something that cannot be done; the flow is refused with a reason.</summary>
    Fail,
}

/// <summary>What a listener should do with one captured flow, and why.</summary>
public sealed record FlowPlan
{
    public required FlowPlanKind Kind { get; init; }

    public IReadOnlyList<ProxyHop> Hops { get; init; } = [];

    /// <summary>The proxy or chain name for Proxy, "Direct" or "Blocked" otherwise.</summary>
    public required string RouteName { get; init; }

    public Guid? RuleId { get; init; }

    public string? RuleName { get; init; }

    public int? OwnerPid { get; init; }

    public string? ProcessName { get; init; }

    public string? Host { get; init; }

    /// <summary>
    /// Where the daemon actually dials when that differs from what the application asked for:
    /// a WireGuard exit's own resolver in place of one that is unreachable from the far end.
    /// Null means the original destination.
    /// </summary>
    public IPEndPoint? DialDestination { get; init; }

    public string? Explanation { get; init; }

    public string? FailureReason { get; init; }
}

/// <summary>What a listener asks the runtime when a flow arrives.</summary>
public interface IRouteDecider
{
    /// <summary>True when some enabled rule names a host, so listeners should sniff for names.</summary>
    bool SniffHosts { get; }

    /// <summary>DNS answers seen by the relay feed this, so later flows have a name to match.</summary>
    DnsCache Dns { get; }

    /// <summary>Decides the route for one captured flow.</summary>
    FlowPlan Decide(RuleSlot slot, IPEndPoint client, IPEndPoint destination, TransportProtocol protocol, string? sniffedHost);
}
