using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Yura.Core.Connections;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Ipc;

/// <summary>
/// The wire protocol between the unprivileged app and the privileged daemon.
/// </summary>
/// <remarks>
/// Newline-delimited JSON over a Unix domain socket: one request object per line, one
/// response object per line, in order. The transport is trivially inspectable with
/// <c>socat</c>, which matters more for a privileged boundary than efficiency does.
///
/// The DTOs are flat on purpose. The domain types use records with polymorphic actions and
/// <see cref="IPNetwork"/> values that do not round-trip through JSON cleanly; the flat
/// shapes here do, and the conversions are the single place that mapping lives.
/// </remarks>
public static class IpcProtocol
{
    public const string DefaultSocketPath = "/run/yura/yura.sock";

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}

public sealed class IpcRequest
{
    /// <summary>
    /// status | set-proxies | set-options | apply-rule | remove-rule | list-rules |
    /// list-flows | list-connections | connection-counts | probe-proxy | measure |
    /// dump-ruleset | log
    /// </summary>
    public required string Op { get; init; }

    public RuleDto? Rule { get; init; }

    public Guid? RuleId { get; init; }

    public List<ProxyDto>? Proxies { get; init; }

    public List<ChainDto>? Chains { get; init; }

    public ProxyDto? Proxy { get; init; }

    public OptionsDto? Options { get; init; }

    public MeasureRequestDto? Measure { get; init; }

    /// <summary>For list-connections: restrict to one owning pid.</summary>
    public int? Pid { get; init; }

    /// <summary>For log: how many trailing lines to return.</summary>
    public int? Lines { get; init; }
}

public sealed class IpcResponse
{
    public required bool Ok { get; init; }

    public string? Error { get; init; }

    public string? Diagnostics { get; init; }

    public StatusDto? Status { get; init; }

    public ApplyResultDto? Apply { get; init; }

    public List<RuleDto>? Rules { get; init; }

    public List<FlowDto>? Flows { get; init; }

    public List<ConnectionDto>? Connections { get; init; }

    public ProbeResultDto? Probe { get; init; }

    public MeasurementDto? Measurement { get; init; }

    public Dictionary<int, int>? Counts { get; init; }

    /// <summary>For dump-ruleset: the installed nftables table, routes and rules as text.</summary>
    public string? Ruleset { get; init; }

    public List<string>? Log { get; init; }

    public static IpcResponse Failure(string error, string? diagnostics = null) =>
        new() { Ok = false, Error = error, Diagnostics = diagnostics };
}

public sealed class StatusDto
{
    public required string Version { get; init; }

    public required int ActiveRules { get; init; }

    public required int ActiveFlows { get; init; }

    public required long UptimeSeconds { get; init; }

    /// <summary>Number of process groups (cgroups) currently in use.</summary>
    public int ActiveGroups { get; init; }

    /// <summary>"netlink" when process events are delivered by the kernel, otherwise why not.</summary>
    public string? ProcessWatcher { get; init; }

    public DnsPolicy DnsPolicy { get; init; }

    public string? KernelRelease { get; init; }

    public string? NftVersion { get; init; }

    public string? CgroupRoot { get; init; }

    public string? SocketPath { get; init; }

    public List<uint> AllowedUids { get; init; } = [];

    /// <summary>Environment checks the daemon ran at startup, each with its outcome.</summary>
    public List<CheckDto> Checks { get; init; } = [];
}

public sealed class CheckDto
{
    public required string Name { get; init; }

    public required bool Passed { get; init; }

    public string? Detail { get; init; }
}

public sealed class OptionsDto
{
    public DnsPolicy DnsPolicy { get; init; }
}

public sealed class ApplyResultDto
{
    public required bool Succeeded { get; init; }

    public string? FailureReason { get; init; }

    public string? Diagnostics { get; init; }

    public DateTimeOffset? ConfirmedAtUtc { get; init; }

    public int MigratedProcesses { get; init; }

    /// <summary>
    /// Sockets the covered processes already had open when the rule was applied. Those keep
    /// their previous route, so the UI must not claim they are proxied. Null means the count
    /// could not be established, which is different from zero.
    /// </summary>
    public int? PreExistingConnections { get; init; }

    public List<string> Warnings { get; init; } = [];
}

public sealed class ProbeResultDto
{
    public required bool Reachable { get; init; }

    public double? HandshakeMilliseconds { get; init; }

    public CapabilityState Udp { get; init; }

    public string? FailureReason { get; init; }

    public string? Diagnostics { get; init; }
}

public sealed class MeasureRequestDto
{
    public required string Host { get; init; }

    public required ushort Port { get; init; }

    /// <summary>Measure through this proxy as well as directly. Null measures direct only.</summary>
    public Guid? ProxyId { get; init; }

    public Guid? ChainId { get; init; }

    public int Samples { get; init; } = 5;
}

/// <summary>One side of a direct-versus-routed comparison, measured the same way.</summary>
public sealed class SampleSetDto
{
    public required int Samples { get; init; }

    public required int Successes { get; init; }

    /// <summary>Median round trip of the successful samples. Null when none succeeded.</summary>
    public double? LatencyMilliseconds { get; init; }

    /// <summary>Mean absolute deviation of the successful samples. Null with fewer than two.</summary>
    public double? JitterMilliseconds { get; init; }

    public double? LossPercent { get; init; }

    public string? FailureReason { get; init; }

    public List<double> RoundTripsMilliseconds { get; init; } = [];
}

public sealed class MeasurementDto
{
    /// <summary>The literal address both sides were measured against.</summary>
    public required string Target { get; init; }

    /// <summary>What was measured: "TCP connect".</summary>
    public required string Method { get; init; }

    public required SampleSetDto Direct { get; init; }

    public SampleSetDto? Routed { get; init; }

    public required DateTimeOffset MeasuredAtUtc { get; init; }
}

public sealed class ProxyDto
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public required ProxyProtocol Protocol { get; init; }

    public required string Host { get; init; }

    public required ushort Port { get; init; }

    public string? Username { get; init; }

    /// <summary>
    /// Sent app-to-daemon only, over a root-owned local socket. Never written to disk by
    /// either side and never echoed back.
    /// </summary>
    public string? Password { get; init; }

    public bool AllowInvalidCertificate { get; init; }

    public static ProxyDto From(ProxyEndpoint endpoint, string? password) => new()
    {
        Id = endpoint.Id,
        Name = endpoint.Name,
        Protocol = endpoint.Protocol,
        Host = endpoint.Host,
        Port = endpoint.Port,
        Username = endpoint.Username,
        Password = password,
        AllowInvalidCertificate = endpoint.AllowInvalidCertificate,
    };

    public ProxyEndpoint ToEndpoint() => new()
    {
        Id = Id,
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        AllowInvalidCertificate = AllowInvalidCertificate,
    };
}

public sealed class ChainDto
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public required List<Guid> Hops { get; init; }

    public static ChainDto From(ProxyChain chain) => new()
    {
        Id = chain.Id,
        Name = chain.Name,
        Hops = chain.Hops.ToList(),
    };

    public ProxyChain ToChain() => new() { Id = Id, Name = Name, Hops = Hops.ToArray() };
}

public sealed class RuleDto
{
    public required Guid Id { get; init; }

    public required int Order { get; init; }

    public required string Name { get; init; }

    public bool Enabled { get; init; } = true;

    public required RuleOrigin Origin { get; init; }

    public required RuleLifetime Lifetime { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public string? Notes { get; init; }

    // -- process side
    public required ProcessSelectorKind ProcessKind { get; init; }

    public int? Pid { get; init; }

    public ulong? StartTicks { get; init; }

    public uint? Uid { get; init; }

    public string? BootId { get; init; }

    public string? ExecutablePath { get; init; }

    public string? ProcessName { get; init; }

    public DescendantPolicy Descendants { get; init; }

    public string? WineTargetExecutable { get; init; }

    public string? WinePrefix { get; init; }

    // -- destination side
    public List<string> Hosts { get; init; } = [];

    public List<string> Networks { get; init; } = [];

    public List<string> Ports { get; init; } = [];

    public TransportFilter Protocol { get; init; }

    // -- action
    /// <summary>direct | block | proxy | chain</summary>
    public required string Action { get; init; }

    public Guid? ProxyId { get; init; }

    public static RuleDto From(RoutingRule rule) => new()
    {
        Id = rule.Id,
        Order = rule.Order,
        Name = rule.Name,
        Enabled = rule.Enabled,
        Origin = rule.Origin,
        Lifetime = rule.Lifetime,
        CreatedAtUtc = rule.CreatedAtUtc,
        Notes = rule.Notes,
        ProcessKind = rule.Process.Kind,
        Pid = rule.Process.Identity?.Pid,
        StartTicks = rule.Process.Identity?.StartTicks,
        Uid = rule.Process.Identity?.Uid ?? rule.Process.Uid,
        BootId = rule.Process.Identity?.BootId,
        ExecutablePath = rule.Process.ExecutablePath,
        ProcessName = rule.Process.ProcessName,
        Descendants = rule.Process.Descendants,
        WineTargetExecutable = rule.Process.WineTargetExecutable,
        WinePrefix = rule.Process.WinePrefix,
        Hosts = rule.Destination.Hosts.Select(h => h.ToString()).ToList(),
        Networks = rule.Destination.Networks.Select(n => n.ToString()).ToList(),
        Ports = rule.Destination.Ports.Select(p => p.ToString()).ToList(),
        Protocol = rule.Destination.Protocol,
        Action = rule.Action switch
        {
            RuleAction.Block => "block",
            RuleAction.Proxy => "proxy",
            RuleAction.Chain => "chain",
            _ => "direct",
        },
        ProxyId = rule.Action switch
        {
            RuleAction.Proxy p => p.EndpointId,
            RuleAction.Chain c => c.ChainId,
            _ => null,
        },
    };

    public RoutingRule ToRule()
    {
        ProcessIdentity? identity = null;
        if (ProcessKind == ProcessSelectorKind.Instance)
        {
            if (Pid is null || StartTicks is null || Uid is null || BootId is null)
            {
                throw new InvalidDataException("an instance rule needs pid, startTicks, uid and bootId");
            }

            identity = new ProcessIdentity
            {
                Pid = Pid.Value,
                StartTicks = StartTicks.Value,
                Uid = Uid.Value,
                BootId = BootId,
            };
        }

        var hosts = Hosts.Select(ParseHost).ToList();
        var networks = Networks.Select(ParseNetwork).ToList();
        var ports = Ports.Select(text =>
            PortRange.TryParse(text, out var range)
                ? range
                : throw new InvalidDataException($"invalid port range '{text}'")).ToList();

        RuleAction action = Action switch
        {
            "block" => RuleAction.Block.Instance,
            "proxy" => new RuleAction.Proxy(ProxyId ?? throw new InvalidDataException("proxy rule needs proxyId")),
            "chain" => new RuleAction.Chain(ProxyId ?? throw new InvalidDataException("chain rule needs proxyId")),
            _ => RuleAction.Direct.Instance,
        };

        return new RoutingRule
        {
            Id = Id,
            Order = Order,
            Name = Name,
            Enabled = Enabled,
            Origin = Origin,
            Lifetime = Lifetime,
            CreatedAtUtc = CreatedAtUtc,
            Notes = Notes,
            Process = new ProcessSelector
            {
                Kind = ProcessKind,
                Identity = identity,
                ExecutablePath = ExecutablePath,
                ProcessName = ProcessName,
                Uid = ProcessKind == ProcessSelectorKind.User ? Uid : null,
                Descendants = Descendants,
                WineTargetExecutable = WineTargetExecutable,
                WinePrefix = WinePrefix,
            },
            Destination = new DestinationSelector
            {
                Hosts = hosts,
                Networks = networks,
                Ports = ports,
                Protocol = Protocol,
            },
            Action = action,
        };
    }

    public static HostPattern ParseHost(string text)
    {
        text = text.Trim();
        return text switch
        {
            _ when text.StartsWith("*.", StringComparison.Ordinal) => new HostPattern(HostMatchKind.Suffix, text[2..]),
            _ when text.StartsWith('*') && text.EndsWith('*') && text.Length > 2 =>
                new HostPattern(HostMatchKind.Keyword, text[1..^1]),
            _ => new HostPattern(HostMatchKind.Exact, text),
        };
    }

    public static IPNetwork ParseNetwork(string text)
    {
        text = text.Trim();
        if (IPNetwork.TryParse(text, out var network))
        {
            return network;
        }

        if (IPAddress.TryParse(text, out var address))
        {
            return new IPNetwork(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
        }

        throw new InvalidDataException($"invalid network '{text}'");
    }
}

public sealed class FlowDto
{
    public required long Id { get; init; }

    public required string Client { get; init; }

    public required string Destination { get; init; }

    public required TransportProtocol Protocol { get; init; }

    public required ConnectionState State { get; init; }

    public required RouteObservation Route { get; init; }

    public Guid? RuleId { get; init; }

    public string? RuleName { get; init; }

    public string? ProxyName { get; init; }

    public int? OwnerPid { get; init; }

    public string? ProcessName { get; init; }

    /// <summary>Destination name learned from SNI, an HTTP Host header or a DNS answer.</summary>
    public string? Host { get; init; }

    public required long BytesUp { get; init; }

    public required long BytesDown { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public string? FailureReason { get; init; }
}

/// <summary>
/// One row for the Connections page: a flow the daemon is relaying, or a kernel socket it
/// merely observed. The two are distinguished by <see cref="Route"/>, never conflated.
/// </summary>
public sealed class ConnectionDto
{
    public required string Id { get; init; }

    public int? Pid { get; init; }

    public string? ProcessName { get; init; }

    public required string Local { get; init; }

    public required string Remote { get; init; }

    public required TransportProtocol Protocol { get; init; }

    public ConnectionState State { get; init; }

    public string? KernelState { get; init; }

    public required RouteObservation Route { get; init; }

    public Guid? RuleId { get; init; }

    public string? RuleName { get; init; }

    public string? ProxyName { get; init; }

    public long? BytesUp { get; init; }

    public long? BytesDown { get; init; }

    public DateTimeOffset? CreatedAtUtc { get; init; }

    public string? FailureReason { get; init; }

    public string? Host { get; init; }

    public string? Note { get; init; }
}
