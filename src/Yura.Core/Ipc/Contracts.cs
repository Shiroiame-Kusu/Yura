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

    /// <summary>
    /// The protocol's options, for code that can only pass options. Both ends serialize through
    /// <see cref="IpcJsonContext"/> directly, which is what NativeAOT can compile.
    /// </summary>
    public static JsonSerializerOptions Json => IpcJsonContext.Default.Options;
}

public sealed class IpcRequest
{
    /// <summary>
    /// ping | status | set-proxies | set-options | apply-rule | remove-rule | list-rules |
    /// list-flows | list-connections | connection-counts | probe-proxy | measure |
    /// nat-test | dump-ruleset | log
    /// </summary>
    public required string Op { get; init; }

    public RuleDto? Rule { get; init; }

    /// <summary>
    /// For apply-rule: also abort the covered processes' open connections whose route this
    /// rule changes, so it governs them too instead of only the next connection.
    /// </summary>
    public bool ResetExisting { get; init; }

    public Guid? RuleId { get; init; }

    public List<ProxyDto>? Proxies { get; init; }

    public List<ChainDto>? Chains { get; init; }

    public ProxyDto? Proxy { get; init; }

    public OptionsDto? Options { get; init; }

    public MeasureRequestDto? Measure { get; init; }

    public NatTestRequestDto? NatTest { get; init; }

    /// <summary>For list-connections: restrict to one owning pid.</summary>
    public int? Pid { get; init; }

    /// <summary>For log: how many trailing lines to return.</summary>
    public int? Lines { get; init; }
}

public sealed class IpcResponse
{
    public required bool Ok { get; init; }

    /// <summary>
    /// Identifies the running daemon process, and changes when it restarts. Stamped on every
    /// response by the server.
    /// </summary>
    /// <remarks>
    /// The daemon keeps nothing across a restart, so a client that sees this change knows the
    /// proxies and rules it pushed are gone and must push them again — whether or not it ever
    /// saw the daemon go away in between. A restart under systemd takes two seconds, which is
    /// shorter than the gap between two requests.
    /// </remarks>
    public string? Instance { get; set; }

    public string? Error { get; init; }

    public string? Diagnostics { get; init; }

    public StatusDto? Status { get; init; }

    public ApplyResultDto? Apply { get; init; }

    public List<RuleDto>? Rules { get; init; }

    public List<FlowDto>? Flows { get; init; }

    public List<ConnectionDto>? Connections { get; init; }

    public ProbeResultDto? Probe { get; init; }

    public MeasurementDto? Measurement { get; init; }

    public NatTestResultDto? Nat { get; init; }

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

    /// <summary>
    /// Processes placed in their rule's cgroup by the exec fast path, before they could open a
    /// socket. A socket's cgroup is fixed when it is created, so this is the count of programs
    /// whose first connection was classified in time rather than escaping the rule.
    /// </summary>
    public long ClassifiedOnExec { get; init; }

    public DnsPolicy DnsPolicy { get; init; }

    public string? KernelRelease { get; init; }

    public string? NftVersion { get; init; }

    public string? CgroupRoot { get; init; }

    public string? SocketPath { get; init; }

    public List<uint> AllowedUids { get; set; } = [];

    /// <summary>Environment checks the daemon ran at startup, each with its outcome.</summary>
    public List<CheckDto> Checks { get; set; } = [];

    /// <summary>Every WireGuard exit the daemon was given, up or not, with what the kernel reports.</summary>
    public List<TunnelDto> Tunnels { get; set; } = [];

    /// <summary>Every Yura agent exit the daemon was given, connected or not.</summary>
    public List<AgentDto> Agents { get; set; } = [];
}

/// <summary>
/// The state of one Yura agent exit. Never carries the token.
/// </summary>
public sealed class AgentDto
{
    public required Guid ProxyId { get; init; }

    public required string Name { get; init; }

    /// <summary>True when the control session is up. TCP flows work without it; UDP does not.</summary>
    public required bool Connected { get; init; }

    /// <summary>What the agent calls itself, which need not be what the exit is named here.</summary>
    public string? AgentName { get; init; }

    public string? AgentVersion { get; init; }

    /// <summary>Round trip to the agent from the last ping on the control connection.</summary>
    public double? RoundTripMilliseconds { get; init; }

    /// <summary>Whether the agent offered the datagram channel and it was set up.</summary>
    public bool Udp { get; init; }

    /// <summary>Whether the agent gave full-cone UDP, so a peer-to-peer game can be reached through it.</summary>
    public bool FullCone { get; init; }

    /// <summary>The resolver the agent offered, used for lookups from processes on this exit.</summary>
    public string? Resolver { get; init; }

    public string? Failure { get; init; }
}

/// <summary>The state of one WireGuard exit as the kernel reports it. Never carries a key.</summary>
public sealed class TunnelDto
{
    public required Guid ProxyId { get; init; }

    public required string Name { get; init; }

    /// <summary>Kernel interface name, e.g. <c>yura-wg0</c>, when the tunnel is configured.</summary>
    public string? Interface { get; init; }

    /// <summary>True when the interface exists and is configured. Says nothing about the peer answering.</summary>
    public required bool Up { get; init; }

    /// <summary>Why the tunnel could not be brought up, when it could not.</summary>
    public string? Failure { get; init; }

    /// <summary>When the peer last completed a handshake. Null when it never has since the interface came up.</summary>
    public DateTimeOffset? LatestHandshakeUtc { get; init; }

    public long RxBytes { get; init; }

    public long TxBytes { get; init; }

    /// <summary>The peer address the kernel is currently sending to.</summary>
    public string? Endpoint { get; init; }
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

    /// <summary>
    /// Connections that were aborted so the rule would apply to them as well. Null when the
    /// daemon was not asked to. A socket's cgroup is fixed when it is created, so this is the
    /// only way a rule reaches a connection older than itself.
    /// </summary>
    public int? ResetConnections { get; init; }

    /// <summary>Why connections that should have been aborted were not.</summary>
    public string? ResetFailure { get; init; }

    public List<string> Warnings { get; set; } = [];
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

    public int Samples { get; set; } = 5;
}

/// <summary>What to test the NAT behaviour of.</summary>
public sealed class NatTestRequestDto
{
    /// <summary>Test this route as well as the direct path. Null tests direct only.</summary>
    public Guid? ProxyId { get; init; }

    public Guid? ChainId { get; init; }

    /// <summary>
    /// STUN servers as <c>host:port</c>. Empty uses the daemon's defaults.
    /// </summary>
    /// <remarks>
    /// Overridable because a NAT test necessarily talks to a third party, and anyone who
    /// would rather it were their own third party must be able to say so. Which servers
    /// actually answered comes back in the result.
    /// </remarks>
    public List<string> Servers { get; set; } = [];

    /// <summary>
    /// Skip the direct half. Only useful when the direct path cannot reach the servers the
    /// route can, which is how the acceptance tests prove a result came from the route.
    /// </summary>
    public bool RouteOnly { get; init; }
}

/// <summary>The NAT behaviour of one path, and what it means for peer-to-peer traffic.</summary>
public sealed class NatReportDto
{
    public required NatVerdict Verdict { get; init; }

    public NatMapping Mapping { get; init; }

    public NatFiltering Filtering { get; init; }

    /// <summary>The address the far side sees. Null when nothing answered.</summary>
    public string? MappedEndpoint { get; init; }

    /// <summary>Null when it could not be told, which is the case for every relayed route.</summary>
    public bool? BehindNat { get; init; }

    /// <summary>What was tried and what came back, for the expandable detail.</summary>
    public string? Diagnostics { get; init; }

    /// <summary>The servers that answered, so a verdict is never credited to a silent one.</summary>
    public List<string> Servers { get; set; } = [];

    public double? RoundTripMilliseconds { get; init; }

    /// <summary>
    /// True when peer-to-peer traffic can be expected to work with most peers.
    /// </summary>
    /// <remarks>
    /// A method rather than a property so it stays out of the serialised shape: the wire
    /// carries what was measured, and this is a reading of it.
    /// </remarks>
    public bool SupportsP2P() => Verdict is NatVerdict.Open or NatVerdict.Moderate;

    /// <summary>NAT1 to NAT4, or null when the measurement does not settle which.</summary>
    /// <remarks>A method for the same reason as <see cref="SupportsP2P"/>.</remarks>
    public int? TypeNumber() => NatClassifier.TypeNumber(Verdict, Filtering);
}

/// <summary>A NAT test: the direct path, and the route, measured the same way.</summary>
public sealed class NatTestResultDto
{
    /// <summary>Null only when the caller asked for the route alone.</summary>
    public NatReportDto? Direct { get; init; }

    /// <summary>Null when no route was named.</summary>
    public NatReportDto? Routed { get; init; }

    public string? RouteName { get; init; }

    public DateTimeOffset TestedAtUtc { get; init; }
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

    public List<double> RoundTripsMilliseconds { get; set; } = [];
}

// A record rather than a class: the split legs are added after the samples are taken, by the
// one caller that can find them out, and copying is how that is done without a settable field.
public sealed record MeasurementDto
{
    /// <summary>The literal address both sides were measured against.</summary>
    public required string Target { get; init; }

    /// <summary>What was measured: "TCP connect".</summary>
    public required string Method { get; init; }

    public required SampleSetDto Direct { get; init; }

    public SampleSetDto? Routed { get; init; }

    /// <summary>Where the routed time went, when the route can say. Null when it cannot.</summary>
    public RouteLegsDto? Legs { get; init; }

    /// <summary>
    /// The route's proxy reports a connection made before it has made it, so a connect through it
    /// times the proxy alone. <see cref="Routed"/> is null then: there is no figure to give.
    /// </summary>
    public bool RouteAnswersBeforeConnecting { get; init; }

    public required DateTimeOffset MeasuredAtUtc { get; init; }
}

/// <summary>
/// The routed figure split in two: this machine to the agent, and the agent onwards.
/// </summary>
/// <remarks>
/// Only a Yura agent can report this, because only it will measure a destination from where
/// it is standing. It is the difference between knowing a route is faster and knowing why —
/// and it is what tells a user whether a better agent would help, or whether their own
/// connection to it is the problem.
/// </remarks>
public sealed class RouteLegsDto
{
    public required string AgentName { get; init; }

    /// <summary>Round trip from here to the agent, on its control connection.</summary>
    public double? ToAgentMilliseconds { get; init; }

    /// <summary>Round trip from the agent to the target, measured by the agent.</summary>
    public double? FromAgentMilliseconds { get; init; }

    /// <summary>Why the agent could not measure it, when it could not.</summary>
    public string? Failure { get; init; }
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

    /// <summary>The WireGuard preshared key. App-to-daemon only, like <see cref="Password"/>.</summary>
    public string? PresharedKey { get; init; }

    public WireGuardDto? WireGuard { get; init; }

    /// <summary>The agent's pinned key. Not a secret — it is a public key — so it travels plainly.</summary>
    public AgentDetailsDto? Agent { get; init; }

    public static ProxyDto From(ProxyEndpoint endpoint, ProxySecrets secrets) => new()
    {
        Id = endpoint.Id,
        Name = endpoint.Name,
        Protocol = endpoint.Protocol,
        Host = endpoint.Host,
        Port = endpoint.Port,
        Username = endpoint.Username,
        Password = secrets.Password,
        PresharedKey = secrets.PresharedKey,
        AllowInvalidCertificate = endpoint.AllowInvalidCertificate,
        WireGuard = endpoint.WireGuard is { } wg ? WireGuardDto.From(wg) : null,
        Agent = endpoint.Agent is { } agent
            ? new AgentDetailsDto { Fingerprint = agent.Fingerprint, AgentLabel = agent.AgentLabel }
            : null,
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
        WireGuard = WireGuard?.ToSettings(),
        Agent = Agent is { } agent
            ? new AgentSettings { Fingerprint = agent.Fingerprint, AgentLabel = agent.AgentLabel }
            : null,
    };

    public ProxySecrets ToSecrets() => new(Password, PresharedKey);
}

/// <summary>What identifies a Yura agent: its pinned public key, and what it calls itself.</summary>
public sealed class AgentDetailsDto
{
    public required string Fingerprint { get; init; }

    public string? AgentLabel { get; init; }
}

/// <summary>The non-secret WireGuard settings, flat for the wire.</summary>
public sealed class WireGuardDto
{
    public required string PeerPublicKey { get; init; }

    public List<string> Addresses { get; set; } = [];

    public List<string> Dns { get; set; } = [];

    public List<string> AllowedIps { get; set; } = [];

    public int? Mtu { get; init; }

    public int PersistentKeepalive { get; init; }

    public static WireGuardDto From(WireGuardSettings settings) => new()
    {
        PeerPublicKey = settings.PeerPublicKey,
        Addresses = settings.Addresses.ToList(),
        Dns = settings.DnsServers.ToList(),
        AllowedIps = settings.AllowedIps.ToList(),
        Mtu = settings.Mtu,
        PersistentKeepalive = settings.PersistentKeepalive,
    };

    public WireGuardSettings ToSettings() => new()
    {
        PeerPublicKey = PeerPublicKey,
        Addresses = Addresses.ToArray(),
        DnsServers = Dns.ToArray(),
        AllowedIps = AllowedIps.Count == 0 ? ["0.0.0.0/0", "::/0"] : AllowedIps.ToArray(),
        Mtu = Mtu,
        PersistentKeepalive = PersistentKeepalive,
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

    public bool Enabled { get; set; } = true;

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
    public List<string> Hosts { get; set; } = [];

    public List<string> Networks { get; set; } = [];

    public List<string> Ports { get; set; } = [];

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
