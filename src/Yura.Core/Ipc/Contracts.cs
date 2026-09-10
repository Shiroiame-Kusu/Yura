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
    /// <summary>status | set-proxies | apply-rule | remove-rule | list-rules | list-flows | probe-proxy | connection-counts</summary>
    public required string Op { get; init; }

    public RuleDto? Rule { get; init; }

    public Guid? RuleId { get; init; }

    public List<ProxyDto>? Proxies { get; init; }

    public ProxyDto? Proxy { get; init; }
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

    public ProbeResultDto? Probe { get; init; }

    public Dictionary<int, int>? Counts { get; init; }

    public static IpcResponse Failure(string error, string? diagnostics = null) =>
        new() { Ok = false, Error = error, Diagnostics = diagnostics };
}

public sealed class StatusDto
{
    public required string Version { get; init; }

    public required int ActiveRules { get; init; }

    public required int ActiveFlows { get; init; }

    public required long UptimeSeconds { get; init; }
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

    public static ProxyDto From(ProxyEndpoint endpoint, string? password) => new()
    {
        Id = endpoint.Id,
        Name = endpoint.Name,
        Protocol = endpoint.Protocol,
        Host = endpoint.Host,
        Port = endpoint.Port,
        Username = endpoint.Username,
        Password = password,
    };

    public ProxyEndpoint ToEndpoint() => new()
    {
        Id = Id,
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
    };
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

    private static HostPattern ParseHost(string text) => text switch
    {
        _ when text.StartsWith("*.", StringComparison.Ordinal) => new HostPattern(HostMatchKind.Suffix, text[2..]),
        _ when text.StartsWith('*') && text.EndsWith('*') && text.Length > 2 =>
            new HostPattern(HostMatchKind.Keyword, text[1..^1]),
        _ => new HostPattern(HostMatchKind.Exact, text),
    };

    private static IPNetwork ParseNetwork(string text)
    {
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

    public required Guid RuleId { get; init; }

    public required string ProxyName { get; init; }

    public required long BytesUp { get; init; }

    public required long BytesDown { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public string? FailureReason { get; init; }
}
