using System.Net;
using System.Net.Sockets;
using Yura.Core.Connections;
using Yura.Core.Ipc;
using Yura.Core.Processes;
using Yura.Core.Rules;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon;

/// <summary>
/// Builds the Connections page: every flow the daemon is relaying, merged with every socket
/// the kernel holds for processes the rules cover, each labelled with what is actually
/// known about its route.
/// </summary>
/// <remarks>
/// The merge is what lets the page distinguish the three things the specification insists
/// on telling apart: a connection confirmed on the proxy (the daemon holds it), a connection
/// opened before the rule that is still on its previous route (the kernel holds it, the
/// daemon does not, and the process is governed), and a connection that was never captured
/// because nothing captures it (loopback, the proxy itself, an ungoverned process).
/// </remarks>
public sealed class ConnectionLister
{
    private readonly RuleRuntime _runtime;
    private readonly FlowRegistry _flows;
    private readonly SocketOwnership _ownership;
    private readonly ProcProcessSource _processes;

    public ConnectionLister(RuleRuntime runtime, FlowRegistry flows, SocketOwnership ownership, ProcProcessSource processes)
    {
        _runtime = runtime;
        _flows = flows;
        _ownership = ownership;
        _processes = processes;
    }

    public List<ConnectionDto> List(int? pidFilter)
    {
        var state = _runtime.State;
        var flows = _flows.Snapshot();
        var sockets = _ownership.Snapshot();
        var names = new Dictionary<int, ProcessSnapshot?>();
        var claimed = new HashSet<long>();
        var rows = new List<ConnectionDto>(sockets.Count + flows.Count);

        // Indexed by the application's side, which is what a socket and its flow share, so
        // matching is a lookup per socket rather than a walk of every flow per socket.
        var flowsByClient = flows.ToLookup(f => (f.Protocol, f.Client));

        var proxyEndpoints = state.Proxies.Values
            .Select(p => IPAddress.TryParse(p.Host, out var a) ? new IPEndPoint(a, p.Port) : null)
            .Where(e => e is not null)
            .Select(e => e!)
            .ToHashSet();

        ProcessSnapshot? Lookup(int pid)
        {
            if (!names.TryGetValue(pid, out var snapshot))
            {
                snapshot = _processes.TryRead(pid);
                names[pid] = snapshot;
            }

            return snapshot;
        }

        foreach (var socket in sockets)
        {
            if (socket.State == "LISTEN" || socket.OwnerPid == Environment.ProcessId)
            {
                continue;
            }

            if (pidFilter is { } wanted && socket.OwnerPid != wanted)
            {
                continue;
            }

            var protocol = socket.Protocol == ProtocolType.Tcp ? TransportProtocol.Tcp : TransportProtocol.Udp;

            // A captured connection appears twice in the kernel: the application's socket and
            // ours. Reporting the application's socket as the flow the daemon holds for it
            // keeps one row per connection and lets the flow's evidence speak.
            var flow = flowsByClient[(protocol, socket.Local)].FirstOrDefault(f =>
                (protocol == TransportProtocol.Udp || f.OriginalDestination.Equals(socket.Remote)) &&
                !claimed.Contains(f.Id));
            if (flow is not null)
            {
                claimed.Add(flow.Id);
                rows.Add(FromFlow(flow, socket.OwnerPid, socket.OwnerPid is { } fp ? Lookup(fp)?.DisplayName : null, socket.State));
                continue;
            }

            if (socket.Protocol == ProtocolType.Tcp && socket.Remote.Port == 0)
            {
                continue; // Not connected to anything yet.
            }

            var process = socket.OwnerPid is { } pid ? Lookup(pid) : null;
            var (route, ruleId, ruleName, note) = Classify(state, socket, process);
            rows.Add(new ConnectionDto
            {
                Id = $"s:{socket.Inode}",
                Pid = socket.OwnerPid,
                ProcessName = process?.DisplayName,
                Local = socket.Local.ToString(),
                Remote = socket.Remote.Port == 0 ? "*" : socket.Remote.ToString(),
                Protocol = protocol,
                State = socket.State is "ESTABLISHED" or "UDP" ? ConnectionState.Established
                    : socket.State is "SYN_SENT" or "SYN_RECV" ? ConnectionState.Establishing
                    : ConnectionState.Closing,
                KernelState = socket.State,
                Route = route,
                RuleId = ruleId,
                RuleName = ruleName,
                Host = _runtime.Dns.Lookup(socket.Remote.Address),
                Note = note,
            });
        }

        // Flows whose application socket has already gone (closed, failed) still carry a
        // failure reason worth showing.
        foreach (var flow in flows)
        {
            if (claimed.Contains(flow.Id))
            {
                continue;
            }

            if (pidFilter is { } wanted && flow.OwnerPid != wanted)
            {
                continue;
            }

            rows.Add(FromFlow(flow, flow.OwnerPid, flow.ProcessName, null));
        }

        return rows
            .OrderBy(r => r.ProcessName ?? "￿", StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Pid)
            .ThenByDescending(r => r.CreatedAtUtc)
            .ToList();
    }

    private (RouteObservation Route, Guid? RuleId, string? RuleName, string? Note) Classify(
        DeciderState state, OwnedSocket socket, ProcessSnapshot? process)
    {
        if (socket.OwnerPid is null)
        {
            return (RouteObservation.Unknown, null, null, "The owning process could not be determined.");
        }

        if (socket.Remote.Port == 0)
        {
            return (RouteObservation.Unknown, null, null, "Unconnected UDP socket; its datagrams appear as separate flows.");
        }

        if (IPAddress.IsLoopback(socket.Remote.Address))
        {
            return (RouteObservation.ConfirmedDirect, null, null, "Loopback is never proxied.");
        }

        var proxyTarget = state.Proxies.Values.FirstOrDefault(p =>
            IPAddress.TryParse(p.Host, out var a) && a.Equals(socket.Remote.Address) && p.Port == socket.Remote.Port);
        if (proxyTarget is not null)
        {
            return (RouteObservation.ConfirmedDirect, null, null, $"Traffic to the configured proxy '{proxyTarget.Name}' is never captured.");
        }

        var groupName = CgroupManager.GroupOf(socket.OwnerPid.Value);
        if (groupName is null || !state.GroupsByName.TryGetValue(groupName, out var group))
        {
            return (RouteObservation.ConfirmedDirect, null, null, null);
        }

        var decision = RuleEvaluator.Evaluate(state.OrderedRules, new RoutingRequest
        {
            Process = process,
            DestinationAddress = socket.Remote.Address,
            DestinationPort = (ushort)socket.Remote.Port,
            Protocol = socket.Protocol == ProtocolType.Tcp ? TransportProtocol.Tcp : TransportProtocol.Udp,
            DestinationHost = _runtime.Dns.Lookup(socket.Remote.Address),
            ClassifierMatchedRuleIds = group.RuleIds,
        });

        if (decision.Action is RuleAction.Direct)
        {
            return (RouteObservation.ConfirmedDirect, decision.MatchedRule?.Id, decision.MatchedRule?.Name, null);
        }

        // The rule would capture a new connection like this one, and the daemon does not
        // hold it: it was opened before the rule and is still on whatever route it had.
        return (RouteObservation.PreExistingPreviousRoute, decision.MatchedRule?.Id, decision.MatchedRule?.Name,
            "Opened before the rule was applied. Restart the application, or reconnect, to move it.");
    }

    private static ConnectionDto FromFlow(Flow flow, int? pid, string? processName, string? kernelState) => new()
    {
        Id = $"f:{flow.Id}",
        Pid = pid ?? flow.OwnerPid,
        ProcessName = processName ?? flow.ProcessName,
        Local = flow.Client.ToString(),
        Remote = flow.OriginalDestination.ToString(),
        Protocol = flow.Protocol,
        State = flow.State,
        KernelState = kernelState,
        Route = flow.Route,
        RuleId = flow.RuleId,
        RuleName = flow.RuleName,
        ProxyName = flow.ProxyName,
        BytesUp = flow.BytesUp,
        BytesDown = flow.BytesDown,
        CreatedAtUtc = flow.CreatedAtUtc,
        FailureReason = flow.FailureReason,
        Host = flow.Host,
        Note = flow.Note,
    };
}
