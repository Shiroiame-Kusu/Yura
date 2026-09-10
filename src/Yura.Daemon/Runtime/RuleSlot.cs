using Yura.Core.Rules;

namespace Yura.Daemon.Runtime;

/// <summary>What the kernel does with traffic that a slot claims.</summary>
public enum SlotDisposition
{
    /// <summary>
    /// Mark it and hand it to this slot's transparent listener, which decides per flow:
    /// proxy, chain, direct relay or block. Used for every proxy rule, and for any rule
    /// that names a host, since names are only visible to the listener.
    /// </summary>
    Capture,

    /// <summary>Refuse it in the kernel: TCP reset, ICMP unreachable for UDP.</summary>
    Block,

    /// <summary>
    /// Let it out untouched. Exists so an explicit Direct rule can win over a broader
    /// rule below it in the list, exactly as first-match evaluation promises.
    /// </summary>
    Direct,
}

/// <summary>
/// One installed rule's kernel footprint: an fwmark, a listener port, and the process
/// groups whose members it covers.
/// </summary>
/// <remarks>
/// The port is the whole trick. TPROXY hands every flow a slot captures to that slot's own
/// listener, so the listener knows which rule first claimed a flow from the socket it
/// arrived on. It still evaluates the full ordered list for that flow — host-name rules
/// above it may match once the name is known — but it starts from certain knowledge.
///
/// The port is assigned by the kernel when the listener binds, not derived from the index.
/// A fixed port range looks tidier but is wrong: <c>ip_local_port_range</c> commonly starts
/// low enough to include any range we might pick, so an unrelated outgoing connection can be
/// holding the port we wanted, and the rule would fail to install for no reason the user
/// could act on.
/// </remarks>
public sealed record RuleSlot
{
    public const int MaxSlots = 250;

    public required int Index { get; init; }

    public required RoutingRule Rule { get; init; }

    public required SlotDisposition Disposition { get; init; }

    /// <summary>Groups that contain this rule, i.e. every cgroup its match must be emitted against.</summary>
    public IReadOnlyList<ProcessGroup> Groups { get; init; } = [];

    /// <summary>
    /// The port this slot's transparent listener is bound to, or 0 before one exists.
    /// A Capture slot with no port has nothing to hand flows to and is not installed.
    /// </summary>
    public int Port { get; init; }

    /// <summary>Listener name, e.g. <c>s007</c>, for logs.</summary>
    public string Name => $"s{Index:D3}";

    /// <summary>Exact fwmark for this slot, within the range PolicyRouting selects.</summary>
    public uint Mark => Linux.PolicyRouting.MarkBase + (uint)Index;

    /// <summary>True when the rule selects on process rather than only destination.</summary>
    public bool UsesCgroup => Rule.Process.Kind != ProcessSelectorKind.Any;
}
