using Yura.Core.Rules;

namespace Yura.Daemon.Runtime;

/// <summary>What the kernel does with traffic that a slot claims.</summary>
public enum SlotDisposition
{
    /// <summary>Mark it and hand it to this slot's transparent listener.</summary>
    Proxy,

    /// <summary>Refuse it: TCP reset, ICMP unreachable for UDP.</summary>
    Block,

    /// <summary>
    /// Let it out untouched. Exists so an explicit Direct rule can win over a broader
    /// rule below it in the list, exactly as first-match evaluation promises.
    /// </summary>
    Direct,
}

/// <summary>
/// One installed rule's kernel footprint: a cgroup, an fwmark, a listener port.
/// </summary>
/// <remarks>
/// The port is the whole trick. TPROXY hands every flow a slot captures to that slot's own
/// listener, so the listener knows which rule — and therefore which proxy — a flow belongs
/// to from the socket it arrived on. No shared table, no lookup, no ambiguity.
/// </remarks>
public sealed record RuleSlot
{
    public const int MaxSlots = 250;
    private const int PortBase = 17800;

    public required int Index { get; init; }

    public required RoutingRule Rule { get; init; }

    public required SlotDisposition Disposition { get; init; }

    /// <summary>cgroup directory name, e.g. <c>s007</c>.</summary>
    public string Name => $"s{Index:D3}";

    /// <summary>Exact fwmark for this slot, within the range PolicyRouting selects.</summary>
    public uint Mark => Linux.PolicyRouting.MarkBase + (uint)Index;

    /// <summary>Transparent listener port. Only meaningful for Proxy slots.</summary>
    public int Port => PortBase + Index;

    /// <summary>True when the slot needs a cgroup, i.e. it selects on process rather than only destination.</summary>
    public bool UsesCgroup => Rule.Process.Kind != ProcessSelectorKind.Any;
}
