using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Linux;

/// <summary>
/// Builds and installs Yura's nftables ruleset.
/// </summary>
/// <remarks>
/// <see cref="Build"/> is pure: it turns slots into the script text and nothing else, so the
/// exact ruleset the daemon would install can be unit-tested and read without root. Every
/// install replaces the whole table in one <c>nft -f</c> transaction — the kernel applies
/// it atomically, so there is never a moment with half of the rules present.
///
/// Reinstalling on every change is also what makes cgroup recreation safe: nftables resolves
/// <c>socket cgroupv2</c> paths to cgroup ids at load time, so a rule that survived a cgroup
/// being deleted and recreated would silently stop matching.
/// </remarks>
public sealed class NftablesManager
{
    public const string TableName = "yura";

    private readonly CommandRunner _commands;
    private readonly Action<string> _log;

    public NftablesManager(CommandRunner commands, Action<string> log)
    {
        _commands = commands;
        _log = log;
    }

    /// <summary>
    /// Renders the complete ruleset for a set of slots.
    /// </summary>
    /// <param name="slots">Already in evaluation order. First match wins, as in the rule list.</param>
    /// <param name="proxies">Configured endpoints, so traffic to them is never captured.</param>
    /// <param name="skipped">Receives one line per rule that could not be expressed in the kernel.</param>
    public static string Build(
        IReadOnlyList<RuleSlot> slots,
        IReadOnlyList<ProxyEndpoint> proxies,
        List<string>? skipped = null)
    {
        var sb = new StringBuilder();

        // Declare-then-flush-then-define: one transaction, idempotent whether or not the
        // table already exists.
        sb.Append("table inet ").Append(TableName).Append(" { }\n");
        sb.Append("flush table inet ").Append(TableName).Append('\n');
        sb.Append("table inet ").Append(TableName).Append(" {\n");

        // ---- classify: decide, for every locally generated packet, which slot owns it.
        sb.Append("  chain classify {\n");
        sb.Append("    type route hook output priority mangle; policy accept;\n\n");

        sb.Append("    # Loop prevention. The daemon's own upstream sockets carry the bypass\n");
        sb.Append("    # mark; without this line the forwarder would capture itself.\n");
        sb.Append(CultureInfo.InvariantCulture, $"    meta mark 0x{PolicyRouting.BypassMark:x} return\n\n");

        sb.Append("    # Loopback is never proxied: it is not reachable from a proxy anyway, and\n");
        sb.Append("    # capturing it breaks local services that applications talk to.\n");
        sb.Append("    oifname \"lo\" return\n\n");

        if (proxies.Count > 0)
        {
            sb.Append("    # Traffic addressed to a configured proxy is the proxy's, never a rule's.\n");
            foreach (var proxy in proxies)
            {
                if (!IPAddress.TryParse(proxy.Host, out var address))
                {
                    // A host name resolves later, possibly to several addresses. The bypass
                    // mark on the daemon's own sockets already protects those flows; this
                    // line only exists for applications that talk to the proxy directly.
                    continue;
                }

                var family = address.AddressFamily == AddressFamily.InterNetworkV6 ? "ip6" : "ip";
                sb.Append(CultureInfo.InvariantCulture,
                    $"    {family} daddr {address} th dport {proxy.Port} return\n");
            }

            sb.Append('\n');
        }

        foreach (var slot in slots)
        {
            if (!TryRenderSlotMatch(slot, out var match, out var reason))
            {
                skipped?.Add($"{slot.Rule.Name}: {reason}");
                sb.Append(CultureInfo.InvariantCulture, $"    # slot {slot.Name} ({slot.Rule.Name}) skipped: {reason}\n");
                continue;
            }

            sb.Append(CultureInfo.InvariantCulture, $"    # {slot.Name}: {slot.Rule.Name}\n");
            switch (slot.Disposition)
            {
                case SlotDisposition.Proxy:
                    // 'accept' ends evaluation so a broader rule further down cannot
                    // overwrite the mark; the route hook still re-routes because the mark
                    // changed.
                    // 'counter' on every slot rule is deliberate: per-rule packet counts are
                    // the first thing to look at when a rule "does nothing", and they cost
                    // nothing to keep.
                    sb.Append(CultureInfo.InvariantCulture,
                        $"    {match} meta mark set 0x{slot.Mark:x} counter accept\n");
                    break;
                case SlotDisposition.Block:
                    sb.Append(CultureInfo.InvariantCulture,
                        $"    {match} meta l4proto tcp counter reject with tcp reset\n");
                    sb.Append(CultureInfo.InvariantCulture,
                        $"    {match} counter reject\n");
                    break;
                case SlotDisposition.Direct:
                    sb.Append(CultureInfo.InvariantCulture, $"    {match} counter accept\n");
                    break;
            }
        }

        sb.Append("  }\n\n");

        // ---- capture: hand each marked flow to its slot's listener.
        sb.Append("  chain capture {\n");
        sb.Append("    type filter hook prerouting priority mangle; policy accept;\n");
        foreach (var slot in slots.Where(s => s.Disposition == SlotDisposition.Proxy))
        {
            sb.Append(CultureInfo.InvariantCulture,
                $"    meta mark 0x{slot.Mark:x} meta l4proto tcp tproxy ip to :{slot.Port} counter accept\n");
            sb.Append(CultureInfo.InvariantCulture,
                $"    meta mark 0x{slot.Mark:x} meta l4proto udp tproxy ip to :{slot.Port} counter accept\n");
        }

        sb.Append("  }\n");
        sb.Append("}\n");
        return sb.ToString();
    }

    /// <summary>
    /// Renders the match expression for a slot, or explains why the kernel cannot express it.
    /// </summary>
    private static bool TryRenderSlotMatch(RuleSlot slot, out string match, out string reason)
    {
        match = string.Empty;
        reason = string.Empty;

        var destination = slot.Rule.Destination;
        if (destination.Hosts.Count > 0)
        {
            // Host names are not visible at the packet layer. Matching them needs the
            // forwarder to sniff SNI/Host and decide per flow, which is not implemented.
            // Installing the rule without the constraint would capture traffic the user
            // never asked for, so it is left out and reported instead.
            reason = "host-name destinations are not supported in the kernel classifier yet";
            return false;
        }

        var parts = new List<string>(6);

        // Transport first: 'th dport' below requires a known transport header.
        parts.Add(destination.Protocol switch
        {
            TransportFilter.Tcp => "meta l4proto tcp",
            TransportFilter.Udp => "meta l4proto udp",
            _ => "meta l4proto { tcp, udp }",
        });

        if (destination.Networks.Count > 0)
        {
            var v4 = destination.Networks.Where(n => n.BaseAddress.AddressFamily == AddressFamily.InterNetwork).ToList();
            var v6 = destination.Networks.Where(n => n.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6).ToList();
            if (v4.Count > 0 && v6.Count > 0)
            {
                reason = "a single rule cannot mix IPv4 and IPv6 destinations";
                return false;
            }

            var family = v6.Count > 0 ? "ip6" : "ip";
            var set = string.Join(", ", destination.Networks.Select(n =>
                n.PrefixLength == (n.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)
                    ? n.BaseAddress.ToString()
                    : $"{n.BaseAddress}/{n.PrefixLength}"));
            parts.Add($"{family} daddr {{ {set} }}");
        }

        if (destination.Ports.Count > 0)
        {
            var set = string.Join(", ", destination.Ports.Select(p => p.ToString()));
            parts.Add($"th dport {{ {set} }}");
        }

        if (slot.UsesCgroup)
        {
            parts.Add($"socket cgroupv2 level {CgroupManager.Level} \"{CgroupManager.RelativePathFor(slot.Name)}\"");
        }
        else if (destination.IsUnconstrained)
        {
            // Any process, any destination, would capture the entire machine including
            // the daemon's control traffic. Refuse rather than let a mis-click do that.
            reason = "a rule with no process and no destination constraint would capture all traffic";
            return false;
        }

        match = string.Join(' ', parts);
        return true;
    }

    public async Task<CommandResult> ApplyAsync(string ruleset, CancellationToken cancellationToken = default)
    {
        var result = await _commands.RunAsync("nft", ["-f", "-"], ruleset, cancellationToken)
            .ConfigureAwait(false);
        if (result.Succeeded)
        {
            _log("nftables ruleset installed");
        }

        return result;
    }

    /// <summary>Validates without installing. Used at startup to fail fast on syntax or kernel support.</summary>
    public Task<CommandResult> CheckAsync(string ruleset, CancellationToken cancellationToken = default) =>
        _commands.RunAsync("nft", ["--check", "-f", "-"], ruleset, cancellationToken);

    public async Task RemoveAsync(CancellationToken cancellationToken = default)
    {
        var result = await _commands.RunAsync("nft", ["delete", "table", "inet", TableName],
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (result.Succeeded)
        {
            _log("nftables ruleset removed");
        }
    }
}
