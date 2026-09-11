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
    /// <param name="options">Daemon-wide policy, currently what to do with DNS.</param>
    /// <param name="skipped">Receives one line per rule that could not be expressed in the kernel.</param>
    public static string Build(
        IReadOnlyList<RuleSlot> slots,
        IReadOnlyList<ProxyEndpoint> proxies,
        DaemonOptions? options = null,
        List<string>? skipped = null)
    {
        options ??= new DaemonOptions();
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
        sb.Append(CultureInfo.InvariantCulture, $"    meta mark 0x{PolicyRouting.BypassMark:x} return\n");
        sb.Append("    # The same for the daemon's sockets inside a WireGuard exit, which carry\n");
        sb.Append("    # the tunnel's mark instead.\n");
        sb.Append(CultureInfo.InvariantCulture,
            $"    meta mark & 0x{PolicyRouting.TunnelMarkMask:x} == 0x{PolicyRouting.TunnelMarkBase:x} return\n\n");

        sb.Append("    # Loopback is never proxied: it is not reachable from a proxy anyway, and\n");
        sb.Append("    # capturing it breaks local services that applications talk to.\n");
        sb.Append("    oifname \"lo\" return\n\n");

        if (proxies.Count > 0)
        {
            sb.Append("    # Traffic addressed to a configured proxy, or to a WireGuard peer, is the\n");
            sb.Append("    # proxy's, never a rule's.\n");
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
            if (!TryRenderBaseMatch(slot, out var baseMatch, out var reason))
            {
                skipped?.Add($"{slot.Rule.Name}: {reason}");
                sb.Append(CultureInfo.InvariantCulture, $"    # slot {slot.Name} ({slot.Rule.Name}) skipped: {reason}\n");
                continue;
            }

            sb.Append(CultureInfo.InvariantCulture, $"    # {slot.Name}: {slot.Rule.Name}\n");

            if (slot.Disposition == SlotDisposition.Capture && slot.Port == 0)
            {
                // No listener, so nothing to hand the traffic to. Marking it would send it
                // into a hole; leaving it alone keeps the application working.
                skipped?.Add($"{slot.Rule.Name}: no transparent listener is available");
                sb.Append(CultureInfo.InvariantCulture, $"    # slot {slot.Name} ({slot.Rule.Name}) skipped: no listener\n");
                continue;
            }

            if (slot.UsesCgroup)
            {
                if (slot.Groups.Count == 0)
                {
                    sb.Append("    # (no running process matches this rule yet)\n");
                    continue;
                }

                foreach (var group in slot.Groups)
                {
                    var match = $"{baseMatch} socket cgroupv2 level {CgroupManager.Level} \"{CgroupManager.RelativePathFor(group.Name)}\"";
                    AppendDisposition(sb, slot, match, options);
                }
            }
            else
            {
                AppendDisposition(sb, slot, baseMatch, options);
            }
        }

        sb.Append("  }\n\n");

        // ---- capture: hand each marked flow to its slot's listener.
        sb.Append("  chain capture {\n");
        sb.Append("    type filter hook prerouting priority mangle; policy accept;\n");
        foreach (var slot in slots.Where(s => s.Disposition == SlotDisposition.Capture && s.Port > 0))
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

    private static void AppendDisposition(StringBuilder sb, RuleSlot slot, string match, DaemonOptions options)
    {
        switch (slot.Disposition)
        {
            case SlotDisposition.Capture:
                if (options.DnsPolicy == DnsPolicy.Direct && slot.Rule.Action.RequiresProxy)
                {
                    // DNS bypass: name lookups leave directly instead of through the proxy.
                    // Emitted before the capture line so it wins for port 53 only.
                    sb.Append(CultureInfo.InvariantCulture, $"    {match} th dport 53 counter accept\n");
                }

                // IPv4 only, and explicitly so. The capture chain below can hand a marked
                // packet to a listener with 'tproxy ip', and the policy-routing rule that
                // loops it back is an IPv4 rule; neither has an IPv6 counterpart yet. Marking
                // an IPv6 packet anyway would change nothing about where it goes, so it would
                // leave on the ordinary route while Yura reported the rule as being in effect.
                // 'accept' ends evaluation so a broader rule further down cannot overwrite
                // the mark; the route hook still re-routes because the mark changed.
                // 'counter' on every slot rule is deliberate: per-rule packet counts are the
                // first thing to look at when a rule "does nothing", and they cost nothing.
                sb.Append(CultureInfo.InvariantCulture,
                    $"    meta nfproto ipv4 {match} meta mark set 0x{slot.Mark:x} counter accept\n");

                // And what cannot be captured is refused rather than let out unrouted: a
                // connection that quietly avoids the route is worse than one that fails, and
                // an application that meets a closed door on IPv6 tries IPv4 a moment later.
                sb.Append(CultureInfo.InvariantCulture,
                    $"    meta nfproto ipv6 {match} meta l4proto tcp counter reject with tcp reset\n");
                sb.Append(CultureInfo.InvariantCulture,
                    $"    meta nfproto ipv6 {match} counter reject\n");
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

    /// <summary>
    /// Renders the destination part of a slot's match, or explains why the kernel cannot
    /// express the rule at all. Host names are deliberately left out: they are matched by
    /// the listener, which is why any rule that names one is a Capture slot.
    /// </summary>
    private static bool TryRenderBaseMatch(RuleSlot slot, out string match, out string reason)
    {
        match = string.Empty;
        reason = string.Empty;

        var destination = slot.Rule.Destination;

        if (destination.Hosts.Count > 0 && !slot.UsesCgroup)
        {
            // Matching a name means capturing the flow to look at it. For a rule with no
            // process selector that would mean capturing the whole machine's traffic.
            reason = "host-name rules need a process selector; add one, or match on an address instead";
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

            if (v6.Count > 0 && slot.Disposition == SlotDisposition.Capture)
            {
                reason = "IPv6 destinations cannot be captured yet, so this rule could not route them";
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

        if (!slot.UsesCgroup && destination.IsUnconstrained)
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

    /// <summary>The installed table with live counters, for diagnostics.</summary>
    public async Task<string> DumpAsync(CancellationToken cancellationToken = default)
    {
        var result = await _commands.RunAsync("nft", ["list", "table", "inet", TableName],
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.Succeeded ? result.StandardOutput : $"(not installed: {result.FailureText})";
    }

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
