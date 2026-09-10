namespace Yura.Daemon.Linux;

/// <summary>
/// The policy-routing glue that lets TPROXY see locally generated packets.
/// </summary>
/// <remarks>
/// Locally generated packets never pass the prerouting hook on their own. Marking one in a
/// <c>route</c>-type output chain forces a re-route; the rule installed here sends any
/// packet carrying a Yura mark to a table whose only entry is <c>local default dev lo</c>,
/// which loops it back into the receive path where TPROXY can claim it.
///
/// One rule covers every slot because all slots share the same table: the mark identifies
/// the slot for TPROXY, not for routing. <c>rp_filter</c> is relaxed on <c>lo</c> and
/// <c>all</c> for the same reason — a strict reverse-path check drops the looped-back
/// packet — and the previous values are restored on shutdown.
/// </remarks>
public sealed class PolicyRouting
{
    /// <summary>All slot marks live in 0x7100..0x71FF; this mask selects exactly that range.</summary>
    public const uint MarkBase = 0x7100;
    public const uint MarkMask = 0xFFFFFF00;

    /// <summary>
    /// Applied with SO_MARK to every socket the daemon opens towards a proxy. Outside the
    /// slot range, so the classifier never re-captures the daemon's own upstream traffic.
    /// </summary>
    public const uint BypassMark = 0x7200;

    /// <summary>
    /// Marks for the daemon's sockets inside a WireGuard exit: 0x7300 + tunnel index. Each
    /// selects that tunnel's routing table, whose only route is the tunnel interface, so a
    /// flow enters exactly the tunnel its rule named and nothing else on the machine does.
    /// </summary>
    public const uint TunnelMarkBase = 0x7300;
    public const uint TunnelMarkMask = 0xFFFFFF00;

    /// <summary>Routing table and rule priority for tunnel index n are both this plus n.</summary>
    public const int TunnelTableBase = 7300;
    public const int TunnelRulePriority = 7300;

    public const int RoutingTable = 711;
    public const int RulePriority = 7100;

    private readonly CommandRunner _commands;
    private readonly Action<string> _log;
    private string? _savedRpFilterAll;
    private string? _savedRpFilterLo;

    public PolicyRouting(CommandRunner commands, Action<string> log)
    {
        _commands = commands;
        _log = log;
    }

    public async Task<bool> InstallAsync(CancellationToken cancellationToken = default)
    {
        _savedRpFilterAll = ReadSysctl("net.ipv4.conf.all.rp_filter");
        _savedRpFilterLo = ReadSysctl("net.ipv4.conf.lo.rp_filter");
        WriteSysctl("net.ipv4.conf.all.rp_filter", "0");
        WriteSysctl("net.ipv4.conf.lo.rp_filter", "0");

        // Idempotent: a previous unclean shutdown may have left these behind.
        await RemoveAsync(cancellationToken).ConfigureAwait(false);

        var route = await _commands.RunAsync("ip",
            ["route", "add", "local", "default", "dev", "lo", "table", RoutingTable.ToString()],
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!route.Succeeded)
        {
            _log($"policy routing: could not add local route: {route.FailureText}");
            return false;
        }

        var rule = await _commands.RunAsync("ip",
            ["rule", "add", "priority", RulePriority.ToString(),
             "fwmark", $"0x{MarkBase:x}/0x{MarkMask:x}", "lookup", RoutingTable.ToString()],
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!rule.Succeeded)
        {
            _log($"policy routing: could not add fwmark rule: {rule.FailureText}");
            return false;
        }

        _log($"policy routing installed: fwmark 0x{MarkBase:x}/0x{MarkMask:x} -> table {RoutingTable}");
        return true;
    }

    public async Task RemoveAsync(CancellationToken cancellationToken = default)
    {
        // Both may legitimately not exist; failures here are not errors.
        await _commands.RunAsync("ip",
            ["rule", "del", "priority", RulePriority.ToString(),
             "fwmark", $"0x{MarkBase:x}/0x{MarkMask:x}", "lookup", RoutingTable.ToString()],
            cancellationToken: cancellationToken, quiet: true).ConfigureAwait(false);
        await _commands.RunAsync("ip",
            ["route", "flush", "table", RoutingTable.ToString()],
            cancellationToken: cancellationToken, quiet: true).ConfigureAwait(false);
    }

    public void RestoreSysctls()
    {
        if (_savedRpFilterAll is not null)
        {
            WriteSysctl("net.ipv4.conf.all.rp_filter", _savedRpFilterAll);
        }

        if (_savedRpFilterLo is not null)
        {
            WriteSysctl("net.ipv4.conf.lo.rp_filter", _savedRpFilterLo);
        }
    }

    private static string? ReadSysctl(string key)
    {
        try
        {
            return File.ReadAllText($"/proc/sys/{key.Replace('.', '/')}").Trim();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void WriteSysctl(string key, string value)
    {
        try
        {
            File.WriteAllText($"/proc/sys/{key.Replace('.', '/')}", value);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _log($"sysctl {key}={value} failed: {e.Message}");
        }
    }
}
