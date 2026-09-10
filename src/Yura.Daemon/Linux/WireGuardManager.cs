using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Daemon.Forwarding;

namespace Yura.Daemon.Linux;

/// <summary>
/// One WireGuard exit as the daemon has installed it: an interface, a mark and a table.
/// </summary>
/// <remarks>
/// Everything a dialler needs to originate a flow inside the tunnel is here and nothing
/// secret is: the keys went to the kernel through <c>wg setconf</c> and were forgotten.
/// </remarks>
public sealed record WireGuardTunnel
{
    public required Guid ProxyId { get; init; }

    public required string Name { get; init; }

    public required int Index { get; init; }

    /// <summary>The peer as configured, for display.</summary>
    public required string Endpoint { get; init; }

    /// <summary>Identifies the exact configuration, so an unchanged exit is not torn down and re-handshaken.</summary>
    public required string Fingerprint { get; init; }

    public IPAddress? Ipv4 { get; init; }

    public IPAddress? Ipv6 { get; init; }

    public IReadOnlyList<IPAddress> Dns { get; init; } = [];

    public string Interface => WireGuardManager.InterfaceName(Index);

    /// <summary>SO_MARK for sockets that must leave through this tunnel.</summary>
    public uint Mark => PolicyRouting.TunnelMarkBase + (uint)Index;

    public int Table => PolicyRouting.TunnelTableBase + Index;

    public int RulePriority => PolicyRouting.TunnelRulePriority + Index;

    /// <summary>The tunnel address to originate from for a destination of this family, if any.</summary>
    public IPAddress? SourceFor(AddressFamily family) =>
        family == AddressFamily.InterNetworkV6 ? Ipv6 : Ipv4;

    /// <summary>The tunnel's resolver of this family, if one is configured.</summary>
    public IPAddress? DnsFor(AddressFamily family) => Dns.FirstOrDefault(d => d.AddressFamily == family);
}

/// <summary>
/// Owns the kernel WireGuard interfaces that back WireGuard exits.
/// </summary>
/// <remarks>
/// Each exit is a real <c>wireguard</c> netdev configured through the <c>wg</c> tool, exactly
/// as <c>wg-quick</c> would do it, minus the part of <c>wg-quick</c> that hijacks the
/// machine's default route. Nothing is routed through the interface by default: the only
/// route pointing at it lives in a private table that is selected by a mark the daemon puts
/// on its own upstream sockets. A process the user selected is captured by TPROXY, the
/// daemon re-originates the flow from the tunnel address with that mark, and the kernel
/// encrypts it. Every other process on the machine is unaware the tunnel exists.
///
/// Keys reach the kernel over <c>wg setconf</c>'s standard input and are logged nowhere.
/// The daemon holds them only as long as it needs to hand them over; the interface keeps
/// its own copy, which is what <c>wg show</c> deliberately hides.
/// </remarks>
public sealed class WireGuardManager
{
    public const string InterfacePrefix = "yura-wg";

    /// <summary>Tunnels 0..63 are exits; the probe uses a fixed index above them.</summary>
    public const int MaxTunnels = 64;
    private const int ProbeIndex = 250;
    private const string ProbeName = "probe";

    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(6);
    private static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(3);

    /// <summary>A handshake this recent means the peer is alive even if no new one is triggered.</summary>
    private static readonly TimeSpan HandshakeFreshness = TimeSpan.FromSeconds(180);

    private readonly CommandRunner _commands;
    private readonly Action<string> _log;
    private readonly object _sync = new();
    private readonly Dictionary<Guid, WireGuardTunnel> _tunnels = [];
    private readonly Dictionary<Guid, (string Name, string Endpoint, string Failure)> _failures = [];
    private readonly SemaphoreSlim _probeGate = new(1, 1);

    public WireGuardManager(CommandRunner commands, Action<string> log)
    {
        _commands = commands;
        _log = log;
    }

    /// <summary>False until <see cref="CheckAsync"/> proved both the tool and the kernel side work.</summary>
    public bool IsAvailable { get; private set; }

    public string? UnavailableReason { get; private set; }

    public static string InterfaceName(int index) => $"{InterfacePrefix}{index}";

    public IReadOnlyDictionary<Guid, WireGuardTunnel> Tunnels
    {
        get
        {
            lock (_sync)
            {
                return new Dictionary<Guid, WireGuardTunnel>(_tunnels);
            }
        }
    }

    /// <summary>Why each exit that could not be brought up is down, by proxy id.</summary>
    public IReadOnlyDictionary<Guid, string> Failures
    {
        get
        {
            lock (_sync)
            {
                return _failures.ToDictionary(kv => kv.Key, kv => kv.Value.Failure);
            }
        }
    }

    // -- environment -------------------------------------------------------------

    /// <summary>Establishes whether WireGuard exits can work here at all, once, at startup.</summary>
    public async Task<IReadOnlyList<CheckDto>> CheckAsync(CancellationToken ct = default)
    {
        var checks = new List<CheckDto>(2);

        var tool = await _commands.RunAsync("wg", ["--version"], cancellationToken: ct).ConfigureAwait(false);
        checks.Add(new CheckDto
        {
            Name = "wg tool available (wireguard-tools)",
            Passed = tool.Succeeded,
            Detail = tool.Succeeded ? tool.StandardOutput.Trim() : "install wireguard-tools to use WireGuard exits",
        });

        // Adding an interface is the only test that proves the kernel side; it also autoloads
        // the module on kernels that build it as one.
        var probeName = InterfaceName(ProbeIndex);
        await _commands.RunAsync("ip", ["link", "del", probeName], cancellationToken: ct, quiet: true).ConfigureAwait(false);
        var kernel = await _commands.RunAsync("ip", ["link", "add", probeName, "type", "wireguard"], cancellationToken: ct)
            .ConfigureAwait(false);
        if (kernel.Succeeded)
        {
            await _commands.RunAsync("ip", ["link", "del", probeName], cancellationToken: ct).ConfigureAwait(false);
        }

        checks.Add(new CheckDto
        {
            Name = "Kernel supports WireGuard interfaces",
            Passed = kernel.Succeeded,
            Detail = kernel.Succeeded ? null : kernel.FailureText,
        });

        IsAvailable = tool.Succeeded && kernel.Succeeded;
        UnavailableReason = IsAvailable ? null
            : !tool.Succeeded ? "The wg tool is not installed (package wireguard-tools)."
            : $"The kernel cannot create WireGuard interfaces: {kernel.FailureText}";
        return checks;
    }

    /// <summary>Removes interfaces, rules and tables a previous daemon may have left behind.</summary>
    public async Task CleanupLeftoversAsync(CancellationToken ct = default)
    {
        var links = await _commands.RunAsync("ip", ["-o", "link", "show", "type", "wireguard"], cancellationToken: ct)
            .ConfigureAwait(false);
        foreach (var line in links.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            // "12: yura-wg0: <POINTOPOINT,...>"
            var parts = line.Split(':', 3, StringSplitOptions.TrimEntries);
            if (parts.Length >= 2 && parts[1].StartsWith(InterfacePrefix, StringComparison.Ordinal))
            {
                _log($"wireguard: removing leftover interface {parts[1]}");
                await _commands.RunAsync("ip", ["link", "del", parts[1]], cancellationToken: ct).ConfigureAwait(false);
            }
        }

        foreach (var family in new[] { "-4", "-6" })
        {
            var rules = await _commands.RunAsync("ip", [family, "rule", "show"], cancellationToken: ct).ConfigureAwait(false);
            foreach (var line in rules.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon <= 0 || !int.TryParse(line[..colon].Trim(), out var priority))
                {
                    continue;
                }

                if (priority >= PolicyRouting.TunnelRulePriority && priority <= PolicyRouting.TunnelRulePriority + 255 &&
                    line.Contains("lookup", StringComparison.Ordinal))
                {
                    await _commands.RunAsync("ip", [family, "rule", "del", "priority", priority.ToString(CultureInfo.InvariantCulture)],
                        cancellationToken: ct, quiet: true).ConfigureAwait(false);
                    await _commands.RunAsync("ip", [family, "route", "flush", "table",
                            (PolicyRouting.TunnelTableBase + priority - PolicyRouting.TunnelRulePriority).ToString(CultureInfo.InvariantCulture)],
                        cancellationToken: ct, quiet: true).ConfigureAwait(false);
                }
            }
        }
    }

    // -- reconciliation ----------------------------------------------------------

    /// <summary>
    /// Makes the set of interfaces match the WireGuard endpoints in the list, touching only
    /// the ones that changed. Returns one warning per exit that could not be brought up.
    /// </summary>
    public async Task<IReadOnlyList<string>> ReconcileAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> endpoints, CancellationToken ct = default)
    {
        var warnings = new List<string>();
        var desired = endpoints.Where(e => e.Endpoint.Protocol == ProxyProtocol.WireGuard).ToList();
        var desiredIds = desired.Select(e => e.Endpoint.Id).ToHashSet();

        List<WireGuardTunnel> stale;
        lock (_sync)
        {
            stale = _tunnels.Values
                .Where(t => !desiredIds.Contains(t.ProxyId) ||
                            desired.First(d => d.Endpoint.Id == t.ProxyId) is var d && Fingerprint(d.Endpoint, d.Secrets) != t.Fingerprint)
                .ToList();
            _failures.Clear();
        }

        foreach (var tunnel in stale)
        {
            await TearDownAsync(tunnel, ct).ConfigureAwait(false);
            lock (_sync)
            {
                _tunnels.Remove(tunnel.ProxyId);
            }
        }

        foreach (var (endpoint, secrets) in desired)
        {
            lock (_sync)
            {
                if (_tunnels.ContainsKey(endpoint.Id))
                {
                    continue;
                }
            }

            string? failure;
            if (!IsAvailable)
            {
                failure = UnavailableReason ?? "WireGuard is not available on this machine.";
            }
            else if (Validate(endpoint, secrets) is { } invalid)
            {
                failure = invalid;
            }
            else
            {
                var index = AllocateIndex();
                if (index is null)
                {
                    failure = $"More than {MaxTunnels} WireGuard exits are configured; this one was not started.";
                }
                else
                {
                    var (tunnel, error) = await BringUpAsync(endpoint, secrets, index.Value, ct).ConfigureAwait(false);
                    if (tunnel is not null)
                    {
                        lock (_sync)
                        {
                            _tunnels[endpoint.Id] = tunnel;
                        }

                        _log($"wireguard: exit '{endpoint.Name}' is up on {tunnel.Interface} (mark 0x{tunnel.Mark:x}, table {tunnel.Table}, peer {endpoint.Authority})");
                        continue;
                    }

                    failure = error;
                }
            }

            lock (_sync)
            {
                _failures[endpoint.Id] = (endpoint.Name, endpoint.Authority, failure!);
            }

            _log($"wireguard: exit '{endpoint.Name}' could not be brought up: {failure}");
            warnings.Add($"WireGuard exit '{endpoint.Name}' is not up: {failure}");
        }

        return warnings;
    }

    private int? AllocateIndex()
    {
        lock (_sync)
        {
            var used = _tunnels.Values.Select(t => t.Index).ToHashSet();
            for (var i = 0; i < MaxTunnels; i++)
            {
                if (!used.Contains(i))
                {
                    return i;
                }
            }

            return null;
        }
    }

    /// <summary>Everything the kernel would refuse, said in words first.</summary>
    internal static string? Validate(ProxyEndpoint endpoint, ProxySecrets secrets)
    {
        if (endpoint.WireGuard is not { } wg)
        {
            return "The endpoint has no WireGuard settings.";
        }

        if (!WireGuardConfig.IsValidKey(secrets.Password))
        {
            return secrets.Password is null
                ? "No private key was provided. It lives in the desktop secret store; open the exit in the app and enter it again."
                : "The private key is not a valid WireGuard key (44 base64 characters).";
        }

        if (!WireGuardConfig.IsValidKey(wg.PeerPublicKey))
        {
            return "The peer's public key is not a valid WireGuard key.";
        }

        if (secrets.PresharedKey is { Length: > 0 } && !WireGuardConfig.IsValidKey(secrets.PresharedKey))
        {
            return "The preshared key is not a valid WireGuard key.";
        }

        if (wg.Addresses.Count == 0)
        {
            return "No tunnel address is configured (the Address line of the [Interface] section).";
        }

        foreach (var address in wg.Addresses)
        {
            if (!WireGuardConfig.TryParseAddress(address, out _, out _))
            {
                return $"'{address}' is not a valid tunnel address.";
            }
        }

        foreach (var dns in wg.DnsServers)
        {
            if (!IPAddress.TryParse(dns, out _))
            {
                return $"'{dns}' is not a valid DNS server address.";
            }
        }

        foreach (var allowed in wg.AllowedIps)
        {
            if (!WireGuardConfig.TryParseCidr(allowed, out _))
            {
                return $"'{allowed}' is not a valid AllowedIPs entry.";
            }
        }

        if (wg.Mtu is { } mtu && (mtu < 1280 || mtu > 65535))
        {
            return "The MTU must be between 1280 and 65535.";
        }

        if (string.IsNullOrWhiteSpace(endpoint.Host) || endpoint.Port == 0)
        {
            return "The peer endpoint (host and port) is required.";
        }

        return null;
    }

    /// <summary>The text handed to <c>wg setconf</c>. Contains the keys; never log it.</summary>
    internal static string RenderConfig(ProxyEndpoint endpoint, ProxySecrets secrets)
    {
        var wg = endpoint.WireGuard ?? throw new InvalidOperationException("not a WireGuard endpoint");
        var sb = new StringBuilder();
        sb.Append("[Interface]\n");
        sb.Append("PrivateKey = ").Append(secrets.Password?.Trim()).Append('\n');
        // The outer packets carry the bypass mark so the classifier leaves them alone.
        sb.Append(CultureInfo.InvariantCulture, $"FwMark = 0x{PolicyRouting.BypassMark:x}\n");
        sb.Append("[Peer]\n");
        sb.Append("PublicKey = ").Append(wg.PeerPublicKey.Trim()).Append('\n');
        if (secrets.PresharedKey is { Length: > 0 } psk)
        {
            sb.Append("PresharedKey = ").Append(psk.Trim()).Append('\n');
        }

        var allowed = wg.AllowedIps.Count == 0 ? ["0.0.0.0/0", "::/0"] : wg.AllowedIps;
        sb.Append("AllowedIPs = ").Append(string.Join(", ", allowed)).Append('\n');
        sb.Append("Endpoint = ").Append(endpoint.Authority).Append('\n');
        if (wg.PersistentKeepalive > 0)
        {
            sb.Append(CultureInfo.InvariantCulture, $"PersistentKeepalive = {wg.PersistentKeepalive}\n");
        }

        return sb.ToString();
    }

    /// <summary>A digest of the whole configuration, keys included, that reveals none of it.</summary>
    internal static string Fingerprint(ProxyEndpoint endpoint, ProxySecrets secrets)
    {
        var wg = endpoint.WireGuard;
        var material = RenderConfig(endpoint, secrets) + "\n" +
                       string.Join(",", wg?.Addresses ?? []) + "\n" +
                       string.Join(",", wg?.DnsServers ?? []) + "\n" +
                       (wg?.Mtu?.ToString(CultureInfo.InvariantCulture) ?? "") + "\n" + endpoint.Name;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    /// <summary>Creates and configures one interface; on any failure nothing is left behind.</summary>
    private async Task<(WireGuardTunnel? Tunnel, string? Failure)> BringUpAsync(
        ProxyEndpoint endpoint, ProxySecrets secrets, int index, CancellationToken ct)
    {
        var (tunnel, failure) = await ConfigureAsync(endpoint, secrets, index, ct).ConfigureAwait(false);
        if (tunnel is null)
        {
            await TearDownAsync(index, ct).ConfigureAwait(false);
        }

        return (tunnel, failure);
    }

    private async Task<(WireGuardTunnel? Tunnel, string? Failure)> ConfigureAsync(
        ProxyEndpoint endpoint, ProxySecrets secrets, int index, CancellationToken ct)
    {
        var name = InterfaceName(index);
        var wg = endpoint.WireGuard!;

        // A stale interface with our name is ours to replace.
        await _commands.RunAsync("ip", ["link", "del", name], cancellationToken: ct, quiet: true).ConfigureAwait(false);

        var add = await _commands.RunAsync("ip", ["link", "add", name, "type", "wireguard"], cancellationToken: ct)
            .ConfigureAwait(false);
        if (!add.Succeeded)
        {
            return (null, $"could not create the interface: {add.FailureText}");
        }

        try
        {
            var conf = await _commands.RunAsync("wg", ["setconf", name, "/dev/stdin"], RenderConfig(endpoint, secrets), ct,
                sensitiveInput: true).ConfigureAwait(false);
            if (!conf.Succeeded)
            {
                return (null, $"wg rejected the configuration: {conf.FailureText}");
            }

            if (wg.Mtu is { } mtu)
            {
                var setMtu = await _commands.RunAsync("ip", ["link", "set", name, "mtu", mtu.ToString(CultureInfo.InvariantCulture)],
                    cancellationToken: ct).ConfigureAwait(false);
                if (!setMtu.Succeeded)
                {
                    return (null, $"could not set the MTU: {setMtu.FailureText}");
                }
            }

            IPAddress? v4 = null, v6 = null;
            foreach (var text in wg.Addresses)
            {
                WireGuardConfig.TryParseAddress(text, out var address, out var prefix);
                var cidr = $"{address}/{prefix}";
                var addr = await _commands.RunAsync("ip", ["addr", "add", cidr, "dev", name], cancellationToken: ct)
                    .ConfigureAwait(false);
                if (!addr.Succeeded)
                {
                    return (null, $"could not assign {cidr}: {addr.FailureText}");
                }

                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    v4 ??= address;
                }
                else
                {
                    v6 ??= address;
                }
            }

            // Replies arrive on the tunnel from addresses the main table routes elsewhere, so
            // a strict reverse-path check on this interface would drop every one of them.
            WriteSysctl($"net.ipv4.conf.{name}.rp_filter", "0");

            var up = await _commands.RunAsync("ip", ["link", "set", name, "up"], cancellationToken: ct).ConfigureAwait(false);
            if (!up.Succeeded)
            {
                return (null, $"could not bring the interface up: {up.FailureText}");
            }

            var table = (PolicyRouting.TunnelTableBase + index).ToString(CultureInfo.InvariantCulture);
            var priority = (PolicyRouting.TunnelRulePriority + index).ToString(CultureInfo.InvariantCulture);
            var mark = $"0x{PolicyRouting.TunnelMarkBase + (uint)index:x}";
            foreach (var (family, present) in new[] { ("-4", v4 is not null), ("-6", v6 is not null) })
            {
                if (!present)
                {
                    continue;
                }

                var route = await _commands.RunAsync("ip", [family, "route", "replace", "default", "dev", name, "table", table],
                    cancellationToken: ct).ConfigureAwait(false);
                if (!route.Succeeded)
                {
                    return (null, $"could not add the tunnel route: {route.FailureText}");
                }

                await _commands.RunAsync("ip", [family, "rule", "del", "priority", priority], cancellationToken: ct, quiet: true).ConfigureAwait(false);
                var rule = await _commands.RunAsync("ip", [family, "rule", "add", "priority", priority, "fwmark", mark, "lookup", table],
                    cancellationToken: ct).ConfigureAwait(false);
                if (!rule.Succeeded)
                {
                    return (null, $"could not add the policy rule: {rule.FailureText}");
                }
            }

            var tunnel = new WireGuardTunnel
            {
                ProxyId = endpoint.Id,
                Name = endpoint.Name,
                Index = index,
                Endpoint = endpoint.Authority,
                Fingerprint = Fingerprint(endpoint, secrets),
                Ipv4 = v4,
                Ipv6 = v6,
                Dns = wg.DnsServers.Select(IPAddress.Parse).ToArray(),
            };
            return (tunnel, null);
        }
        catch (Exception e) when (e is IOException or InvalidOperationException)
        {
            return (null, e.Message);
        }
    }

    private async Task TearDownAsync(WireGuardTunnel tunnel, CancellationToken ct)
    {
        await TearDownAsync(tunnel.Index, ct, tunnel.Ipv4 is not null, tunnel.Ipv6 is not null).ConfigureAwait(false);
        _log($"wireguard: exit '{tunnel.Name}' removed from {tunnel.Interface}");
    }

    /// <summary>Removes whatever a bring-up may have left; families the tunnel never had are skipped so the log stays quiet.</summary>
    private async Task TearDownAsync(int index, CancellationToken ct, bool v4 = true, bool v6 = true)
    {
        var name = InterfaceName(index);
        var table = (PolicyRouting.TunnelTableBase + index).ToString(CultureInfo.InvariantCulture);
        var priority = (PolicyRouting.TunnelRulePriority + index).ToString(CultureInfo.InvariantCulture);
        foreach (var (family, present) in new[] { ("-4", v4), ("-6", v6) })
        {
            if (!present)
            {
                continue;
            }

            // Each may legitimately not exist.
            await _commands.RunAsync("ip", [family, "rule", "del", "priority", priority], cancellationToken: ct, quiet: true).ConfigureAwait(false);
            await _commands.RunAsync("ip", [family, "route", "flush", "table", table], cancellationToken: ct, quiet: true).ConfigureAwait(false);
        }

        await _commands.RunAsync("ip", ["link", "del", name], cancellationToken: ct, quiet: true).ConfigureAwait(false);
    }

    public async Task RemoveAllAsync(CancellationToken ct = default)
    {
        List<WireGuardTunnel> all;
        lock (_sync)
        {
            all = _tunnels.Values.ToList();
            _tunnels.Clear();
            _failures.Clear();
        }

        foreach (var tunnel in all)
        {
            await TearDownAsync(tunnel, ct).ConfigureAwait(false);
        }
    }

    // -- status ------------------------------------------------------------------

    public async Task<IReadOnlyList<TunnelDto>> StatusAsync(CancellationToken ct = default)
    {
        List<WireGuardTunnel> tunnels;
        List<(Guid Id, string Name, string Endpoint, string Failure)> failures;
        lock (_sync)
        {
            tunnels = _tunnels.Values.OrderBy(t => t.Index).ToList();
            failures = _failures.Select(kv => (kv.Key, kv.Value.Name, kv.Value.Endpoint, kv.Value.Failure)).ToList();
        }

        var result = new List<TunnelDto>(tunnels.Count + failures.Count);
        foreach (var tunnel in tunnels)
        {
            var (handshake, rx, tx, endpoint) = await ReadPeerStateAsync(tunnel.Interface, ct).ConfigureAwait(false);
            result.Add(new TunnelDto
            {
                ProxyId = tunnel.ProxyId,
                Name = tunnel.Name,
                Interface = tunnel.Interface,
                Up = true,
                LatestHandshakeUtc = handshake,
                RxBytes = rx,
                TxBytes = tx,
                Endpoint = endpoint ?? tunnel.Endpoint,
            });
        }

        foreach (var (id, name, endpoint, failure) in failures)
        {
            result.Add(new TunnelDto { ProxyId = id, Name = name, Up = false, Failure = failure, Endpoint = endpoint });
        }

        return result;
    }

    /// <summary>
    /// What <c>wg show</c> says about the single peer.
    /// </summary>
    /// <remarks>
    /// Three field queries rather than one <c>wg show all dump</c>: the dump form prints the
    /// interface's <em>private key</em> in its first column, and this output is read by a
    /// method whose whole purpose is to report tunnel state without ever handling a key. Each
    /// query is a netlink round trip costing microseconds, so the saving would be nothing and
    /// the risk would be real.
    /// </remarks>
    private async Task<(DateTimeOffset? Handshake, long Rx, long Tx, string? Endpoint)> ReadPeerStateAsync(string name, CancellationToken ct)
    {
        var handshakes = await _commands.RunAsync("wg", ["show", name, "latest-handshakes"], cancellationToken: ct).ConfigureAwait(false);
        var transfer = await _commands.RunAsync("wg", ["show", name, "transfer"], cancellationToken: ct).ConfigureAwait(false);
        var endpoints = await _commands.RunAsync("wg", ["show", name, "endpoints"], cancellationToken: ct).ConfigureAwait(false);

        var epoch = ParseHandshakeEpoch(handshakes.StandardOutput);
        var (rx, tx) = ParseTransfer(transfer.StandardOutput);
        var endpoint = SecondField(endpoints.StandardOutput);
        return (epoch > 0 ? DateTimeOffset.FromUnixTimeSeconds(epoch) : null, rx, tx,
            endpoint is "(none)" or null ? null : endpoint);
    }

    /// <summary>"pubkey\tepoch" per peer; the first peer's epoch, 0 when there has been none.</summary>
    internal static long ParseHandshakeEpoch(string output)
    {
        var field = SecondField(output);
        return field is not null && long.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out var epoch) ? epoch : 0;
    }

    /// <summary>"pubkey\trx\ttx" per peer.</summary>
    internal static (long Rx, long Tx) ParseTransfer(string output)
    {
        var line = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        var fields = line?.Split('\t');
        if (fields is { Length: >= 3 } &&
            long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var rx) &&
            long.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var tx))
        {
            return (rx, tx);
        }

        return (0, 0);
    }

    private static string? SecondField(string output)
    {
        var line = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        var fields = line?.Split('\t');
        return fields is { Length: >= 2 } ? fields[1].Trim() : null;
    }

    // -- probe -------------------------------------------------------------------

    /// <summary>
    /// Tests an exit the way a flow would use it: bring the tunnel up, make the peer
    /// handshake, and if a resolver is configured, get an answer from it through the tunnel.
    /// </summary>
    /// <remarks>
    /// An exit that is already installed with the same configuration is probed in place, so
    /// testing a saved exit does not tear down the tunnel its flows are using. Anything else
    /// gets a temporary interface that is gone before this returns.
    /// </remarks>
    public async Task<ProbeResultDto> ProbeAsync(ProxyEndpoint endpoint, ProxySecrets secrets, CancellationToken ct = default)
    {
        if (!IsAvailable)
        {
            return new ProbeResultDto { Reachable = false, FailureReason = UnavailableReason ?? "WireGuard is not available on this machine." };
        }

        if (Validate(endpoint, secrets) is { } invalid)
        {
            return new ProbeResultDto { Reachable = false, FailureReason = invalid };
        }

        await _probeGate.WaitAsync(ct).ConfigureAwait(false);
        WireGuardTunnel? temporary = null;
        try
        {
            WireGuardTunnel? tunnel;
            var fingerprint = Fingerprint(endpoint, secrets);
            lock (_sync)
            {
                tunnel = _tunnels.GetValueOrDefault(endpoint.Id) is { } existing && existing.Fingerprint == fingerprint ? existing : null;
            }

            if (tunnel is null)
            {
                var (created, failure) = await BringUpAsync(endpoint with { Name = ProbeName }, secrets, ProbeIndex, ct).ConfigureAwait(false);
                if (created is null)
                {
                    await TearDownAsync(ProbeIndex, ct).ConfigureAwait(false);
                    return new ProbeResultDto { Reachable = false, FailureReason = $"The tunnel could not be set up: {failure}" };
                }

                temporary = tunnel = created;
            }

            return await MeasureAsync(tunnel, endpoint, ct).ConfigureAwait(false);
        }
        finally
        {
            if (temporary is not null)
            {
                await TearDownAsync(temporary.Index, ct).ConfigureAwait(false);
            }

            _probeGate.Release();
        }
    }

    private async Task<ProbeResultDto> MeasureAsync(WireGuardTunnel tunnel, ProxyEndpoint endpoint, CancellationToken ct)
    {
        var source = tunnel.Ipv4 ?? tunnel.Ipv6;
        if (source is null)
        {
            return new ProbeResultDto { Reachable = false, FailureReason = "The tunnel has no address to originate from." };
        }

        // Any packet towards the peer triggers a handshake. A DNS query is the most useful one
        // to send, because if a resolver is configured its answer proves the far side works.
        var resolver = tunnel.DnsFor(source.AddressFamily);
        var target = resolver is not null
            ? new IPEndPoint(resolver, 53)
            : new IPEndPoint(source.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Parse("1.1.1.1") : IPAddress.Parse("2606:4700:4700::1111"), 53);

        var (handshakeBefore, _, _, _) = await ReadPeerStateAsync(tunnel.Interface, ct).ConfigureAwait(false);
        var startedAt = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        using var socket = new Socket(source.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.SetMark(tunnel.Mark);
        socket.Bind(new IPEndPoint(source, 0));
        var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var query = DnsMessage.BuildQuery(id, "example.com");

        double? handshakeMs = null;
        double? dnsMs = null;
        string? dnsFailure = null;
        var answer = new byte[512];

        try
        {
            await socket.SendToAsync(query, target, ct).ConfigureAwait(false);

            using var overall = CancellationTokenSource.CreateLinkedTokenSource(ct);
            overall.CancelAfter(HandshakeTimeout + DnsTimeout);
            var any = new IPEndPoint(source.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            var receive = socket.ReceiveFromAsync(answer, any, overall.Token).AsTask();

            while (stopwatch.Elapsed < HandshakeTimeout + DnsTimeout)
            {
                if (receive.IsCompletedSuccessfully)
                {
                    var received = receive.Result.ReceivedBytes;
                    if (received >= 12 && answer[0] == (byte)(id >> 8) && answer[1] == (byte)id)
                    {
                        dnsMs ??= stopwatch.Elapsed.TotalMilliseconds;
                        handshakeMs ??= dnsMs;
                        break;
                    }

                    receive = socket.ReceiveFromAsync(answer, any, overall.Token).AsTask();
                }
                else if (receive.IsFaulted || receive.IsCanceled)
                {
                    break;
                }

                if (handshakeMs is null)
                {
                    var (latest, _, _, _) = await ReadPeerStateAsync(tunnel.Interface, ct).ConfigureAwait(false);
                    if (latest is { } stamp && (stamp >= startedAt.AddSeconds(-1) ||
                                                (handshakeBefore is not null && DateTimeOffset.UtcNow - stamp < HandshakeFreshness)))
                    {
                        handshakeMs = stopwatch.Elapsed.TotalMilliseconds;
                        if (resolver is null)
                        {
                            break; // Nothing more to wait for.
                        }
                    }
                    else if (stopwatch.Elapsed >= HandshakeTimeout)
                    {
                        break;
                    }
                }
                else if (stopwatch.Elapsed.TotalMilliseconds - handshakeMs.Value >= DnsTimeout.TotalMilliseconds)
                {
                    dnsFailure = $"the resolver at {target} did not answer within {DnsTimeout.TotalSeconds:0} s";
                    break;
                }

                await Task.Delay(150, ct).ConfigureAwait(false);
            }

            overall.Cancel();
            // The pending receive is cancelled with the socket a moment later; observing it
            // here keeps a long-lived daemon free of unobserved task exceptions.
            _ = receive.ContinueWith(static t => _ = t.Exception, TaskScheduler.Default);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return new ProbeResultDto
            {
                Reachable = false,
                FailureReason = "The tunnel could not send through the interface.",
                Diagnostics = e.Message,
            };
        }

        var (afterHandshake, rx, tx, currentEndpoint) = await ReadPeerStateAsync(tunnel.Interface, ct).ConfigureAwait(false);
        var facts = $"interface {tunnel.Interface}, peer {currentEndpoint ?? endpoint.Authority}, " +
                    $"latest handshake {(afterHandshake is { } h ? h.ToString("u", CultureInfo.InvariantCulture) : "never")}, " +
                    $"transfer rx {rx} B tx {tx} B";

        if (handshakeMs is null)
        {
            return new ProbeResultDto
            {
                Reachable = false,
                FailureReason = $"The peer at {endpoint.Authority} did not complete a handshake within {HandshakeTimeout.TotalSeconds:0} s. " +
                                "Check both keys and the endpoint, and that UDP to it is not blocked.",
                Diagnostics = facts,
            };
        }

        var detail = new StringBuilder();
        detail.Append(CultureInfo.InvariantCulture, $"Handshake completed in {handshakeMs.Value:0} ms. ");
        if (resolver is null)
        {
            detail.Append("No resolver is configured for this exit, so name lookups from its processes are sent through the tunnel to whatever resolver the application asked for. ");
        }
        else if (dnsMs is { } ms)
        {
            detail.Append(CultureInfo.InvariantCulture, $"The resolver at {resolver} answered through the tunnel in {ms:0} ms. ");
        }
        else
        {
            detail.Append(CultureInfo.InvariantCulture, $"The handshake completed but {dnsFailure}; flows may still work, name lookups may not. ");
        }

        detail.Append("A WireGuard tunnel carries IP, so UDP passes by construction. ").Append(facts);
        return new ProbeResultDto
        {
            Reachable = true,
            HandshakeMilliseconds = handshakeMs,
            Udp = CapabilityState.Supported,
            Diagnostics = detail.ToString(),
        };
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
