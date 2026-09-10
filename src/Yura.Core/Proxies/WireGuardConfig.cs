using System.Net;
using System.Net.Sockets;

namespace Yura.Core.Proxies;

/// <summary>What was read out of a wg-quick style configuration file.</summary>
/// <remarks>
/// Every member is optional because the file is the user's, not ours: an importer that
/// rejected a file for a missing MTU would be worse than one that fills in what it can and
/// lets the form say what is still needed.
/// </remarks>
public sealed record WireGuardConfigImport
{
    public string? PrivateKey { get; init; }

    public string? PeerPublicKey { get; init; }

    public string? PresharedKey { get; init; }

    public string? EndpointHost { get; init; }

    public ushort? EndpointPort { get; init; }

    public IReadOnlyList<string> Addresses { get; init; } = [];

    public IReadOnlyList<string> DnsServers { get; init; } = [];

    public IReadOnlyList<string> AllowedIps { get; init; } = [];

    public int? Mtu { get; init; }

    public int? PersistentKeepalive { get; init; }

    /// <summary>Directives that were understood well enough to know they are being ignored.</summary>
    public IReadOnlyList<string> Ignored { get; init; } = [];

    /// <summary>True when the text contained at least one WireGuard section.</summary>
    public bool Recognised { get; init; }
}

/// <summary>
/// Reads and validates WireGuard configuration values.
/// </summary>
/// <remarks>
/// The format is the one <c>wg-quick</c> reads: INI-like sections <c>[Interface]</c> and
/// <c>[Peer]</c>, one <c>Key = Value</c> per line, <c>#</c> comments, and comma-separated
/// lists. Only the first peer is imported; an exit node has one.
/// </remarks>
public static class WireGuardConfig
{
    /// <summary>Base64 of exactly 32 bytes, which is what every WireGuard key is.</summary>
    public static bool IsValidKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        var buffer = new byte[48];
        return Convert.TryFromBase64String(key.Trim(), buffer, out var written) && written == 32;
    }

    /// <summary>An address with a prefix, or a bare address which gets a host prefix.</summary>
    public static bool TryParseCidr(string? text, out IPNetwork network)
    {
        network = default;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        if (IPNetwork.TryParse(text, out network))
        {
            return true;
        }

        if (IPAddress.TryParse(text, out var address))
        {
            network = new IPNetwork(address, address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }

        return false;
    }

    /// <summary>Tunnel addresses keep their host part; <c>10.0.0.2/24</c> is an address, not a network.</summary>
    public static bool TryParseAddress(string? text, out IPAddress address, out int prefixLength)
    {
        address = IPAddress.None;
        prefixLength = 0;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? text : text[..slash];
        if (!IPAddress.TryParse(addressText, out var parsed))
        {
            return false;
        }

        var max = parsed.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (slash < 0)
        {
            prefixLength = max;
        }
        else if (!int.TryParse(text[(slash + 1)..], out prefixLength) || prefixLength < 0 || prefixLength > max)
        {
            return false;
        }

        address = parsed;
        return true;
    }

    /// <summary><c>host:port</c> or <c>[v6]:port</c>, as WireGuard writes endpoints.</summary>
    public static bool TryParseEndpoint(string? text, out string host, out ushort port)
    {
        host = string.Empty;
        port = 0;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']', StringComparison.Ordinal);
            if (close < 0 || close + 1 >= text.Length || text[close + 1] != ':')
            {
                return false;
            }

            host = text[1..close];
            return IPAddress.TryParse(host, out _) && ushort.TryParse(text[(close + 2)..], out port) && port > 0;
        }

        var colon = text.LastIndexOf(':');
        if (colon <= 0 || colon == text.Length - 1)
        {
            return false;
        }

        host = text[..colon];
        if (host.Contains(':', StringComparison.Ordinal))
        {
            return false; // A bare IPv6 literal without brackets is ambiguous.
        }

        return ushort.TryParse(text[(colon + 1)..], out port) && port > 0 &&
               (IPAddress.TryParse(host, out _) || Uri.CheckHostName(host) != UriHostNameType.Unknown);
    }

    public static WireGuardConfigImport Parse(string text)
    {
        string? section = null;
        var seenPeer = false;
        string? privateKey = null, peerPublicKey = null, presharedKey = null, endpointHost = null;
        ushort? endpointPort = null;
        int? mtu = null, keepalive = null;
        var addresses = new List<string>();
        var dns = new List<string>();
        var allowed = new List<string>();
        var ignored = new List<string>();
        var recognised = false;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            var comment = line.IndexOf('#', StringComparison.Ordinal);
            if (comment >= 0)
            {
                line = line[..comment].Trim();
            }

            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                var name = line[1..^1].Trim();
                if (name.Equals("Interface", StringComparison.OrdinalIgnoreCase))
                {
                    section = "interface";
                    recognised = true;
                }
                else if (name.Equals("Peer", StringComparison.OrdinalIgnoreCase))
                {
                    recognised = true;
                    if (seenPeer)
                    {
                        ignored.Add("a second [Peer] section (an exit node has one peer)");
                        section = "skip";
                    }
                    else
                    {
                        seenPeer = true;
                        section = "peer";
                    }
                }
                else
                {
                    section = "skip";
                }

                continue;
            }

            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            var key = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            if (value.Length == 0)
            {
                continue;
            }

            switch (section)
            {
                case "interface":
                    switch (key.ToLowerInvariant())
                    {
                        case "privatekey":
                            privateKey = value;
                            break;
                        case "address":
                            addresses.AddRange(SplitList(value));
                            break;
                        case "dns":
                            // wg-quick allows search domains here; only addresses are useful to us.
                            dns.AddRange(SplitList(value).Where(v => IPAddress.TryParse(v, out _)));
                            break;
                        case "mtu":
                            mtu = int.TryParse(value, out var m) ? m : null;
                            break;
                        case "listenport" or "fwmark" or "table":
                            ignored.Add($"{key} (Yura chooses its own)");
                            break;
                        case "preup" or "postup" or "predown" or "postdown" or "saveconfig":
                            ignored.Add($"{key} (scripts are never run)");
                            break;
                    }

                    break;

                case "peer":
                    switch (key.ToLowerInvariant())
                    {
                        case "publickey":
                            peerPublicKey = value;
                            break;
                        case "presharedkey":
                            presharedKey = value;
                            break;
                        case "endpoint":
                            if (TryParseEndpoint(value, out var host, out var port))
                            {
                                endpointHost = host;
                                endpointPort = port;
                            }

                            break;
                        case "allowedips":
                            allowed.AddRange(SplitList(value));
                            break;
                        case "persistentkeepalive":
                            keepalive = int.TryParse(value, out var k) ? k : null;
                            break;
                    }

                    break;
            }
        }

        return new WireGuardConfigImport
        {
            PrivateKey = privateKey,
            PeerPublicKey = peerPublicKey,
            PresharedKey = presharedKey,
            EndpointHost = endpointHost,
            EndpointPort = endpointPort,
            Addresses = addresses,
            DnsServers = dns,
            AllowedIps = allowed,
            Mtu = mtu,
            PersistentKeepalive = keepalive,
            Ignored = ignored,
            Recognised = recognised,
        };
    }

    public static IReadOnlyList<string> SplitList(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
