namespace Yura.Core.Proxies;

/// <summary>Wire protocol spoken to a user-supplied exit.</summary>
/// <remarks>
/// Yura does not embed or manage a routing engine. The user runs whatever client they
/// already trust (sing-box, mihomo, Xray, a corporate proxy, an SSH tunnel, a WireGuard
/// server) and Yura classifies traffic per process and hands it to one of these endpoints.
/// </remarks>
public enum ProxyProtocol
{
    /// <summary>SOCKS5, optionally with username/password auth (RFC 1928/1929).</summary>
    Socks5,

    /// <summary>HTTP proxy using <c>CONNECT</c> for tunnelling.</summary>
    Http,

    /// <summary>HTTP proxy reached over TLS (<c>CONNECT</c> inside TLS).</summary>
    Https,

    /// <summary>
    /// A WireGuard peer used as an exit node. The daemon terminates the tunnel in the kernel
    /// and re-originates each selected flow from the tunnel's address, so the rest of the
    /// machine never sees the tunnel and nothing else is routed through it.
    /// </summary>
    WireGuard,
}

/// <summary>
/// Whether a capability has been measured. Distinguishing "we have not checked" from
/// "checked and unsupported" is a hard requirement: the UI shows "Not measured" for
/// <see cref="Unknown"/> and never substitutes a guess.
/// </summary>
public enum CapabilityState
{
    Unknown,
    Supported,
    Unsupported,
}

/// <summary>Result of the last reachability test run against an endpoint.</summary>
public sealed record ProxyProbeResult
{
    public required DateTimeOffset TimestampUtc { get; init; }

    /// <summary>True when the proxy completed a handshake and opened a test tunnel.</summary>
    public required bool Reachable { get; init; }

    /// <summary>Round-trip of the handshake, or null when the probe failed before timing.</summary>
    public TimeSpan? HandshakeLatency { get; init; }

    /// <summary>
    /// Whether UDP relaying actually worked, measured by a real UDP ASSOCIATE round trip.
    /// Never inferred from the protocol alone.
    /// </summary>
    public CapabilityState Udp { get; init; } = CapabilityState.Unknown;

    /// <summary>Operator-facing failure text, already suitable for display.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Raw diagnostic detail for the expandable "technical details" section.</summary>
    public string? Diagnostics { get; init; }
}

/// <summary>
/// The non-secret half of a WireGuard peer configuration.
/// </summary>
/// <remarks>
/// The private key and the optional preshared key are secrets and are kept in the desktop
/// secret store, referenced from the endpoint the same way a proxy password is. Everything
/// here is safe to write to the configuration file. The peer's endpoint host and port live
/// on the owning <see cref="ProxyEndpoint"/> so an endpoint's authority means the same thing
/// for every protocol.
/// </remarks>
public sealed record WireGuardSettings
{
    /// <summary>The peer's public key, base64.</summary>
    public required string PeerPublicKey { get; init; }

    /// <summary>Tunnel addresses in CIDR form, e.g. <c>10.0.0.2/32</c>. At least one is needed.</summary>
    public IReadOnlyList<string> Addresses { get; init; } = [];

    /// <summary>
    /// Resolvers reachable through the tunnel. When present, name lookups from processes on
    /// this exit are sent here rather than to the resolver the application asked for, which
    /// is usually unreachable from the far end.
    /// </summary>
    public IReadOnlyList<string> DnsServers { get; init; } = [];

    /// <summary>
    /// What the kernel will send through the tunnel. Yura decides which flows go in by
    /// process, so the default of everything is the right choice for an exit node.
    /// </summary>
    public IReadOnlyList<string> AllowedIps { get; init; } = ["0.0.0.0/0", "::/0"];

    /// <summary>Interface MTU; null keeps the WireGuard default of 1420.</summary>
    public int? Mtu { get; init; }

    /// <summary>Keepalive interval in seconds, 0 for none.</summary>
    public int PersistentKeepalive { get; init; }

    /// <summary>Key into the OS secret store for the preshared key, if one is used.</summary>
    public string? PresharedKeyRef { get; init; }
}

/// <summary>An exit the user has added. Credentials are referenced, never stored inline.</summary>
public sealed record ProxyEndpoint
{
    public required Guid Id { get; init; }

    /// <summary>User-chosen display name. Unique within the configuration.</summary>
    public required string Name { get; init; }

    public required ProxyProtocol Protocol { get; init; }

    /// <summary>
    /// Host name or literal IP (v4 or v6) of the proxy listener, or of the WireGuard peer.
    /// </summary>
    public required string Host { get; init; }

    public required ushort Port { get; init; }

    public string? Username { get; init; }

    /// <summary>
    /// Key into the OS secret store. For a proxy this is the password; for a WireGuard exit
    /// it is the private key. The secret itself is never written to the config file and
    /// never leaves the daemon's memory in cleartext.
    /// </summary>
    public string? PasswordRef { get; init; }

    /// <summary>
    /// For <see cref="ProxyProtocol.Https"/>: accept a certificate that does not validate.
    /// Off by default; an explicit, visible choice for self-signed corporate proxies.
    /// </summary>
    public bool AllowInvalidCertificate { get; init; }

    /// <summary>Present exactly when <see cref="Protocol"/> is <see cref="ProxyProtocol.WireGuard"/>.</summary>
    public WireGuardSettings? WireGuard { get; init; }

    /// <summary>Last measured state. Null until a probe has been run.</summary>
    public ProxyProbeResult? LastProbe { get; init; }

    public bool IsWireGuard => Protocol == ProxyProtocol.WireGuard;

    /// <summary>
    /// UDP support as currently known. HTTP proxies are structurally incapable of relaying
    /// UDP, and a WireGuard tunnel carries IP and so cannot tell one transport from another;
    /// those are the two cases we may assert without probing.
    /// </summary>
    public CapabilityState UdpSupport => Protocol switch
    {
        ProxyProtocol.Http or ProxyProtocol.Https => CapabilityState.Unsupported,
        ProxyProtocol.WireGuard => CapabilityState.Supported,
        _ => LastProbe?.Udp ?? CapabilityState.Unknown,
    };

    public string Authority => Host.Contains(':', StringComparison.Ordinal)
        ? $"[{Host}]:{Port}"          // IPv6 literal
        : $"{Host}:{Port}";

    /// <summary>
    /// Protocol name as it is normally written. The enum member names would render as
    /// "Socks5" and "Http", which look like typos to anyone who works with these protocols.
    /// </summary>
    public string ProtocolDisplay => Protocol switch
    {
        ProxyProtocol.Socks5 => "SOCKS5",
        ProxyProtocol.Http => "HTTP",
        ProxyProtocol.Https => "HTTPS",
        ProxyProtocol.WireGuard => "WireGuard",
        _ => Protocol.ToString(),
    };

    public override string ToString() => $"{Name} ({Protocol.ToString().ToLowerInvariant()}://{Authority})";
}

/// <summary>
/// The secrets that travel with an endpoint from the app to the daemon: never persisted by
/// either, never echoed back.
/// </summary>
/// <param name="Password">The proxy password, or the WireGuard private key.</param>
/// <param name="PresharedKey">The WireGuard preshared key, when one is used.</param>
public sealed record ProxySecrets(string? Password = null, string? PresharedKey = null)
{
    public static readonly ProxySecrets None = new();
}

/// <summary>
/// An ordered list of proxies traversed in sequence. Element 0 is dialled first.
/// </summary>
/// <remarks>
/// Chaining is TCP-only: relaying UDP through more than one hop needs every hop to support
/// UDP ASSOCIATE and to agree on the relay address, which cannot be verified end to end.
/// <see cref="SupportsUdp"/> therefore reports Unsupported for chains of length &gt; 1 rather
/// than letting a game silently lose its UDP traffic. A chain of one hop behaves exactly
/// like that endpoint.
///
/// A WireGuard exit can only ever be the first hop: the daemon reaches later hops through
/// the tunnel, but there is no way to carry a kernel tunnel inside a SOCKS connection.
/// </remarks>
public sealed record ProxyChain
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public required IReadOnlyList<Guid> Hops { get; init; }

    public CapabilityState SupportsUdp => Hops.Count > 1 ? CapabilityState.Unsupported : CapabilityState.Unknown;

    /// <summary>
    /// Why this chain cannot be dialled, or null when it can. Evaluated against the endpoints
    /// it names, so the app can refuse to build a chain the daemon would refuse to run.
    /// </summary>
    public static string? Validate(IReadOnlyList<ProxyEndpoint> hops)
    {
        if (hops.Count == 0)
        {
            return "A chain needs at least one hop.";
        }

        for (var i = 1; i < hops.Count; i++)
        {
            if (hops[i].Protocol == ProxyProtocol.WireGuard)
            {
                return $"'{hops[i].Name}' is a WireGuard exit and can only be the first hop of a chain.";
            }
        }

        return null;
    }
}
