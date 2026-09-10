namespace Yura.Core.Proxies;

/// <summary>Wire protocol spoken to a user-supplied proxy.</summary>
/// <remarks>
/// Yura does not embed or manage a routing engine. The user runs whatever client they
/// already trust (sing-box, mihomo, Xray, a corporate proxy, an SSH tunnel) and exposes it
/// locally; Yura classifies traffic per process and hands it to one of these endpoints.
/// </remarks>
public enum ProxyProtocol
{
    /// <summary>SOCKS5, optionally with username/password auth (RFC 1928/1929).</summary>
    Socks5,

    /// <summary>HTTP proxy using <c>CONNECT</c> for tunnelling.</summary>
    Http,

    /// <summary>HTTP proxy reached over TLS (<c>CONNECT</c> inside TLS).</summary>
    Https,
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

/// <summary>A proxy the user has added. Credentials are referenced, never stored inline.</summary>
public sealed record ProxyEndpoint
{
    public required Guid Id { get; init; }

    /// <summary>User-chosen display name. Unique within the configuration.</summary>
    public required string Name { get; init; }

    public required ProxyProtocol Protocol { get; init; }

    /// <summary>Host name or literal IP (v4 or v6) of the proxy listener.</summary>
    public required string Host { get; init; }

    public required ushort Port { get; init; }

    public string? Username { get; init; }

    /// <summary>
    /// Key into the OS secret store. The password itself is never written to the config
    /// file and never leaves the daemon's memory in cleartext.
    /// </summary>
    public string? PasswordRef { get; init; }

    /// <summary>
    /// For <see cref="ProxyProtocol.Https"/>: accept a certificate that does not validate.
    /// Off by default; an explicit, visible choice for self-signed corporate proxies.
    /// </summary>
    public bool AllowInvalidCertificate { get; init; }

    /// <summary>Last measured state. Null until a probe has been run.</summary>
    public ProxyProbeResult? LastProbe { get; init; }

    /// <summary>
    /// UDP support as currently known. HTTP proxies are structurally incapable of relaying
    /// UDP, which is the one case we may assert without probing.
    /// </summary>
    public CapabilityState UdpSupport =>
        Protocol is ProxyProtocol.Http or ProxyProtocol.Https
            ? CapabilityState.Unsupported
            : LastProbe?.Udp ?? CapabilityState.Unknown;

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
        _ => Protocol.ToString(),
    };

    public override string ToString() => $"{Name} ({Protocol.ToString().ToLowerInvariant()}://{Authority})";
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
/// </remarks>
public sealed record ProxyChain
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public required IReadOnlyList<Guid> Hops { get; init; }

    public CapabilityState SupportsUdp => Hops.Count > 1 ? CapabilityState.Unsupported : CapabilityState.Unknown;
}
