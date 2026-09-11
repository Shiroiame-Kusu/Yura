using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Yura.Core.Agent;

/// <summary>
/// Everything needed to reach one agent, in the single string the agent prints when it is
/// installed.
/// </summary>
/// <remarks>
/// <para>
/// <c>yura://&lt;token&gt;@host:port?fp=&lt;key fingerprint&gt;&amp;name=&lt;label&gt;</c>
/// </para>
/// <para>
/// One string, because the alternative is four fields typed by hand into a form, and a
/// mistyped fingerprint fails in a way that looks like a network problem. The agent prints
/// it; the user pastes it. The token is a secret and goes to the secret store; the
/// fingerprint and the address are not secrets and go to the configuration file.
/// </para>
/// <para>
/// The fingerprint is a SHA-256 of the agent's public key in <c>SubjectPublicKeyInfo</c>
/// form — the same thing HPKP and SSH pin, and the same key across certificate renewals.
/// Pinning it means the agent needs no certificate authority and no domain name: a server
/// with an IP address and a keypair is a complete deployment.
/// </para>
/// </remarks>
public sealed record AgentConnection
{
    public const string Scheme = "yura://";

    public required string Host { get; init; }

    public required ushort Port { get; init; }

    /// <summary>The shared token, base64url. A secret: never written to the configuration file.</summary>
    public required string Token { get; init; }

    /// <summary>SHA-256 of the agent's SubjectPublicKeyInfo, base64url.</summary>
    public required string Fingerprint { get; init; }

    /// <summary>The agent's own label, used as the exit's name when the user does not pick one.</summary>
    public string? Name { get; init; }

    public string Authority => Host.Contains(':', StringComparison.Ordinal) ? $"[{Host}]:{Port}" : $"{Host}:{Port}";

    /// <summary>As SSH writes a host key, so it can be compared by eye against the agent's output.</summary>
    public string FingerprintDisplay => $"SHA256:{Fingerprint}";

    /// <summary>The string to paste into Yura. Contains the token, so it is a secret in itself.</summary>
    public string ToConnectString()
    {
        var text = $"{Scheme}{Token}@{Authority}?fp={Fingerprint}";
        return Name is { Length: > 0 } name ? $"{text}&name={Uri.EscapeDataString(name)}" : text;
    }

    /// <summary>The same string with the token removed, which is the only form fit for a log.</summary>
    public string Redacted => $"{Scheme}…@{Authority}?fp={Fingerprint}";

    public override string ToString() => Redacted;

    /// <summary>
    /// Parses a connect string, explaining exactly what is wrong when it will not parse.
    /// </summary>
    public static bool TryParse(
        string? text,
        [NotNullWhen(true)] out AgentConnection? connection,
        [NotNullWhen(false)] out string? problem)
    {
        connection = null;
        problem = null;
        text = text?.Trim();

        if (string.IsNullOrEmpty(text))
        {
            problem = "Paste the connect string the agent printed.";
            return false;
        }

        if (!text.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            problem = $"A connect string starts with {Scheme}";
            return false;
        }

        var body = text[Scheme.Length..];

        // Parameters are accepted after '?' or '#': the agent writes '?', and a string that
        // has been through a chat client or a terminal sometimes comes back with the other.
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var split = body.IndexOfAny(['?', '#']);
        if (split >= 0)
        {
            foreach (var pair in body[(split + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var equals = pair.IndexOf('=', StringComparison.Ordinal);
                if (equals > 0)
                {
                    parameters[pair[..equals]] = Uri.UnescapeDataString(pair[(equals + 1)..]);
                }
            }

            body = body[..split];
        }

        var at = body.LastIndexOf('@');
        if (at <= 0)
        {
            problem = "The connect string has no token. It should read yura://<token>@host:port?fp=…";
            return false;
        }

        var token = body[..at];
        if (!IsValidToken(token))
        {
            problem = "The token in the connect string is not a 32-byte value.";
            return false;
        }

        if (!TryParseAuthority(body[(at + 1)..], out var host, out var port))
        {
            problem = "The address in the connect string is not host:port.";
            return false;
        }

        if (!parameters.TryGetValue("fp", out var fingerprint) || fingerprint.Length == 0)
        {
            problem = "The connect string has no key fingerprint (fp=…), so the agent could not be identified.";
            return false;
        }

        // "SHA256:" is how it is displayed, so accept it back.
        if (fingerprint.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
        {
            fingerprint = fingerprint["SHA256:".Length..];
        }

        if (!IsValidFingerprint(fingerprint))
        {
            problem = "The key fingerprint in the connect string is not a SHA-256 value.";
            return false;
        }

        connection = new AgentConnection
        {
            Host = host,
            Port = port,
            Token = Normalise(token),
            Fingerprint = Normalise(fingerprint),
            Name = parameters.GetValueOrDefault("name"),
        };

        return true;
    }

    private static bool TryParseAuthority(string authority, out string host, out ushort port)
    {
        host = string.Empty;
        port = AgentProtocol.DefaultPort;

        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']', StringComparison.Ordinal);
            if (close < 0)
            {
                return false;
            }

            host = authority[1..close];
            var rest = authority[(close + 1)..];
            return host.Length > 0 && (rest.Length == 0 || (rest[0] == ':' && ushort.TryParse(rest[1..], out port)));
        }

        var colon = authority.LastIndexOf(':');
        if (colon < 0)
        {
            host = authority;
            return host.Length > 0;
        }

        host = authority[..colon];
        return host.Length > 0 && ushort.TryParse(authority[(colon + 1)..], out port) && port > 0;
    }

    /// <summary>True when this is a 32-byte value in base64 or base64url.</summary>
    public static bool IsValidToken(string? token) => TryDecode(token, AgentProtocol.TokenBytes, out _);

    /// <summary>True when this is a 32-byte SHA-256, in base64 or base64url.</summary>
    public static bool IsValidFingerprint(string? fingerprint) => TryDecode(fingerprint, SHA256.HashSizeInBytes, out _);

    public static bool TryDecodeToken(string? token, out byte[] value) =>
        TryDecode(token, AgentProtocol.TokenBytes, out value);

    public static bool TryDecodeFingerprint(string? fingerprint, out byte[] value) =>
        TryDecode(fingerprint, SHA256.HashSizeInBytes, out value);

    /// <summary>base64url without padding, which survives being pasted anywhere.</summary>
    public static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>The same bytes written the way this type writes them, whatever form they arrived in.</summary>
    private static string Normalise(string value) => TryDecode(value, 0, out var raw) ? Encode(raw) : value;

    private static bool TryDecode(string? text, int expectedLength, out byte[] value)
    {
        value = [];
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var padded = text.Trim().Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 1:
                return false; // Not a base64 length at all.
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
        }

        var buffer = new byte[padded.Length];
        if (!Convert.TryFromBase64String(padded, buffer, out var written) ||
            (expectedLength > 0 && written != expectedLength))
        {
            return false;
        }

        value = buffer[..written];
        return true;
    }
}
