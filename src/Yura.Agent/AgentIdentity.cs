using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Yura.Core.Agent;

namespace Yura.Agent;

/// <summary>
/// The agent's keypair and token: generated once, on first run, and never printed except on
/// request.
/// </summary>
/// <remarks>
/// <para>
/// Two secrets, with different jobs. The keypair identifies the agent — clients pin the
/// public key's SHA-256, so no certificate authority is involved and the same key works
/// whether the server is reached by name or by address. The token authorises clients: the
/// agent relays nothing for a connection that has not presented it.
/// </para>
/// <para>
/// Both live in the state directory with permissions that exclude everyone else, and neither
/// is ever passed on a command line, where the process table would publish it.
/// </para>
/// </remarks>
public sealed class AgentIdentity
{
    private const string CertificateFile = "agent.pfx";
    private const string TokenFile = "token";
    private const string NameFile = "name";

    private AgentIdentity(string directory, X509Certificate2 certificate, byte[] token, string name)
    {
        Directory = directory;
        Certificate = certificate;
        Token = token;
        Name = name;
        Fingerprint = FingerprintOf(certificate);
    }

    public string Directory { get; }

    public X509Certificate2 Certificate { get; }

    /// <summary>The shared token, raw. Compared in constant time, never logged.</summary>
    public byte[] Token { get; }

    /// <summary>SHA-256 of the certificate's SubjectPublicKeyInfo, base64url.</summary>
    public string Fingerprint { get; }

    public string Name { get; }

    /// <summary>The pin a client checks: the public key, not the certificate.</summary>
    /// <remarks>
    /// Pinning the key rather than the certificate means renewing the certificate — or issuing
    /// one with a hostname in it later — does not invalidate every client's configuration.
    /// </remarks>
    public static string FingerprintOf(X509Certificate2 certificate) =>
        AgentConnection.Encode(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));

    /// <summary>Loads the identity, creating one the first time.</summary>
    public static AgentIdentity LoadOrCreate(string directory, string? name = null)
    {
        System.IO.Directory.CreateDirectory(directory);
        try
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // A directory we cannot tighten is still usable; the files themselves are 0600.
        }

        var certificatePath = Path.Combine(directory, CertificateFile);
        var tokenPath = Path.Combine(directory, TokenFile);
        var namePath = Path.Combine(directory, NameFile);

        var certificate = File.Exists(certificatePath)
            ? X509CertificateLoader.LoadPkcs12FromFile(certificatePath, password: null,
                X509KeyStorageFlags.EphemeralKeySet)
            : Create(certificatePath);

        var token = File.Exists(tokenPath) && AgentConnection.TryDecodeToken(File.ReadAllText(tokenPath).Trim(), out var existing)
            ? existing
            : NewToken(tokenPath);

        var label = name
                    ?? (File.Exists(namePath) ? File.ReadAllText(namePath).Trim() : null)
                    ?? DefaultName();
        WriteFile(namePath, label + "\n", UnixFileMode.UserRead | UnixFileMode.UserWrite);

        return new AgentIdentity(directory, certificate, token, label);
    }

    /// <summary>Reads an existing identity, or null when the agent has never run here.</summary>
    public static AgentIdentity? Load(string directory)
    {
        var certificatePath = Path.Combine(directory, CertificateFile);
        var tokenPath = Path.Combine(directory, TokenFile);
        if (!File.Exists(certificatePath) || !File.Exists(tokenPath))
        {
            return null;
        }

        return LoadOrCreate(directory);
    }

    private static X509Certificate2 Create(string path)
    {
        // P-256: universally supported, small, and fast enough that a per-flow TLS handshake
        // costs the server nothing worth measuring.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=yura-agent", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // serverAuth

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
        WriteFile(path, certificate.Export(X509ContentType.Pkcs12),
            UnixFileMode.UserRead | UnixFileMode.UserWrite);

        return X509CertificateLoader.LoadPkcs12FromFile(path, password: null, X509KeyStorageFlags.EphemeralKeySet);
    }

    private static byte[] NewToken(string path)
    {
        var token = RandomNumberGenerator.GetBytes(AgentProtocol.TokenBytes);
        WriteFile(path, AgentConnection.Encode(token) + "\n", UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return token;
    }

    /// <summary>Replaces the token, which is how a leaked one is dealt with.</summary>
    public static byte[] RotateToken(string directory)
    {
        System.IO.Directory.CreateDirectory(directory);
        return NewToken(Path.Combine(directory, TokenFile));
    }

    private static void WriteFile(string path, string content, UnixFileMode mode) =>
        WriteFile(path, System.Text.Encoding.UTF8.GetBytes(content), mode);

    private static void WriteFile(string path, byte[] content, UnixFileMode mode)
    {
        // Created with the mode already set: a secret must never exist, even briefly, with
        // permissions that let anyone else read it.
        var temporary = path + ".new";
        using (var stream = new FileStream(temporary, new FileStreamOptions
               {
                   Mode = FileMode.Create,
                   Access = FileAccess.Write,
                   Share = FileShare.None,
                   UnixCreateMode = mode,
               }))
        {
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }

    private static string DefaultName()
    {
        try
        {
            var host = Dns.GetHostName();
            return host is { Length: > 0 } ? host : "yura-agent";
        }
        catch (Exception e) when (e is SocketException or InvalidOperationException)
        {
            return "yura-agent";
        }
    }

    /// <summary>The connect string for this agent at a given address.</summary>
    public AgentConnection ConnectionFor(string host, ushort port) => new()
    {
        Host = host,
        Port = port,
        Token = AgentConnection.Encode(Token),
        Fingerprint = Fingerprint,
        Name = Name,
    };

    /// <summary>
    /// The address a client would most likely use to reach this machine.
    /// </summary>
    /// <remarks>
    /// Read from the routing table by asking the kernel which source address it would use for
    /// an outbound connection, without sending anything. It is a guess about what the outside
    /// world sees — a server behind NAT has a different public address — so the caller says
    /// so rather than presenting it as fact.
    /// </remarks>
    public static (string Address, bool LooksPublic) LikelyAddress()
    {
        try
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53));
            if (probe.LocalEndPoint is IPEndPoint local)
            {
                var address = local.Address;
                var isPrivate = IPAddress.IsLoopback(address) || DestinationPolicy.IsPrivate(address);
                return (address.ToString(), !isPrivate);
            }
        }
        catch (SocketException)
        {
            // No route to anywhere: nothing to report.
        }

        return ("<server-address>", false);
    }
}
