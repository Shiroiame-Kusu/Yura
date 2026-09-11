using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Yura.Core.Agent;
using Yura.Core.Proxies;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Forwarding;

/// <summary>Raised when a proxy refuses or garbles a handshake. The message is operator-facing.</summary>
public sealed class ProxyHandshakeException(string message) : Exception(message);

/// <summary>
/// One hop of a route: an endpoint plus the credential the app handed over, or the installed
/// tunnel when the endpoint is a WireGuard exit.
/// </summary>
public sealed record ProxyHop(ProxyEndpoint Endpoint, string? Password, WireGuardTunnel? Tunnel = null)
{
    public bool IsTunnel => Tunnel is not null;

    public bool IsAgent => Endpoint.Protocol == ProxyProtocol.YuraAgent;
}

/// <summary>How the end of the application's data can be signalled towards the destination.</summary>
public enum UpstreamHalfClose
{
    /// <summary>A plain socket: shut down the sending half.</summary>
    Socket,

    /// <summary>
    /// A TLS 1.3 connection to something that will pass the signal on — a Yura agent, which
    /// half-closes the destination when it sees <c>close_notify</c> and keeps answering.
    /// </summary>
    Tls,

    /// <summary>
    /// Nothing can be signalled. A proxy reached over TLS is the case: ending the TLS session
    /// would end the tunnel in both directions, so the far end is left to close on its own.
    /// </summary>
    None,
}

/// <summary>
/// The daemon's side of a relayed connection: the socket it dialled and the stream it
/// speaks over, which is the socket itself or a TLS layer above it.
/// </summary>
public sealed class UpstreamLeg : IAsyncDisposable
{
    public UpstreamLeg(Socket socket, Stream stream, UpstreamHalfClose halfClose)
    {
        Socket = socket;
        Stream = stream;
        HalfClose = halfClose;
    }

    public Socket Socket { get; }

    public Stream Stream { get; }

    public UpstreamHalfClose HalfClose { get; }

    /// <summary>
    /// Signals EOF towards the destination, by whichever means this leg has.
    /// </summary>
    /// <remarks>
    /// It matters for any protocol where one side says everything and then waits: without it
    /// the destination waits for more that will never come. Which means are available depends
    /// on what is between here and there, so the leg records that when it is built rather than
    /// guessing here.
    /// </remarks>
    public async ValueTask ShutdownSendAsync()
    {
        switch (HalfClose)
        {
            case UpstreamHalfClose.Socket:
                try
                {
                    Socket.Shutdown(SocketShutdown.Send);
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException)
                {
                }

                break;

            case UpstreamHalfClose.Tls when Stream is SslStream tls:
                try
                {
                    // close_notify only: the connection stays open for the other direction.
                    await tls.ShutdownAsync().ConfigureAwait(false);
                }
                catch (Exception e) when (e is IOException or ObjectDisposedException
                                             or InvalidOperationException or SocketException)
                {
                }

                break;
        }
    }

    public ValueTask DisposeAsync()
    {
        try
        {
            Stream.Dispose();
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
        }

        Socket.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Opens a TCP path to a destination: directly, through one proxy, or through a chain.
/// </summary>
/// <remarks>
/// A chain is dialled by connecting to the first hop and then asking each hop, in turn, to
/// CONNECT to the next one, so every hop only ever sees its neighbours. SOCKS5 (RFC 1928,
/// 1929) and HTTP CONNECT (RFC 7231 §4.3.6) both run over any byte stream, which is what
/// makes chaining and HTTPS proxies (CONNECT inside TLS) the same code path.
///
/// The final destination is always sent as a literal address: by the time a flow reaches
/// the daemon the application has already resolved it, and asking the proxy to resolve
/// again could send the flow somewhere different. Intermediate hops are sent by whatever
/// the user typed, since the previous hop is the one that has to reach them.
///
/// A WireGuard exit is a hop with no protocol to speak: the daemon simply originates the
/// connection from inside the tunnel, towards the next hop or the destination, and carries
/// on with whatever handshakes the remaining hops need. That is why an exit can only ever be
/// the first hop.
///
/// Every socket opened here carries the bypass mark, or a tunnel's mark, which is what stops
/// the classifier from capturing the daemon's own upstream traffic and feeding the forwarder
/// into itself.
/// </remarks>
public static class ProxyDialer
{
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    public static async Task<UpstreamLeg> OpenAsync(IReadOnlyList<ProxyHop> hops, IPEndPoint destination, CancellationToken ct)
    {
        if (hops.Count == 0)
        {
            return await OpenDirectAsync(destination, ct).ConfigureAwait(false);
        }

        Socket socket;
        var start = 0;
        if (hops[0].Tunnel is { } tunnel)
        {
            // The exit is entered by originating from inside it: towards the next hop when
            // there is one, otherwise straight at the destination.
            var next = hops.Count > 1
                ? new IPEndPoint(await ResolveAsync(hops[1].Endpoint.Host, ct).ConfigureAwait(false), hops[1].Endpoint.Port)
                : destination;
            socket = await ConnectViaTunnelAsync(tunnel, next, ct).ConfigureAwait(false);
            start = 1;
        }
        else
        {
            var first = hops[0].Endpoint;
            socket = await ConnectWithBypassAsync(first.Host, first.Port, ct).ConfigureAwait(false);
        }

        Stream stream = new NetworkStream(socket, ownsSocket: false);
        var halfClose = UpstreamHalfClose.Socket;

        try
        {
            for (var i = start; i < hops.Count; i++)
            {
                var hop = hops[i];
                if (hop.IsTunnel)
                {
                    throw new ProxyHandshakeException(
                        $"'{hop.Endpoint.Name}' is a WireGuard exit and can only be the first hop of a chain.");
                }

                switch (hop.Endpoint.Protocol)
                {
                    case ProxyProtocol.Https:
                        stream = await WrapTlsAsync(stream, hop.Endpoint, ct).ConfigureAwait(false);
                        halfClose = UpstreamHalfClose.None;
                        break;

                    case ProxyProtocol.YuraAgent:
                        // The agent authenticates over whatever stream reaches it, so an agent
                        // is a hop like any other rather than a special first one.
                        stream = await AgentHandshakeAsync(stream, hop, ct).ConfigureAwait(false);
                        halfClose = UpstreamHalfClose.Tls;
                        break;
                }

                var (targetHost, targetPort) = i + 1 < hops.Count
                    ? (hops[i + 1].Endpoint.Host, (int)hops[i + 1].Endpoint.Port)
                    : (destination.Address.ToString(), destination.Port);

                await TunnelAsync(stream, hop, targetHost, targetPort, ct).ConfigureAwait(false);
            }
        }
        catch
        {
            stream.Dispose();
            socket.Dispose();
            throw;
        }

        return new UpstreamLeg(socket, stream, halfClose);
    }

    /// <summary>The options for talking to one agent, from the endpoint and the token.</summary>
    /// <remarks>
    /// The token and the pinned key are the whole of an agent exit's security, so a missing one
    /// is refused here with something the user can act on rather than becoming a handshake
    /// failure further in.
    /// </remarks>
    public static AgentClientOptions AgentOptionsFor(ProxyHop hop, Action<Socket>? configureSocket = null)
    {
        if (hop.Endpoint.Agent is not { } settings || settings.Fingerprint.Length == 0)
        {
            throw new ProxyHandshakeException(
                $"Agent exit '{hop.Endpoint.Name}' has no key fingerprint. Add it again from the agent's connect string.");
        }

        if (hop.Password is not { Length: > 0 } token)
        {
            throw new ProxyHandshakeException(
                $"Agent exit '{hop.Endpoint.Name}' has no token. Add it again from the agent's connect string.");
        }

        return new AgentClientOptions
        {
            Host = hop.Endpoint.Host,
            Port = hop.Endpoint.Port,
            Token = token,
            Fingerprint = settings.Fingerprint,
            Label = $"yura-daemon/{typeof(ProxyDialer).Assembly.GetName().Version?.ToString(3) ?? "0"}",
            ConfigureSocket = configureSocket,
        };
    }

    private static async Task<Stream> AgentHandshakeAsync(Stream inner, ProxyHop hop, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(HandshakeTimeout);
        try
        {
            return await AgentClient.HandshakeAsync(
                inner, AgentOptionsFor(hop), AgentRole.Stream, timeout.Token).ConfigureAwait(false);
        }
        catch (AgentProtocolException e)
        {
            throw new ProxyHandshakeException($"Agent exit '{hop.Endpoint.Name}': {e.Message}");
        }
    }

    /// <summary>A plain connection to the destination, still bypass-marked so it is not re-captured.</summary>
    public static async Task<UpstreamLeg> OpenDirectAsync(IPEndPoint destination, CancellationToken ct)
    {
        var socket = new Socket(destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.SetMark(PolicyRouting.BypassMark);
        socket.NoDelay = true;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ConnectTimeout);
        try
        {
            await socket.ConnectAsync(destination, timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return new UpstreamLeg(socket, new NetworkStream(socket, ownsSocket: false), UpstreamHalfClose.Socket);
    }

    /// <summary>
    /// Connects from inside a WireGuard exit: the socket carries the tunnel's mark, which
    /// selects the tunnel's routing table, and is bound to the tunnel address so the far side
    /// sees a source it will accept.
    /// </summary>
    public static async Task<Socket> ConnectViaTunnelAsync(WireGuardTunnel tunnel, IPEndPoint target, CancellationToken ct)
    {
        var source = tunnel.SourceFor(target.AddressFamily)
                     ?? throw new ProxyHandshakeException(
                         $"WireGuard exit '{tunnel.Name}' has no {(target.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")} address, so it cannot reach {target}.");

        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.SetMark(tunnel.Mark);
        socket.NoDelay = true;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ConnectTimeout);
        try
        {
            socket.Bind(new IPEndPoint(source, 0));
            await socket.ConnectAsync(target, timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return socket;
    }

    /// <summary>Resolves and connects to a proxy host with the bypass mark set.</summary>
    public static async Task<Socket> ConnectWithBypassAsync(string host, int port, CancellationToken ct)
    {
        var address = await ResolveAsync(host, ct).ConfigureAwait(false);
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.SetMark(PolicyRouting.BypassMark);
        socket.NoDelay = true;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ConnectTimeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return socket;
    }

    public static async Task<IPAddress> ResolveAsync(string host, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var literal))
        {
            return literal;
        }

        var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        return addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
               ?? addresses.FirstOrDefault()
               ?? throw new SocketException((int)SocketError.HostNotFound);
    }

    private static async Task<Stream> WrapTlsAsync(Stream inner, ProxyEndpoint hop, CancellationToken ct)
    {
        var tls = new SslStream(inner, leaveInnerStreamOpen: false, (_, _, _, errors) =>
            errors == SslPolicyErrors.None || hop.AllowInvalidCertificate);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(HandshakeTimeout);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = hop.Host,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or System.Security.Authentication.AuthenticationException)
        {
            tls.Dispose();
            throw new ProxyHandshakeException(
                e is System.Security.Authentication.AuthenticationException
                    ? $"TLS to {hop.Authority} failed: {e.Message} Enable 'allow invalid certificate' only if you trust this proxy."
                    : $"TLS to {hop.Authority} was cut off: {e.Message}");
        }

        return tls;
    }

    /// <summary>Performs one hop's handshake on an already-connected stream.</summary>
    public static async Task TunnelAsync(Stream stream, ProxyHop hop, string targetHost, int targetPort, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(HandshakeTimeout);

        switch (hop.Endpoint.Protocol)
        {
            case ProxyProtocol.Socks5:
                await Socks5ConnectAsync(stream, hop.Endpoint.Username, hop.Password, targetHost, targetPort, timeout.Token)
                    .ConfigureAwait(false);
                break;
            case ProxyProtocol.Http:
            case ProxyProtocol.Https:
                await HttpConnectAsync(stream, hop.Endpoint.Username, hop.Password, targetHost, targetPort, timeout.Token)
                    .ConfigureAwait(false);
                break;
            case ProxyProtocol.YuraAgent:
                try
                {
                    await AgentClient.JoinAsync(stream, new AgentAddress(targetHost, (ushort)targetPort), timeout.Token)
                        .ConfigureAwait(false);
                }
                catch (AgentRefusedException e)
                {
                    throw new ProxyHandshakeException(e.Message);
                }
                catch (AgentProtocolException e)
                {
                    throw new ProxyHandshakeException($"Agent exit '{hop.Endpoint.Name}': {e.Message}");
                }

                break;
            default:
                throw new ProxyHandshakeException($"{hop.Endpoint.Protocol} is not a supported proxy protocol.");
        }
    }

    // -- SOCKS5 --------------------------------------------------------------

    /// <summary>Negotiates authentication with a SOCKS5 server. Shared by CONNECT, UDP ASSOCIATE and the probe.</summary>
    public static async Task Socks5GreetAsync(Stream stream, string? username, string? password, CancellationToken ct)
    {
        var wantsAuth = !string.IsNullOrEmpty(username);
        var greeting = wantsAuth ? new byte[] { 0x05, 0x02, 0x00, 0x02 } : new byte[] { 0x05, 0x01, 0x00 };
        await stream.WriteAsync(greeting, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        var choice = await ReadExactlyAsync(stream, 2, ct).ConfigureAwait(false);
        if (choice[0] != 0x05)
        {
            throw new ProxyHandshakeException("The proxy did not answer as SOCKS5. Check the protocol setting.");
        }

        switch (choice[1])
        {
            case 0x00:
                return;
            case 0x02 when wantsAuth:
                await Socks5AuthenticateAsync(stream, username!, password ?? string.Empty, ct).ConfigureAwait(false);
                return;
            case 0x02:
                throw new ProxyHandshakeException("The proxy requires a username and password.");
            case 0xFF:
                throw new ProxyHandshakeException(
                    wantsAuth ? "The proxy rejected the offered authentication methods."
                              : "The proxy requires authentication. Add a username and password.");
            default:
                throw new ProxyHandshakeException($"The proxy chose an unsupported authentication method ({choice[1]:#x}).");
        }
    }

    private static async Task Socks5ConnectAsync(
        Stream stream, string? username, string? password, string targetHost, int targetPort, CancellationToken ct)
    {
        await Socks5GreetAsync(stream, username, password, ct).ConfigureAwait(false);

        var request = BuildSocks5Request(0x01, targetHost, targetPort);
        await stream.WriteAsync(request, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        var header = await ReadExactlyAsync(stream, 4, ct).ConfigureAwait(false);
        if (header[1] != 0x00)
        {
            throw new ProxyHandshakeException(header[1] switch
            {
                0x02 => "The proxy's ruleset does not allow this connection.",
                0x03 => "The proxy reports the network is unreachable.",
                0x04 => "The proxy reports the destination host is unreachable.",
                0x05 => "The destination refused the connection (via the proxy).",
                0x06 => "The proxy reports the connection timed out.",
                0x07 => "The proxy does not support CONNECT.",
                0x08 => "The proxy does not support this address type.",
                _ => $"The proxy refused the connection (reply {header[1]:#x}).",
            });
        }

        await DrainSocks5AddressAsync(stream, header[3], ct).ConfigureAwait(false);
    }

    /// <summary>RSV/CMD/ATYP/ADDR/PORT for CONNECT (1) or UDP ASSOCIATE (3).</summary>
    public static byte[] BuildSocks5Request(byte command, string targetHost, int targetPort)
    {
        byte[] request;
        if (IPAddress.TryParse(targetHost, out var ip))
        {
            var address = ip.GetAddressBytes();
            request = new byte[4 + address.Length + 2];
            request[3] = ip.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
            address.CopyTo(request, 4);
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4 + address.Length), (ushort)targetPort);
        }
        else
        {
            var name = Encoding.ASCII.GetBytes(targetHost);
            if (name.Length > 255)
            {
                throw new ProxyHandshakeException("The destination host name is too long for SOCKS5.");
            }

            request = new byte[4 + 1 + name.Length + 2];
            request[3] = 0x03;
            request[4] = (byte)name.Length;
            name.CopyTo(request, 5);
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(5 + name.Length), (ushort)targetPort);
        }

        request[0] = 0x05;
        request[1] = command;
        request[2] = 0x00;
        return request;
    }

    /// <summary>Reads the bound address that follows a SOCKS5 reply header.</summary>
    public static async Task<IPEndPoint?> DrainSocks5AddressAsync(Stream stream, byte addressType, CancellationToken ct)
    {
        switch (addressType)
        {
            case 0x01:
            {
                var bound = await ReadExactlyAsync(stream, 6, ct).ConfigureAwait(false);
                return new IPEndPoint(new IPAddress(bound.AsSpan(0, 4)), BinaryPrimitives.ReadUInt16BigEndian(bound.AsSpan(4)));
            }

            case 0x04:
            {
                var bound = await ReadExactlyAsync(stream, 18, ct).ConfigureAwait(false);
                return new IPEndPoint(new IPAddress(bound.AsSpan(0, 16)), BinaryPrimitives.ReadUInt16BigEndian(bound.AsSpan(16)));
            }

            case 0x03:
            {
                var length = (await ReadExactlyAsync(stream, 1, ct).ConfigureAwait(false))[0];
                await ReadExactlyAsync(stream, length + 2, ct).ConfigureAwait(false);
                return null;
            }

            default:
                throw new ProxyHandshakeException("The proxy sent a malformed reply.");
        }
    }

    private static async Task Socks5AuthenticateAsync(Stream stream, string username, string password, CancellationToken ct)
    {
        var user = Encoding.UTF8.GetBytes(username);
        var pass = Encoding.UTF8.GetBytes(password);
        if (user.Length > 255 || pass.Length > 255)
        {
            throw new ProxyHandshakeException("SOCKS5 credentials must be at most 255 bytes each.");
        }

        var frame = new byte[3 + user.Length + pass.Length];
        frame[0] = 0x01;
        frame[1] = (byte)user.Length;
        user.CopyTo(frame, 2);
        frame[2 + user.Length] = (byte)pass.Length;
        pass.CopyTo(frame, 3 + user.Length);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        var reply = await ReadExactlyAsync(stream, 2, ct).ConfigureAwait(false);
        if (reply[1] != 0x00)
        {
            throw new ProxyHandshakeException("The proxy rejected the username or password.");
        }
    }

    // -- HTTP CONNECT --------------------------------------------------------

    private static async Task HttpConnectAsync(
        Stream stream, string? username, string? password, string targetHost, int targetPort, CancellationToken ct)
    {
        var authority = targetHost.Contains(':', StringComparison.Ordinal)
            ? $"[{targetHost}]:{targetPort}"
            : $"{targetHost}:{targetPort}";

        var sb = new StringBuilder();
        sb.Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(authority).Append("\r\n");
        if (!string.IsNullOrEmpty(username))
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            sb.Append("Proxy-Authorization: Basic ").Append(token).Append("\r\n");
        }

        sb.Append("Proxy-Connection: keep-alive\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        // Read up to the end of the response headers, byte by byte to avoid consuming
        // tunnelled payload that may follow immediately.
        var response = new StringBuilder();
        var one = new byte[1];
        while (!EndsWithBlankLine(response))
        {
            if (response.Length > 16 * 1024)
            {
                throw new ProxyHandshakeException("The proxy sent an oversized CONNECT response.");
            }

            var read = await stream.ReadAsync(one, ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new ProxyHandshakeException("The proxy closed the connection during CONNECT.");
            }

            response.Append((char)one[0]);
        }

        var statusLine = response.ToString().Split("\r\n", 2)[0];
        var fields = statusLine.Split(' ', 3);
        if (fields.Length < 2 || !fields[0].StartsWith("HTTP/", StringComparison.Ordinal) || !int.TryParse(fields[1], out var status))
        {
            throw new ProxyHandshakeException("The proxy did not answer as HTTP. Check the protocol setting.");
        }

        if (status is < 200 or > 299)
        {
            throw new ProxyHandshakeException(status switch
            {
                407 => "The proxy requires authentication. Add a username and password.",
                403 => "The proxy's ruleset does not allow this connection.",
                502 or 504 => "The proxy could not reach the destination.",
                _ => $"The proxy refused CONNECT with HTTP {status}.",
            });
        }
    }

    private static bool EndsWithBlankLine(StringBuilder sb) =>
        sb.Length >= 4 && sb[^1] == '\n' && sb[^2] == '\r' && sb[^3] == '\n' && sb[^4] == '\r';

    // -- helpers -------------------------------------------------------------

    public static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken ct)
    {
        var buffer = new byte[count];
        try
        {
            await stream.ReadExactlyAsync(buffer, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            throw new ProxyHandshakeException("The proxy closed the connection during the handshake.");
        }

        return buffer;
    }
}
