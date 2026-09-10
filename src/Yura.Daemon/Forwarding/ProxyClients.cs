using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Yura.Core.Proxies;

namespace Yura.Daemon.Forwarding;

/// <summary>Raised when a proxy refuses or garbles a handshake. The message is operator-facing.</summary>
public sealed class ProxyHandshakeException(string message) : Exception(message);

/// <summary>
/// Opens a TCP tunnel to an arbitrary destination through a user-supplied proxy.
/// </summary>
/// <remarks>
/// Only what Yura needs: SOCKS5 CONNECT with optional username/password (RFC 1928, 1929)
/// and HTTP CONNECT (RFC 7231 §4.3.6). The destination is always sent as a literal address,
/// because by the time a flow reaches the daemon the application has already resolved it —
/// asking the proxy to resolve again could send the flow somewhere different.
/// </remarks>
public static class ProxyClients
{
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Performs the handshake for <paramref name="endpoint"/>'s protocol on an already-connected socket.</summary>
    public static async Task TunnelAsync(
        Socket upstream,
        ProxyEndpoint endpoint,
        string? password,
        IPEndPoint destination,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HandshakeTimeout);

        switch (endpoint.Protocol)
        {
            case ProxyProtocol.Socks5:
                await Socks5ConnectAsync(upstream, endpoint.Username, password, destination, timeout.Token)
                    .ConfigureAwait(false);
                break;
            case ProxyProtocol.Http:
                await HttpConnectAsync(upstream, endpoint.Username, password, destination, timeout.Token)
                    .ConfigureAwait(false);
                break;
            default:
                throw new ProxyHandshakeException(
                    $"{endpoint.Protocol} is not supported by the forwarder yet.");
        }
    }

    // -- SOCKS5 --------------------------------------------------------------

    private static async Task Socks5ConnectAsync(
        Socket socket, string? username, string? password, IPEndPoint destination, CancellationToken ct)
    {
        var wantsAuth = !string.IsNullOrEmpty(username);

        // Greeting: offer no-auth, plus user/pass when we have credentials.
        var greeting = wantsAuth ? new byte[] { 0x05, 0x02, 0x00, 0x02 } : new byte[] { 0x05, 0x01, 0x00 };
        await socket.SendAsync(greeting, ct).ConfigureAwait(false);

        var choice = await ReadExactlyAsync(socket, 2, ct).ConfigureAwait(false);
        if (choice[0] != 0x05)
        {
            throw new ProxyHandshakeException("The proxy did not answer as SOCKS5. Check the protocol setting.");
        }

        switch (choice[1])
        {
            case 0x00:
                break;
            case 0x02 when wantsAuth:
                await Socks5AuthenticateAsync(socket, username!, password ?? string.Empty, ct).ConfigureAwait(false);
                break;
            case 0x02:
                throw new ProxyHandshakeException("The proxy requires a username and password.");
            case 0xFF:
                throw new ProxyHandshakeException(
                    wantsAuth ? "The proxy rejected the offered authentication methods."
                              : "The proxy requires authentication. Add a username and password.");
            default:
                throw new ProxyHandshakeException($"The proxy chose an unsupported authentication method ({choice[1]:#x}).");
        }

        // CONNECT request with a literal address.
        var address = destination.Address.GetAddressBytes();
        var request = new byte[4 + address.Length + 2];
        request[0] = 0x05;
        request[1] = 0x01; // CONNECT
        request[2] = 0x00;
        request[3] = destination.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
        address.CopyTo(request, 4);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4 + address.Length), (ushort)destination.Port);
        await socket.SendAsync(request, ct).ConfigureAwait(false);

        var header = await ReadExactlyAsync(socket, 4, ct).ConfigureAwait(false);
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

        // Drain the bound address the proxy reports; we do not use it.
        var boundLength = header[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 => (await ReadExactlyAsync(socket, 1, ct).ConfigureAwait(false))[0],
            _ => throw new ProxyHandshakeException("The proxy sent a malformed CONNECT reply."),
        };
        await ReadExactlyAsync(socket, boundLength + 2, ct).ConfigureAwait(false);
    }

    private static async Task Socks5AuthenticateAsync(Socket socket, string username, string password, CancellationToken ct)
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
        await socket.SendAsync(frame, ct).ConfigureAwait(false);

        var reply = await ReadExactlyAsync(socket, 2, ct).ConfigureAwait(false);
        if (reply[1] != 0x00)
        {
            throw new ProxyHandshakeException("The proxy rejected the username or password.");
        }
    }

    // -- HTTP CONNECT --------------------------------------------------------

    private static async Task HttpConnectAsync(
        Socket socket, string? username, string? password, IPEndPoint destination, CancellationToken ct)
    {
        var authority = destination.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{destination.Address}]:{destination.Port}"
            : $"{destination.Address}:{destination.Port}";

        var sb = new StringBuilder();
        sb.Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(authority).Append("\r\n");
        if (!string.IsNullOrEmpty(username))
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            sb.Append("Proxy-Authorization: Basic ").Append(token).Append("\r\n");
        }

        sb.Append("Proxy-Connection: keep-alive\r\n\r\n");
        await socket.SendAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct).ConfigureAwait(false);

        // Read up to the end of the response headers, byte by byte to avoid consuming
        // tunnelled payload that may follow immediately.
        var response = new StringBuilder();
        var one = new byte[1];
        while (!response.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            if (response.Length > 16 * 1024)
            {
                throw new ProxyHandshakeException("The proxy sent an oversized CONNECT response.");
            }

            var read = await socket.ReceiveAsync(one, ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new ProxyHandshakeException("The proxy closed the connection during CONNECT.");
            }

            response.Append((char)one[0]);
        }

        var statusLine = response.ToString().Split("\r\n", 2)[0];
        var fields = statusLine.Split(' ', 3);
        if (fields.Length < 2 || !int.TryParse(fields[1], out var status))
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

    // -- helpers -------------------------------------------------------------

    private static async Task<byte[]> ReadExactlyAsync(Socket socket, int count, CancellationToken ct)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new ProxyHandshakeException("The proxy closed the connection during the handshake.");
            }

            offset += read;
        }

        return buffer;
    }
}
