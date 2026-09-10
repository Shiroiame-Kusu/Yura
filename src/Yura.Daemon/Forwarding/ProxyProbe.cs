using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Tests a proxy the way the forwarder will use it.
/// </summary>
/// <remarks>
/// Reachability is a completed authentication negotiation, not a TCP connect: a port that
/// accepts and then refuses SOCKS is not a working proxy. UDP support is established by
/// actually requesting an association, because plenty of SOCKS5 servers advertise nothing
/// and simply refuse the command.
/// </remarks>
public static class ProxyProbe
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(6);

    public static async Task<ProbeResultDto> RunAsync(ProxyEndpoint endpoint, string? password, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        var token = timeout.Token;

        IPAddress address;
        try
        {
            if (!IPAddress.TryParse(endpoint.Host, out address!))
            {
                var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, token).ConfigureAwait(false);
                address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                          ?? addresses.FirstOrDefault()
                          ?? throw new SocketException((int)SocketError.HostNotFound);
            }
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            return new ProbeResultDto
            {
                Reachable = false,
                FailureReason = $"The host name '{endpoint.Host}' could not be resolved.",
                Diagnostics = e.Message,
            };
        }

        var stopwatch = Stopwatch.StartNew();
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.SetMark(PolicyRouting.BypassMark);

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, endpoint.Port), token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            return new ProbeResultDto
            {
                Reachable = false,
                FailureReason = $"Nothing is listening at {endpoint.Authority}, or it is blocked.",
                Diagnostics = e.Message,
            };
        }

        if (endpoint.Protocol != ProxyProtocol.Socks5)
        {
            // Without a destination to CONNECT to there is nothing more to verify for
            // HTTP; report exactly what was measured.
            return new ProbeResultDto
            {
                Reachable = true,
                HandshakeMilliseconds = stopwatch.Elapsed.TotalMilliseconds,
                Udp = CapabilityState.Unsupported,
                Diagnostics = "TCP connect succeeded. HTTP CONNECT itself is only exercised by a real flow.",
            };
        }

        // SOCKS5: negotiate auth, then try UDP ASSOCIATE to learn UDP support.
        try
        {
            var wantsAuth = !string.IsNullOrEmpty(endpoint.Username);
            await socket.SendAsync(wantsAuth ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 }, token).ConfigureAwait(false);
            var choice = new byte[2];
            if (await ReadAsync(socket, choice, token).ConfigureAwait(false) != 2 || choice[0] != 5)
            {
                return new ProbeResultDto
                {
                    Reachable = false,
                    FailureReason = "The server answered, but not as SOCKS5. Check the protocol.",
                };
            }

            if (choice[1] == 0xFF)
            {
                return new ProbeResultDto
                {
                    Reachable = false,
                    FailureReason = wantsAuth
                        ? "The proxy rejected the offered authentication methods."
                        : "The proxy requires authentication. Add a username and password.",
                };
            }

            if (choice[1] == 2)
            {
                if (!wantsAuth)
                {
                    return new ProbeResultDto
                    {
                        Reachable = false,
                        FailureReason = "The proxy requires a username and password.",
                    };
                }

                var user = System.Text.Encoding.UTF8.GetBytes(endpoint.Username!);
                var pass = System.Text.Encoding.UTF8.GetBytes(password ?? string.Empty);
                var frame = new byte[3 + user.Length + pass.Length];
                frame[0] = 1;
                frame[1] = (byte)user.Length;
                user.CopyTo(frame, 2);
                frame[2 + user.Length] = (byte)pass.Length;
                pass.CopyTo(frame, 3 + user.Length);
                await socket.SendAsync(frame, token).ConfigureAwait(false);
                var auth = new byte[2];
                if (await ReadAsync(socket, auth, token).ConfigureAwait(false) != 2 || auth[1] != 0)
                {
                    return new ProbeResultDto
                    {
                        Reachable = false,
                        FailureReason = "The proxy rejected the username or password.",
                    };
                }
            }

            var handshake = stopwatch.Elapsed.TotalMilliseconds;

            await socket.SendAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, token).ConfigureAwait(false);
            var reply = new byte[4];
            var udp = await ReadAsync(socket, reply, token).ConfigureAwait(false) == 4 && reply[1] == 0
                ? CapabilityState.Supported
                : CapabilityState.Unsupported;

            return new ProbeResultDto
            {
                Reachable = true,
                HandshakeMilliseconds = handshake,
                Udp = udp,
                Diagnostics = udp == CapabilityState.Supported
                    ? "SOCKS5 negotiation and UDP ASSOCIATE both succeeded."
                    : $"SOCKS5 negotiation succeeded; UDP ASSOCIATE was refused (reply {reply[1]:#x}).",
            };
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            return new ProbeResultDto
            {
                Reachable = false,
                FailureReason = "The proxy stopped responding during the handshake.",
                Diagnostics = e.Message,
            };
        }
    }

    private static async Task<int> ReadAsync(Socket socket, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset), ct).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return offset;
    }
}
