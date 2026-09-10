using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Yura.Core.Ipc;
using Yura.Core.Proxies;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Tests a proxy the way the forwarder will use it.
/// </summary>
/// <remarks>
/// Reachability is a completed authentication negotiation, not a TCP connect: a port that
/// accepts and then refuses SOCKS is not a working proxy. UDP support is established by
/// actually requesting an association, because plenty of SOCKS5 servers advertise nothing
/// and simply refuse the command. An HTTPS proxy must complete its TLS handshake.
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
            address = await ProxyDialer.ResolveAsync(endpoint.Host, token).ConfigureAwait(false);
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
        Socket socket;
        try
        {
            socket = await ProxyDialer.ConnectWithBypassAsync(address.ToString(), endpoint.Port, token).ConfigureAwait(false);
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

        using (socket)
        {
            Stream stream = new NetworkStream(socket, ownsSocket: false);
            try
            {
                if (endpoint.Protocol == ProxyProtocol.Https)
                {
                    var tls = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, errors) =>
                        errors == SslPolicyErrors.None || endpoint.AllowInvalidCertificate);
                    try
                    {
                        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                        {
                            TargetHost = endpoint.Host,
                            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        }, token).ConfigureAwait(false);
                    }
                    catch (Exception e) when (e is IOException or System.Security.Authentication.AuthenticationException)
                    {
                        return new ProbeResultDto
                        {
                            Reachable = false,
                            FailureReason = "The TLS handshake with the proxy failed. Check the certificate, or allow an invalid one if you trust this proxy.",
                            Diagnostics = e.Message,
                        };
                    }

                    stream = tls;
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
                        Diagnostics = endpoint.Protocol == ProxyProtocol.Https
                            ? "TCP connect and TLS handshake succeeded. HTTP CONNECT itself is only exercised by a real flow."
                            : "TCP connect succeeded. HTTP CONNECT itself is only exercised by a real flow.",
                    };
                }

                await ProxyDialer.Socks5GreetAsync(stream, endpoint.Username, password, token).ConfigureAwait(false);
                var handshake = stopwatch.Elapsed.TotalMilliseconds;

                await stream.WriteAsync(ProxyDialer.BuildSocks5Request(0x03, "0.0.0.0", 0), token).ConfigureAwait(false);
                await stream.FlushAsync(token).ConfigureAwait(false);
                var reply = new byte[4];
                var read = 0;
                while (read < 4)
                {
                    var n = await stream.ReadAsync(reply.AsMemory(read), token).ConfigureAwait(false);
                    if (n == 0)
                    {
                        break;
                    }

                    read += n;
                }

                var udp = read == 4 && reply[1] == 0 ? CapabilityState.Supported : CapabilityState.Unsupported;
                return new ProbeResultDto
                {
                    Reachable = true,
                    HandshakeMilliseconds = handshake,
                    Udp = udp,
                    Diagnostics = udp == CapabilityState.Supported
                        ? "SOCKS5 negotiation and UDP ASSOCIATE both succeeded."
                        : $"SOCKS5 negotiation succeeded; UDP ASSOCIATE was refused (reply {(read == 4 ? reply[1] : -1):#x}).",
                };
            }
            catch (ProxyHandshakeException e)
            {
                return new ProbeResultDto { Reachable = false, FailureReason = e.Message };
            }
            catch (Exception e) when (e is SocketException or IOException or OperationCanceledException)
            {
                return new ProbeResultDto
                {
                    Reachable = false,
                    FailureReason = "The proxy stopped responding during the handshake.",
                    Diagnostics = e.Message,
                };
            }
            finally
            {
                stream.Dispose();
            }
        }
    }
}
