using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Yura.Core.Ipc;
using Yura.Core.Proxies;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Measures the same target the same way, directly and through a route, so the two
/// figures the Games page shows side by side are actually comparable.
/// </summary>
/// <remarks>
/// The probe is a TCP connect: it is the one measurement that works identically on a bare
/// path and through any proxy protocol, and it is what a game's own connection setup
/// experiences. Through a proxy the figure is the full round trip (here → proxy → target),
/// which is the latency the application will see, not just the hop to the proxy. ICMP would
/// be a different thing measured a different way and is deliberately not mixed in.
///
/// Figures are medians and mean absolute deviations of the samples that were answered; a target
/// that never answers yields no latency rather than a zero. A refused connection counts as an
/// answer: the refusal comes from the destination, one round trip away, so the host is there
/// and the time is its latency. Counting it as loss reported every game server that listens only
/// on UDP, and so refuses TCP, as unreachable.
/// </remarks>
public static class NetworkMeasurer
{
    private static readonly TimeSpan SampleTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan Gap = TimeSpan.FromMilliseconds(120);

    /// <summary>Port 1 on the proxy's own loopback: closed on every host, so connecting to it must fail.</summary>
    private static readonly IPEndPoint ClosedEverywhere = new(IPAddress.Loopback, 1);

    /// <summary>How long what a proxy was found to do is trusted before it is asked again.</summary>
    private static readonly TimeSpan EarlyAnswerLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long a proxy that could not be asked is left alone: asking again at every sample would
    /// add the wait to each one.
    /// </summary>
    private static readonly TimeSpan UnknownAnswerLifetime = TimeSpan.FromMinutes(1);

    private static readonly ConcurrentDictionary<string, (bool Early, DateTimeOffset Until)> EarlyAnswers = new();

    public static async Task<MeasurementDto> MeasureAsync(
        IPEndPoint target, IReadOnlyList<ProxyHop>? route, int samples, CancellationToken ct)
    {
        samples = Math.Clamp(samples, 1, 20);
        var direct = await SampleAsync(samples, async token =>
        {
            await using var leg = await ProxyDialer.OpenDirectAsync(target, token).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);

        SampleSetDto? routed = null;
        var early = route is { Count: > 0 } && await AnswersBeforeConnectingAsync(route, ct).ConfigureAwait(false);
        if (route is { Count: > 0 } && !early)
        {
            routed = await SampleAsync(samples, async token =>
            {
                await using var leg = await ProxyDialer.OpenAsync(route, target, token).ConfigureAwait(false);
            }, ct).ConfigureAwait(false);
        }

        return new MeasurementDto
        {
            Target = target.ToString(),
            Method = "TCP connect",
            Direct = direct,
            Routed = routed,
            RouteAnswersBeforeConnecting = early,
            MeasuredAtUtc = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>
    /// Whether the route's last proxy says a connection is made before it has made it.
    /// </summary>
    /// <remarks>
    /// Some proxies answer a CONNECT at once and dial afterwards — mihomo (Clash) does, on its
    /// SOCKS5 and HTTP ports alike. Timed by connecting, a route through one is as fast as the
    /// proxy itself, whatever lies beyond it: on loopback, a fraction of a millisecond. Asking the
    /// proxy for a port that is closed on every host tells the two kinds apart without sending
    /// anything anywhere: one that dials first reports the refusal, one that answers first reports
    /// success. Only the last proxy matters; every hop before it has to carry the real answer back.
    /// What was found is kept for a while, because the session's monitor measures every few seconds.
    /// </remarks>
    internal static async Task<bool> AnswersBeforeConnectingAsync(IReadOnlyList<ProxyHop> route, CancellationToken ct)
    {
        if (route is not [.., { Tunnel: null, Endpoint.Protocol: ProxyProtocol.Socks5 or ProxyProtocol.Http or ProxyProtocol.Https }])
        {
            return false;
        }

        var key = string.Join('>', route.Select(h => $"{h.Endpoint.Protocol}:{h.Endpoint.Host}:{h.Endpoint.Port}"));
        if (EarlyAnswers.TryGetValue(key, out var known) && DateTimeOffset.UtcNow < known.Until)
        {
            return known.Early;
        }

        var early = await ProbeEarlyAnswerAsync(async (target, token) =>
            await ProxyDialer.OpenAsync(route, target, token).ConfigureAwait(false), ct).ConfigureAwait(false);
        EarlyAnswers[key] = (early ?? false, DateTimeOffset.UtcNow + (early is null ? UnknownAnswerLifetime : EarlyAnswerLifetime));
        return early ?? false;
    }

    /// <summary>Makes the next measurement through each proxy find out again what it does.</summary>
    public static void ForgetEarlyAnswers() => EarlyAnswers.Clear();

    /// <summary>
    /// Asks for <see cref="ClosedEverywhere"/>: true when told it is open, false when told it is
    /// not, null when no proxy answered at all and so nothing was learned.
    /// </summary>
    internal static async Task<bool?> ProbeEarlyAnswerAsync(
        Func<IPEndPoint, CancellationToken, Task<IAsyncDisposable>> open, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(SampleTimeout);
        try
        {
            await (await open(ClosedEverywhere, timeout.Token).ConfigureAwait(false)).DisposeAsync().ConfigureAwait(false);
            return true;
        }
        catch (ProxyHandshakeException)
        {
            // Refused, by the destination or by the proxy's own rules: either way it was asked
            // before it answered.
            return false;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception e) when (e is SocketException or IOException)
        {
            return null;
        }
    }

    /// <summary>Whether a failed connect was nonetheless answered by the destination.</summary>
    internal static bool IsAnswer(Exception e) =>
        e is SocketException { SocketErrorCode: SocketError.ConnectionRefused } or DestinationRefusedException;

    internal static async Task<SampleSetDto> SampleAsync(int count, Func<CancellationToken, Task> attempt, CancellationToken ct)
    {
        var successes = new List<double>(count);
        string? lastFailure = null;

        for (var i = 0; i < count; i++)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(SampleTimeout);
            var stopwatch = Stopwatch.StartNew();
            try
            {
                await attempt(timeout.Token).ConfigureAwait(false);
                successes.Add(stopwatch.Elapsed.TotalMilliseconds);
            }
            catch (Exception e) when (IsAnswer(e))
            {
                successes.Add(stopwatch.Elapsed.TotalMilliseconds);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                lastFailure = "timed out";
            }
            catch (ProxyHandshakeException e)
            {
                lastFailure = e.Message;
            }
            catch (Exception e) when (e is SocketException or IOException)
            {
                lastFailure = e is SocketException s ? s.SocketErrorCode.ToString() : e.Message;
            }

            if (i + 1 < count)
            {
                await Task.Delay(Gap, ct).ConfigureAwait(false);
            }
        }

        double? latency = null;
        double? jitter = null;
        if (successes.Count > 0)
        {
            var sorted = successes.Order().ToList();
            latency = sorted.Count % 2 == 1
                ? sorted[sorted.Count / 2]
                : (sorted[sorted.Count / 2 - 1] + sorted[sorted.Count / 2]) / 2;
            if (successes.Count > 1)
            {
                var mean = successes.Average();
                jitter = successes.Average(s => Math.Abs(s - mean));
            }
        }

        return new SampleSetDto
        {
            Samples = count,
            Successes = successes.Count,
            LatencyMilliseconds = latency,
            JitterMilliseconds = jitter,
            LossPercent = 100.0 * (count - successes.Count) / count,
            FailureReason = successes.Count == count ? null : lastFailure,
            RoundTripsMilliseconds = successes,
        };
    }
}
