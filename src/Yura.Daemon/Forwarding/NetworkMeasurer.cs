using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Yura.Core.Ipc;

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
/// Figures are medians and mean absolute deviations of the successful samples; a target that
/// never answers yields no latency rather than a zero.
/// </remarks>
public static class NetworkMeasurer
{
    private static readonly TimeSpan SampleTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan Gap = TimeSpan.FromMilliseconds(120);

    public static async Task<MeasurementDto> MeasureAsync(
        IPEndPoint target, IReadOnlyList<ProxyHop>? route, int samples, CancellationToken ct)
    {
        samples = Math.Clamp(samples, 1, 20);
        var direct = await SampleAsync(samples, async token =>
        {
            await using var leg = await ProxyDialer.OpenDirectAsync(target, token).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);

        SampleSetDto? routed = null;
        if (route is { Count: > 0 })
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
            MeasuredAtUtc = DateTimeOffset.UtcNow,
        };
    }

    private static async Task<SampleSetDto> SampleAsync(int count, Func<CancellationToken, Task> attempt, CancellationToken ct)
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
