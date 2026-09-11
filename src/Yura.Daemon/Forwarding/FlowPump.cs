using System.Net.Sockets;

namespace Yura.Daemon.Forwarding;

/// <summary>Copies bytes both ways between the application's socket and an upstream leg.</summary>
internal static class FlowPump
{
    private const int BufferSize = 64 * 1024;

    public static async Task RunAsync(Socket client, UpstreamLeg upstream, Flow flow, CancellationToken cancellationToken)
    {
        var up = CopyUpAsync(client, upstream, flow, cancellationToken);
        var down = CopyDownAsync(upstream, client, flow, cancellationToken);

        // When either direction finishes, half-close the other side so the peer sees EOF,
        // then wait for the remaining direction to drain naturally.
        await Task.WhenAny(up, down).ConfigureAwait(false);
        flow.MarkClosing();
        await Task.WhenAll(up, down).ConfigureAwait(false);
    }

    private static async Task CopyUpAsync(Socket client, UpstreamLeg upstream, Flow flow, CancellationToken ct)
    {
        var buffer = new byte[BufferSize];
        try
        {
            while (true)
            {
                var read = await client.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await upstream.Stream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                await upstream.Stream.FlushAsync(ct).ConfigureAwait(false);
                flow.AddUp(read);
            }
        }
        catch (Exception e) when (e is SocketException or IOException or ObjectDisposedException or OperationCanceledException)
        {
            // A reset or cancellation ends the copy; the pump's caller closes both sockets.
        }
        finally
        {
            await upstream.ShutdownSendAsync().ConfigureAwait(false);
        }
    }

    private static async Task CopyDownAsync(UpstreamLeg upstream, Socket client, Flow flow, CancellationToken ct)
    {
        var buffer = new byte[BufferSize];
        try
        {
            while (true)
            {
                var read = await upstream.Stream.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await client.SendAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                flow.AddDown(read);
            }
        }
        catch (Exception e) when (e is SocketException or IOException or ObjectDisposedException or OperationCanceledException)
        {
        }
        finally
        {
            try
            {
                client.Shutdown(SocketShutdown.Send);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException)
            {
            }
        }
    }
}
