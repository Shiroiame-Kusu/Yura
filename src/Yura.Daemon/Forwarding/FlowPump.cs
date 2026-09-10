using System.Net.Sockets;

namespace Yura.Daemon.Forwarding;

/// <summary>Copies bytes both ways between two sockets until both directions are done.</summary>
internal static class FlowPump
{
    private const int BufferSize = 64 * 1024;

    public static async Task RunAsync(Socket client, Socket upstream, Flow flow, CancellationToken cancellationToken)
    {
        var up = CopyAsync(client, upstream, flow.AddUp, cancellationToken);
        var down = CopyAsync(upstream, client, flow.AddDown, cancellationToken);

        // When either direction finishes, half-close the other side so the peer sees EOF,
        // then wait for the remaining direction to drain naturally.
        var first = await Task.WhenAny(up, down).ConfigureAwait(false);
        flow.MarkClosing();
        TryShutdown(first == up ? upstream : client);
        await Task.WhenAll(up, down).ConfigureAwait(false);
    }

    private static async Task CopyAsync(Socket from, Socket to, Action<long> count, CancellationToken ct)
    {
        var buffer = new byte[BufferSize];
        try
        {
            while (true)
            {
                var read = await from.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await to.SendAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                count(read);
            }
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
            // A reset or cancellation ends the copy; the pump's caller closes both sockets.
        }
        finally
        {
            TryShutdown(to);
        }
    }

    private static void TryShutdown(Socket socket)
    {
        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException)
        {
        }
    }
}
