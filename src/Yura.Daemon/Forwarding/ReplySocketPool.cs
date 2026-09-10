using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// The transparent sockets that answer applications from the address they addressed.
/// </summary>
/// <remarks>
/// A UDP reply must appear to come from the peer the application sent to, which means sending
/// from a socket bound to that foreign address — what <c>IP_TRANSPARENT</c> exists to permit.
///
/// Such a socket also *receives* traffic addressed there, and the kernel's early demux
/// prefers it over the TPROXY redirect. That is not a hazard to be avoided but a second
/// delivery path to be handled: datagrams arriving here carry the same information the TPROXY
/// socket would have given (sender, payload, and the destination this socket is bound to), so
/// they are fed back through the same dispatch. Without this, the second and every later
/// datagram to a destination that already has a session would be silently queued on an idle
/// socket and lost — which is exactly what a DNS resolver behind a proxy would experience.
///
/// One socket per original destination, shared by every session to it, created on first use.
/// </remarks>
internal sealed class ReplySocketPool : IAsyncDisposable
{
    private readonly ConcurrentDictionary<IPEndPoint, Entry> _entries = new();
    private readonly Func<IPEndPoint, IPEndPoint, byte[], Task> _dispatch;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _stopping = new();

    public ReplySocketPool(Func<IPEndPoint, IPEndPoint, byte[], Task> dispatch, Action<string> log)
    {
        _dispatch = dispatch;
        _log = log;
    }

    private sealed record Entry(Socket Socket, Task Drain);

    /// <summary>Sends one datagram to <paramref name="client"/> as if it came from <paramref name="original"/>.</summary>
    public async Task SendAsync(IPEndPoint original, IPEndPoint client, ReadOnlyMemory<byte> payload)
    {
        if (!TryGet(original, out var socket))
        {
            return;
        }

        try
        {
            await socket.SendToAsync(payload, client, _stopping.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    /// <summary>Opens the socket for a destination up front, so a session fails early if it cannot.</summary>
    public bool Reserve(IPEndPoint original) => TryGet(original, out _);

    private bool TryGet(IPEndPoint original, out Socket socket)
    {
        if (_entries.TryGetValue(original, out var existing))
        {
            socket = existing.Socket;
            return true;
        }

        Socket created;
        try
        {
            created = new Socket(original.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            created.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            created.SetTransparent();
            created.SetMark(PolicyRouting.BypassMark);
            created.Bind(original);
        }
        catch (SocketException e)
        {
            _log($"udp: cannot answer as {original}: {e.SocketErrorCode}");
            socket = null!;
            return false;
        }

        var entry = new Entry(created, Task.CompletedTask);
        if (!_entries.TryAdd(original, entry))
        {
            created.Dispose();
            socket = _entries[original].Socket;
            return true;
        }

        _entries[original] = entry with { Drain = DrainAsync(created, original, _stopping.Token) };
        socket = created;
        return true;
    }

    /// <summary>
    /// Handles datagrams the kernel delivered here instead of to the TPROXY socket.
    /// </summary>
    private async Task DrainAsync(Socket socket, IPEndPoint original, CancellationToken ct)
    {
        var buffer = new byte[65535];
        var any = new IPEndPoint(original.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            if (received.ReceivedBytes == 0 || received.RemoteEndPoint is not IPEndPoint client)
            {
                continue;
            }

            var datagram = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            try
            {
                await _dispatch(client, original, datagram).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or IOException or ObjectDisposedException)
            {
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stopping.Cancel();
        foreach (var entry in _entries.Values)
        {
            entry.Socket.Dispose();
            try
            {
                await entry.Drain.ConfigureAwait(false);
            }
            catch (Exception)
            {
            }
        }

        _entries.Clear();
        _stopping.Dispose();
    }
}
