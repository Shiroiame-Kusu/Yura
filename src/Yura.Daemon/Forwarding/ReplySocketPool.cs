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
/// One socket per original destination, shared by every session to it, created when the first
/// session reserves it and closed when the last one releases it. Kept for the listener's whole
/// life instead, every server, peer and resolver a game or browser ever reached held a socket
/// and a receive buffer until the rule was removed.
/// </remarks>
internal sealed class ReplySocketPool : IAsyncDisposable
{
    private readonly Dictionary<IPEndPoint, Entry> _entries = [];
    private readonly Lock _gate = new();
    private readonly Func<IPEndPoint, IPEndPoint, byte[], Task> _dispatch;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _stopping = new();

    public ReplySocketPool(Func<IPEndPoint, IPEndPoint, byte[], Task> dispatch, Action<string> log)
    {
        _dispatch = dispatch;
        _log = log;
    }

    private sealed class Entry(Socket socket)
    {
        public Socket Socket { get; } = socket;

        public int Users { get; set; }

        public Task Drain { get; set; } = Task.CompletedTask;
    }

    /// <summary>Destinations that currently have a socket. For tests and diagnostics.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Sends one datagram to <paramref name="client"/> as if it came from <paramref name="original"/>.</summary>
    public async Task SendAsync(IPEndPoint original, IPEndPoint client, ReadOnlyMemory<byte> payload)
    {
        Socket? socket;
        lock (_gate)
        {
            socket = _entries.GetValueOrDefault(original)?.Socket;
        }

        if (socket is null)
        {
            return; // No session holds this destination any more, so there is nobody to answer.
        }

        try
        {
            await socket.SendToAsync(payload, client, _stopping.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
        {
        }
    }

    /// <summary>
    /// Takes a reference on the socket for a destination, opening it if this is the first.
    /// Every reservation that returns true must be matched by one <see cref="Release"/>.
    /// </summary>
    /// <returns>False when the socket cannot be opened; replies to that destination are then lost.</returns>
    public bool Reserve(IPEndPoint original)
    {
        Entry entry;
        lock (_gate)
        {
            if (_entries.TryGetValue(original, out var existing))
            {
                existing.Users++;
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
                return false;
            }

            entry = new Entry(created) { Users = 1 };
            _entries[original] = entry;
        }

        // Started outside the lock: a datagram already waiting would be dispatched from here,
        // and dispatching can reserve.
        entry.Drain = DrainAsync(entry.Socket, original, _stopping.Token);
        return true;
    }

    /// <summary>Gives back a reservation; the last one closes the destination's socket.</summary>
    public void Release(IPEndPoint original)
    {
        Socket closing;
        lock (_gate)
        {
            if (!_entries.TryGetValue(original, out var entry) || --entry.Users > 0)
            {
                return;
            }

            _entries.Remove(original);
            closing = entry.Socket;
        }

        // Ends its drain loop, which is waiting in a receive on it.
        closing.Dispose();
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
        List<Entry> entries;
        lock (_gate)
        {
            entries = _entries.Values.ToList();
            _entries.Clear();
        }

        foreach (var entry in entries)
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

        _stopping.Dispose();
    }
}
