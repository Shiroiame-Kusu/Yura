using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Yura.Daemon.Linux;

/// <summary>A socket the kernel currently holds, with its owner when one could be found.</summary>
public sealed record OwnedSocket(
    ProtocolType Protocol,
    IPEndPoint Local,
    IPEndPoint Remote,
    string State,
    long Inode,
    int? OwnerPid);

/// <summary>
/// Attributes sockets to processes by joining <c>/proc/net/*</c> with <c>/proc/[pid]/fd</c>.
/// </summary>
/// <remarks>
/// This is the only way to answer "which process owns this socket" without a kernel module
/// or eBPF, and it needs root: <c>/proc/[pid]/fd</c> is only readable for one's own
/// processes. That is why the count lives in the daemon and the app shows "Unavailable"
/// when the daemon is not there.
///
/// Two paths exist. The full scan behind <see cref="Snapshot"/> joins every socket with every
/// process and is cached briefly; it feeds the process table's connection counts. The
/// targeted lookup behind <see cref="FindOwnerPid"/> is for attributing a single freshly
/// captured flow: it reads the socket's inode from the kernel table and scans only the few
/// processes that could possibly own it, so per-connection attribution stays cheap.
///
/// Both are inherently racy — a socket can close between the table read and the fd scan —
/// so callers get a snapshot, never a guarantee. Ownership that could not be established is
/// reported as null rather than guessed.
/// </remarks>
public sealed class SocketOwnership
{
    private static readonly TimeSpan CacheFor = TimeSpan.FromMilliseconds(750);
    private readonly object _lock = new();
    private IReadOnlyList<OwnedSocket> _cached = [];
    private DateTimeOffset _cachedAt = DateTimeOffset.MinValue;

    public IReadOnlyList<OwnedSocket> Snapshot()
    {
        lock (_lock)
        {
            if (DateTimeOffset.UtcNow - _cachedAt < CacheFor)
            {
                return _cached;
            }

            var sockets = ReadAllTables();
            var owners = MapInodesToPids(sockets.Select(s => s.Inode).Where(i => i > 0).ToHashSet(), null);
            _cached = sockets
                .Select(s => s with { OwnerPid = owners.TryGetValue(s.Inode, out var pid) ? pid : null })
                .ToArray();
            _cachedAt = DateTimeOffset.UtcNow;
            return _cached;
        }
    }

    /// <summary>Number of non-listening sockets per pid. Pids with none are absent, not zero.</summary>
    public IReadOnlyDictionary<int, int> CountsByPid()
    {
        var counts = new Dictionary<int, int>();
        foreach (var socket in Snapshot())
        {
            if (socket.OwnerPid is not { } pid || socket.State is "LISTEN")
            {
                continue;
            }

            counts[pid] = counts.GetValueOrDefault(pid) + 1;
        }

        return counts;
    }

    /// <summary>
    /// Finds the owner of one specific socket, checking <paramref name="candidates"/> first
    /// and falling back to the cached full map.
    /// </summary>
    /// <param name="local">The application's side: its source address and port.</param>
    /// <param name="remote">The application's peer, or null for an unconnected UDP socket.</param>
    public int? FindOwnerPid(ProtocolType protocol, IPEndPoint local, IPEndPoint? remote, IReadOnlyCollection<int> candidates)
    {
        var inode = FindInode(protocol, local, remote);
        if (inode is null)
        {
            return null;
        }

        if (candidates.Count > 0)
        {
            var owners = MapInodesToPids([inode.Value], candidates);
            if (owners.TryGetValue(inode.Value, out var pid))
            {
                return pid;
            }
        }

        return Snapshot().FirstOrDefault(s => s.Inode == inode.Value)?.OwnerPid;
    }

    private static long? FindInode(ProtocolType protocol, IPEndPoint local, IPEndPoint? remote)
    {
        var family = local.AddressFamily;
        var table = (protocol, family) switch
        {
            (ProtocolType.Tcp, AddressFamily.InterNetworkV6) => "/proc/net/tcp6",
            (ProtocolType.Tcp, _) => "/proc/net/tcp",
            (_, AddressFamily.InterNetworkV6) => "/proc/net/udp6",
            _ => "/proc/net/udp",
        };

        foreach (var socket in ReadTable(table, protocol, family))
        {
            if (!socket.Local.Equals(local))
            {
                continue;
            }

            if (remote is not null && socket.Remote.Port != 0 && !socket.Remote.Equals(remote))
            {
                continue;
            }

            return socket.Inode;
        }

        return null;
    }

    private static List<OwnedSocket> ReadAllTables()
    {
        var sockets = new List<OwnedSocket>(256);
        sockets.AddRange(ReadTable("/proc/net/tcp", ProtocolType.Tcp, AddressFamily.InterNetwork));
        sockets.AddRange(ReadTable("/proc/net/tcp6", ProtocolType.Tcp, AddressFamily.InterNetworkV6));
        sockets.AddRange(ReadTable("/proc/net/udp", ProtocolType.Udp, AddressFamily.InterNetwork));
        sockets.AddRange(ReadTable("/proc/net/udp6", ProtocolType.Udp, AddressFamily.InterNetworkV6));
        return sockets;
    }

    // -- /proc/net/{tcp,udp}{,6} ------------------------------------------

    private static IEnumerable<OwnedSocket> ReadTable(string path, ProtocolType protocol, AddressFamily family)
    {
        string[] lines;
        try
        {
            lines = File.ReadAllLines(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
        foreach (var line in lines.Skip(1))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 10)
            {
                continue;
            }

            if (!TryParseEndpoint(fields[1], family, out var local) ||
                !TryParseEndpoint(fields[2], family, out var remote) ||
                !long.TryParse(fields[9], NumberStyles.None, CultureInfo.InvariantCulture, out var inode))
            {
                continue;
            }

            var state = protocol == ProtocolType.Tcp ? TcpState(fields[3]) : "UDP";
            yield return new OwnedSocket(protocol, local, remote, state, inode, null);
        }
    }

    private static bool TryParseEndpoint(string text, AddressFamily family, out IPEndPoint endpoint)
    {
        endpoint = new IPEndPoint(IPAddress.None, 0);
        var colon = text.IndexOf(':', StringComparison.Ordinal);
        if (colon < 0)
        {
            return false;
        }

        var hexAddress = text[..colon];
        if (!int.TryParse(text[(colon + 1)..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var port))
        {
            return false;
        }

        // The kernel prints each 32-bit word of the address in host byte order.
        var bytes = Convert.FromHexString(hexAddress);
        if (family == AddressFamily.InterNetwork)
        {
            if (bytes.Length != 4)
            {
                return false;
            }

            Array.Reverse(bytes);
        }
        else
        {
            if (bytes.Length != 16)
            {
                return false;
            }

            for (var i = 0; i < 16; i += 4)
            {
                Array.Reverse(bytes, i, 4);
            }
        }

        var address = new IPAddress(bytes);
        // An IPv4 client of a dual-stack socket appears as ::ffff:a.b.c.d; normalise so it
        // compares equal to the IPv4 endpoint the listener reports.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        endpoint = new IPEndPoint(address, port);
        return true;
    }

    private static string TcpState(string hex) => hex switch
    {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => hex,
    };

    // -- /proc/[pid]/fd ------------------------------------------------------

    private static Dictionary<long, int> MapInodesToPids(HashSet<long> wanted, IReadOnlyCollection<int>? onlyPids)
    {
        var map = new Dictionary<long, int>(wanted.Count);
        if (wanted.Count == 0)
        {
            return map;
        }

        IEnumerable<int> pids = onlyPids ?? Directory.EnumerateDirectories("/proc")
            .Select(d => int.TryParse(Path.GetFileName(d), NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : -1)
            .Where(p => p > 0);

        foreach (var pid in pids)
        {
            IEnumerable<string> fds;
            try
            {
                fds = Directory.EnumerateFiles($"/proc/{pid}/fd");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                continue; // Exited, or a kernel thread.
            }

            foreach (var fd in fds)
            {
                string? target;
                try
                {
                    target = new FileInfo(fd).LinkTarget;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                // socket:[12345]
                if (target is null || !target.StartsWith("socket:[", StringComparison.Ordinal))
                {
                    continue;
                }

                if (long.TryParse(target.AsSpan(8, target.Length - 9), NumberStyles.None, CultureInfo.InvariantCulture, out var inode) &&
                    wanted.Contains(inode))
                {
                    map.TryAdd(inode, pid);
                    if (map.Count == wanted.Count)
                    {
                        return map;
                    }
                }
            }
        }

        return map;
    }
}
