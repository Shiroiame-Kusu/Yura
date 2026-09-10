using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace Yura.Daemon.Linux;

/// <summary>What the kernel told us about a process.</summary>
public enum ProcessEventKind
{
    /// <summary>A new process (not a thread) was created. Payload: parent tgid, child tgid.</summary>
    Fork,

    /// <summary>A process replaced its image. Payload: tgid.</summary>
    Exec,

    /// <summary>A process exited. Payload: tgid, exit code.</summary>
    Exit,
}

public readonly record struct ProcessEvent(ProcessEventKind Kind, int Pid, int ChildPid, int ExitCode);

/// <summary>
/// Subscribes to the kernel's process connector (<c>NETLINK_CONNECTOR</c> / <c>CN_IDX_PROC</c>)
/// and turns fork, exec and exit notifications into a stream of events.
/// </summary>
/// <remarks>
/// This is what makes process tracking event-driven instead of polled. It matters for
/// three things a poll cannot do well:
/// <list type="bullet">
/// <item>A process that starts and connects within a poll interval keeps its original route,
/// because a socket's cgroup is fixed at creation. The exec event arrives within
/// microseconds of the new image, so the migration usually beats the first connect.</item>
/// <item>Excluding children from a rule needs the fork event: the child inherits its
/// parent's cgroup and must be moved out before it opens a socket.</item>
/// <item>An instance rule can expire the moment its process exits rather than half a second
/// later, so nothing can reuse the pid in between.</item>
/// </list>
/// .NET's <see cref="System.Net.Sockets.Socket"/> does not model netlink, so the socket is
/// driven through libc directly on a dedicated thread. Events are delivered through a channel,
/// which decouples the receive loop from the runtime's asynchronous handling. The kernel drops
/// events under load (<c>ENOBUFS</c>); that is counted, and the periodic membership sweep
/// remains as the safety net.
/// </remarks>
public sealed class ProcessEventWatcher : IDisposable
{
    private const int AfNetlink = 16;
    private const int SockDgram = 2;
    private const int NetlinkConnector = 11;
    private const uint CnIdxProc = 1;
    private const uint CnValProc = 1;
    private const uint ProcCnMcastListen = 1;
    private const uint ProcCnMcastIgnore = 2;
    private const ushort NlmsgDone = 3;

    private const uint ProcEventFork = 0x00000001;
    private const uint ProcEventExec = 0x00000002;
    private const uint ProcEventExit = 0x80000000;

    private readonly Action<string> _log;
    private readonly Channel<ProcessEvent> _events = Channel.CreateUnbounded<ProcessEvent>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private int _fd = -1;
    private Thread? _thread;
    private long _dropped;
    private volatile bool _stopping;

    public ProcessEventWatcher(Action<string> log) => _log = log;

    public ChannelReader<ProcessEvent> Events => _events.Reader;

    /// <summary>
    /// Called on the receive thread, before the event is queued, for every new process.
    /// </summary>
    /// <remarks>
    /// Exists for one job: moving a child out of a cgroup it must not be in, before it can
    /// open a socket. A socket's cgroup is fixed at creation, so that decision cannot be
    /// deferred — going through the channel and the runtime's lock loses the race against a
    /// child that connects immediately. Whatever is installed here must do a bounded, tiny
    /// amount of work: blocking this thread makes the kernel drop events.
    /// </remarks>
    public Func<int, int, bool>? OnForkFastPath { get; set; }

    public bool IsRunning { get; private set; }

    /// <summary>Why the watcher is not running, for the diagnostics page.</summary>
    public string? UnavailableReason { get; private set; }

    /// <summary>Events the kernel discarded because we did not read fast enough.</summary>
    public long DroppedEvents => Interlocked.Read(ref _dropped);

    public bool Start()
    {
        var fd = socket(AfNetlink, SockDgram, NetlinkConnector);
        if (fd < 0)
        {
            UnavailableReason = $"the kernel has no process connector (socket: errno {Marshal.GetLastPInvokeError()}); " +
                                "CONFIG_PROC_EVENTS is probably off";
            return false;
        }

        // struct sockaddr_nl { sa_family_t nl_family; unsigned short nl_pad; __u32 nl_pid; __u32 nl_groups; }
        var address = new byte[12];
        BinaryPrimitives.WriteUInt16LittleEndian(address, AfNetlink);
        BinaryPrimitives.WriteUInt32LittleEndian(address.AsSpan(4), 0); // let the kernel pick a port id
        BinaryPrimitives.WriteUInt32LittleEndian(address.AsSpan(8), CnIdxProc);
        if (bind(fd, address, address.Length) < 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            close(fd);
            UnavailableReason = errno == 1
                ? "binding the process connector needs CAP_NET_ADMIN"
                : $"could not bind the process connector (errno {errno})";
            return false;
        }

        // The kernel drops events it cannot queue (ENOBUFS), and a fork storm is exactly when
        // the exclusion path must not miss one. Ask for a generous buffer; failure is harmless.
        var size = BitConverter.GetBytes(8 * 1024 * 1024);
        setsockopt(fd, 1 /* SOL_SOCKET */, 33 /* SO_RCVBUFFORCE */, size, size.Length);

        if (!Subscribe(fd, ProcCnMcastListen))
        {
            var errno = Marshal.GetLastPInvokeError();
            close(fd);
            UnavailableReason = $"could not subscribe to process events (errno {errno})";
            return false;
        }

        _fd = fd;
        _thread = new Thread(ReceiveLoop)
        {
            IsBackground = true,
            Name = "yura-proc-events",
            // Blocked on recv almost all the time; when it wakes, the work is a race against
            // a child process creating a socket.
            Priority = ThreadPriority.AboveNormal,
        };
        _thread.Start();
        IsRunning = true;
        _log("process events: subscribed to the kernel process connector");
        return true;
    }

    private static bool Subscribe(int fd, uint op)
    {
        // nlmsghdr(16) + cn_msg(20) + __u32 op
        var message = new byte[40];
        BinaryPrimitives.WriteUInt32LittleEndian(message, 40);                 // nlmsg_len
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(4), NlmsgDone); // nlmsg_type
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(6), 0);         // nlmsg_flags
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(8), 0);         // nlmsg_seq
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(12), (uint)Environment.ProcessId);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(16), CnIdxProc);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(20), CnValProc);
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(24), 0);        // seq
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(28), 0);        // ack
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(32), 4);        // len
        BinaryPrimitives.WriteUInt16LittleEndian(message.AsSpan(34), 0);        // flags
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(36), op);
        return send(fd, message, (nuint)message.Length, 0) == message.Length;
    }

    private void ReceiveLoop()
    {
        var buffer = new byte[64 * 1024];
        while (!_stopping)
        {
            var received = recv(_fd, buffer, (nuint)buffer.Length, 0);
            if (received < 0)
            {
                var errno = Marshal.GetLastPInvokeError();
                switch (errno)
                {
                    case 4: // EINTR
                        continue;
                    case 105: // ENOBUFS: the kernel dropped events; the sweep will catch up.
                        Interlocked.Increment(ref _dropped);
                        continue;
                    default:
                        if (!_stopping)
                        {
                            _log($"process events: receive failed (errno {errno}); falling back to polling");
                        }

                        IsRunning = false;
                        UnavailableReason = $"receive failed with errno {errno}";
                        return;
                }
            }

            foreach (var evt in Parse(buffer.AsSpan(0, (int)received)))
            {
                if (evt.Kind == ProcessEventKind.Fork && OnForkFastPath is { } fast)
                {
                    try
                    {
                        fast(evt.Pid, evt.ChildPid);
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        // The child exited already, or is not ours to move.
                    }
                }

                _events.Writer.TryWrite(evt);
            }
        }
    }

    /// <summary>
    /// Walks one netlink datagram, which may carry several messages, and yields the process
    /// events in it. Public and pure so the wire layout can be unit-tested without root.
    /// </summary>
    public static IReadOnlyList<ProcessEvent> Parse(ReadOnlySpan<byte> datagram)
    {
        var events = new List<ProcessEvent>(4);
        var offset = 0;
        while (offset + 16 <= datagram.Length)
        {
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(datagram[offset..]);
            var type = BinaryPrimitives.ReadUInt16LittleEndian(datagram[(offset + 4)..]);
            if (length < 16 || offset + length > datagram.Length)
            {
                break;
            }

            // Only NLMSG_DONE carries connector payloads; NOOP/ERROR/OVERRUN are skipped.
            // nlmsghdr(16) + cn_msg(20) puts proc_event at +36:
            //   __u32 what; __u32 cpu; __u64 timestamp_ns; union event_data at +16 (=> +52)
            if (type == NlmsgDone && length >= 52)
            {
                var what = BinaryPrimitives.ReadUInt32LittleEndian(datagram[(offset + 36)..]);
                var data = datagram[(offset + 52)..(offset + length)];
                switch (what)
                {
                    case ProcEventFork when data.Length >= 16:
                    {
                        var parentTgid = BinaryPrimitives.ReadInt32LittleEndian(data[4..]);
                        var childPid = BinaryPrimitives.ReadInt32LittleEndian(data[8..]);
                        var childTgid = BinaryPrimitives.ReadInt32LittleEndian(data[12..]);
                        // A new thread reports child_pid != child_tgid; only new processes matter.
                        if (childPid == childTgid && childTgid != parentTgid)
                        {
                            events.Add(new ProcessEvent(ProcessEventKind.Fork, parentTgid, childTgid, 0));
                        }

                        break;
                    }

                    case ProcEventExec when data.Length >= 8:
                    {
                        var tgid = BinaryPrimitives.ReadInt32LittleEndian(data[4..]);
                        events.Add(new ProcessEvent(ProcessEventKind.Exec, tgid, 0, 0));
                        break;
                    }

                    case ProcEventExit when data.Length >= 12:
                    {
                        var pid = BinaryPrimitives.ReadInt32LittleEndian(data);
                        var tgid = BinaryPrimitives.ReadInt32LittleEndian(data[4..]);
                        var code = BinaryPrimitives.ReadInt32LittleEndian(data[8..]);
                        // The thread-group leader's exit is the process's exit.
                        if (pid == tgid)
                        {
                            events.Add(new ProcessEvent(ProcessEventKind.Exit, tgid, 0, code));
                        }

                        break;
                    }
                }
            }

            offset += (length + 3) & ~3; // NLMSG_ALIGN
        }

        return events;
    }

    public void Dispose()
    {
        _stopping = true;
        if (_fd >= 0)
        {
            Subscribe(_fd, ProcCnMcastIgnore);
            shutdown(_fd, 2 /* SHUT_RDWR */);
            close(_fd);
            _fd = -1;
        }

        _thread?.Join(TimeSpan.FromSeconds(2));
        _events.Writer.TryComplete();
        IsRunning = false;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern int bind(int fd, byte[] address, int length);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int option, byte[] value, int length);

    [DllImport("libc", SetLastError = true)]
    private static extern nint send(int fd, byte[] buffer, nuint length, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern nint recv(int fd, byte[] buffer, nuint length, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int shutdown(int fd, int how);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);
}
