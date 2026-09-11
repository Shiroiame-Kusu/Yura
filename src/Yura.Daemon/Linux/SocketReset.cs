using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Yura.Daemon.Linux;

/// <summary>One socket to abort, identified the way the kernel identifies it.</summary>
public readonly record struct ResetTarget(ProtocolType Protocol, IPEndPoint Local, IPEndPoint Remote);

/// <summary>What came of asking the kernel to abort a set of sockets.</summary>
/// <param name="Reset">Sockets the kernel aborted.</param>
/// <param name="AlreadyGone">Sockets that had closed between listing them and asking.</param>
/// <param name="Failed">Sockets the kernel refused to abort.</param>
/// <param name="Failure">Why, when at least one was refused. Null when nothing was refused.</param>
public sealed record SocketResetOutcome(int Reset, int AlreadyGone, int Failed, string? Failure)
{
    public static readonly SocketResetOutcome Nothing = new(0, 0, 0, null);
}

/// <summary>
/// Aborts established sockets through <c>NETLINK_SOCK_DIAG</c>'s <c>SOCK_DESTROY</c>.
/// </summary>
/// <remarks>
/// This exists because of the one hard limit in the classifier: a socket's cgroup is fixed
/// when the socket is created, so a rule can never capture a connection that was already
/// open. Leaving those connections alone is what makes a freshly applied rule look like it
/// does nothing — the program keeps using the connection it already has. Aborting them is
/// the only way to make the rule take effect now: the application sees its connection fail,
/// reconnects, and the new socket is created inside the rule's cgroup.
///
/// This is exactly what <c>ss -K</c> does, and it needs <c>CONFIG_INET_DIAG_DESTROY</c> and
/// <c>CAP_NET_ADMIN</c>. Both are checked by trying, not by guessing: the kernel's error is
/// more accurate than any probe we could write, and it is reported rather than swallowed.
///
/// Only connected sockets are targets. An unconnected UDP socket has no connection to reset:
/// aborting it delivers an error the application never asked for and does not make it rebind,
/// so those are left alone by the callers that build the target list.
/// </remarks>
public sealed class SocketReset
{
    private const int AfNetlink = 16;
    private const int SockDgram = 2;
    private const int NetlinkSockDiag = 4;

    /// <summary>SOCK_DESTROY, from linux/sock_diag.h.</summary>
    private const ushort SockDestroy = 21;

    private const ushort NlmFRequest = 0x01;
    private const ushort NlmFAck = 0x04;
    private const ushort NlmsgError = 0x02;

    private const int NlMsgHeaderBytes = 16;
    private const int SockIdBytes = 48;
    private const int RequestBytes = NlMsgHeaderBytes + 8 + SockIdBytes;

    private const int AfInet = 2;
    private const int AfInet6 = 10;

    private readonly Action<string> _log;

    public SocketReset(Action<string> log) => _log = log;

    /// <summary>
    /// Asks the kernel to abort every target, and reports what happened to each.
    /// </summary>
    /// <remarks>
    /// One netlink socket is used for the whole batch, and each request is acknowledged before
    /// the next is sent. Requests are cheap; the ordering keeps one socket's error from being
    /// attributed to another, which matters because the count is shown to the user as fact.
    /// </remarks>
    public SocketResetOutcome Destroy(IReadOnlyCollection<ResetTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count == 0)
        {
            return SocketResetOutcome.Nothing;
        }

        var fd = socket(AfNetlink, SockDgram, NetlinkSockDiag);
        if (fd < 0)
        {
            var errno = Marshal.GetLastPInvokeError();
            return new SocketResetOutcome(0, 0, targets.Count,
                $"the kernel has no socket diagnostics interface (socket: errno {errno}); " +
                "connections already open keep their previous route");
        }

        try
        {
            var reset = 0;
            var gone = 0;
            var failed = 0;
            string? failure = null;
            var seq = 1u;
            var reply = new byte[256];

            foreach (var target in targets)
            {
                var request = BuildDestroyRequest(seq++, target);
                if (send(fd, request, (nuint)request.Length, 0) < 0)
                {
                    failed++;
                    failure ??= $"could not ask the kernel to abort the socket (send: errno {Marshal.GetLastPInvokeError()})";
                    continue;
                }

                var received = (int)recv(fd, reply, (nuint)reply.Length, 0);
                if (received < 0)
                {
                    failed++;
                    failure ??= $"the kernel did not answer (recv: errno {Marshal.GetLastPInvokeError()})";
                    continue;
                }

                switch (ReadError(reply.AsSpan(0, received)))
                {
                    case 0:
                        reset++;
                        break;

                    // The socket closed between the listing and the request. Nothing to do,
                    // and nothing to report: the connection the user wanted gone is gone.
                    case 2 or 107: // ENOENT, ENOTCONN
                        gone++;
                        break;

                    case var errno:
                        failed++;
                        failure ??= Explain(errno);
                        break;
                }
            }

            if (failure is not null)
            {
                _log($"socket reset: {failed} of {targets.Count} could not be aborted: {failure}");
            }

            return new SocketResetOutcome(reset, gone, failed, failure);
        }
        finally
        {
            close(fd);
        }
    }

    private static string Explain(int errno) => errno switch
    {
        1 => "the kernel refused (EPERM): aborting a socket needs CAP_NET_ADMIN",
        95 => "this kernel cannot abort sockets (EOPNOTSUPP): CONFIG_INET_DIAG_DESTROY is off",
        _ => $"the kernel refused with errno {errno}",
    };

    /// <summary>
    /// Builds one <c>SOCK_DESTROY</c> request.
    /// </summary>
    /// <remarks>
    /// Exposed so the byte layout can be asserted in a test rather than only against a live
    /// kernel. The shapes are <c>nlmsghdr</c>, <c>inet_diag_req_v2</c> and
    /// <c>inet_diag_sockid</c> from <c>linux/inet_diag.h</c>; ports and addresses are in
    /// network byte order, everything else in host order.
    /// </remarks>
    public static byte[] BuildDestroyRequest(uint sequence, ResetTarget target)
    {
        ArgumentNullException.ThrowIfNull(target.Local);
        ArgumentNullException.ThrowIfNull(target.Remote);

        var v6 = target.Local.AddressFamily == AddressFamily.InterNetworkV6;
        var message = new byte[RequestBytes];
        var span = message.AsSpan();

        // struct nlmsghdr
        BinaryPrimitives.WriteUInt32LittleEndian(span, RequestBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(span[4..], SockDestroy);
        BinaryPrimitives.WriteUInt16LittleEndian(span[6..], NlmFRequest | NlmFAck);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], sequence);
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], 0); // to the kernel

        // struct inet_diag_req_v2
        var body = span[NlMsgHeaderBytes..];
        body[0] = (byte)(v6 ? AfInet6 : AfInet);
        body[1] = (byte)(target.Protocol == ProtocolType.Udp ? 17 : 6); // IPPROTO_UDP / IPPROTO_TCP
        body[2] = 0; // no extensions wanted
        body[3] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(body[4..], uint.MaxValue); // any state

        // struct inet_diag_sockid
        var id = body[8..];
        BinaryPrimitives.WriteUInt16BigEndian(id, (ushort)target.Local.Port);
        BinaryPrimitives.WriteUInt16BigEndian(id[2..], (ushort)target.Remote.Port);
        WriteAddress(id[4..20], target.Local.Address, v6);
        WriteAddress(id[20..36], target.Remote.Address, v6);
        BinaryPrimitives.WriteUInt32LittleEndian(id[36..], 0); // no interface constraint

        // INET_DIAG_NOCOOKIE: look the socket up by its addresses, not by a cookie from a
        // previous dump. The 4-tuple is what we have, and it identifies the socket uniquely.
        BinaryPrimitives.WriteUInt32LittleEndian(id[40..], uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(id[44..], uint.MaxValue);

        return message;
    }

    private static void WriteAddress(Span<byte> destination, IPAddress address, bool v6)
    {
        destination.Clear();
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written))
        {
            return;
        }

        // An IPv4 address in an IPv6 request has to be sent the way the kernel stores it,
        // which is mapped into the first four words rather than as ::ffff:a.b.c.d.
        if (v6 && written == 4)
        {
            bytes[..4].CopyTo(destination);
            return;
        }

        bytes[..written].CopyTo(destination);
    }

    /// <summary>The errno from a netlink acknowledgement: 0 for success, positive for a refusal.</summary>
    public static int ReadError(ReadOnlySpan<byte> reply)
    {
        if (reply.Length < NlMsgHeaderBytes + 4)
        {
            return 71; // EPROTO: not an answer we can read
        }

        var type = BinaryPrimitives.ReadUInt16LittleEndian(reply[4..]);
        if (type != NlmsgError)
        {
            return 0; // Anything but an error message means the request was carried out.
        }

        return -BinaryPrimitives.ReadInt32LittleEndian(reply[NlMsgHeaderBytes..]);
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern nint send(int fd, byte[] buffer, nuint length, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern nint recv(int fd, byte[] buffer, nuint length, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);
}
