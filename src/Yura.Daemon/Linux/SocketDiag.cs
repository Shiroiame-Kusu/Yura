using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Yura.Daemon.Linux;

/// <summary>
/// Looks one socket up by its addresses through <c>NETLINK_SOCK_DIAG</c>, the way <c>ss</c> does.
/// </summary>
/// <remarks>
/// <para>
/// The alternative, reading <c>/proc/net/tcp</c>, makes the kernel print every socket on the
/// machine as text for the sake of one of them, and attributing a captured flow did that once
/// per flow — a browser opening connections by the hundred on a busy machine paid for a full
/// table each time. Asked directly, the kernel finds the socket in its own hash tables.
/// </para>
/// <para>
/// It also finds what the text tables file under a different name. A dual-stack IPv6 socket
/// talking to an IPv4 address — how Java opens every connection, Minecraft included — is
/// listed in <c>/proc/net/tcp6</c> as <c>::ffff:a.b.c.d</c>, but the kernel hashes it with
/// its IPv4 addresses, and an IPv4 lookup finds it.
/// </para>
/// </remarks>
public static class SocketDiag
{
    private const int AfNetlink = 16;
    private const int SockDgram = 2;
    private const int NetlinkSockDiag = 4;
    private const int AfInet = 2;
    private const int AfInet6 = 10;

    /// <summary>SOCK_DIAG_BY_FAMILY, from linux/sock_diag.h.</summary>
    private const ushort SockDiagByFamily = 20;

    private const ushort NlmFRequest = 0x01;
    private const ushort NlmsgError = 0x02;

    private const int NlMsgHeaderBytes = 16;
    private const int RequestBytes = NlMsgHeaderBytes + 8 + 48;

    /// <summary>Where <c>idiag_inode</c> sits in a reply: after the header and 68 bytes of <c>inet_diag_msg</c>.</summary>
    private const int InodeOffset = NlMsgHeaderBytes + 68;

    /// <summary>
    /// The inode of the socket with these addresses.
    /// </summary>
    /// <param name="local">The socket's own address and port.</param>
    /// <param name="remote">The peer it talks to. For an unconnected UDP socket, where the datagram was going.</param>
    /// <param name="inode">The inode, or null when the kernel holds no such socket.</param>
    /// <returns>
    /// False when the question could not be asked at all — no socket diagnostics in this kernel,
    /// say — in which case the caller has to find the socket another way.
    /// </returns>
    public static bool TryFindInode(ProtocolType protocol, IPEndPoint local, IPEndPoint remote, out long? inode)
    {
        inode = null;
        if (local.AddressFamily != remote.AddressFamily)
        {
            return false;
        }

        var fd = socket(AfNetlink, SockDgram, NetlinkSockDiag);
        if (fd < 0)
        {
            return false;
        }

        try
        {
            var request = BuildLookupRequest(1, protocol, local, remote);
            if (send(fd, request, (nuint)request.Length, 0) != request.Length)
            {
                return false;
            }

            var reply = new byte[512];
            var received = (int)recv(fd, reply, (nuint)reply.Length, 0);
            if (received < NlMsgHeaderBytes)
            {
                return false;
            }

            return TryReadInode(reply.AsSpan(0, received), protocol, local, remote, out inode);
        }
        finally
        {
            close(fd);
        }
    }

    /// <summary>
    /// Builds one lookup request: <c>nlmsghdr</c>, <c>inet_diag_req_v2</c>, <c>inet_diag_sockid</c>.
    /// </summary>
    /// <remarks>
    /// Public so the byte layout can be pinned in a test. TCP names the socket's own address as
    /// the source. UDP names it as the destination: the kernel answers a UDP lookup by asking
    /// which socket a datagram from <c>src</c> to <c>dst</c> would reach, "swapped for historical
    /// reasons" in its own words.
    /// </remarks>
    public static byte[] BuildLookupRequest(uint sequence, ProtocolType protocol, IPEndPoint local, IPEndPoint remote)
    {
        var v6 = local.AddressFamily == AddressFamily.InterNetworkV6;
        var udp = protocol == ProtocolType.Udp;
        var (source, destination) = udp ? (remote, local) : (local, remote);

        var message = new byte[RequestBytes];
        var span = message.AsSpan();

        BinaryPrimitives.WriteUInt32LittleEndian(span, RequestBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(span[4..], SockDiagByFamily);
        BinaryPrimitives.WriteUInt16LittleEndian(span[6..], NlmFRequest);
        BinaryPrimitives.WriteUInt32LittleEndian(span[8..], sequence);
        BinaryPrimitives.WriteUInt32LittleEndian(span[12..], 0);

        var body = span[NlMsgHeaderBytes..];
        body[0] = (byte)(v6 ? AfInet6 : AfInet);
        body[1] = (byte)(udp ? 17 : 6);
        body[2] = 0;
        body[3] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(body[4..], uint.MaxValue);

        var id = body[8..];
        BinaryPrimitives.WriteUInt16BigEndian(id, (ushort)source.Port);
        BinaryPrimitives.WriteUInt16BigEndian(id[2..], (ushort)destination.Port);
        WriteAddress(id[4..20], source.Address);
        WriteAddress(id[20..36], destination.Address);
        BinaryPrimitives.WriteUInt32LittleEndian(id[36..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(id[40..], uint.MaxValue); // INET_DIAG_NOCOOKIE
        BinaryPrimitives.WriteUInt32LittleEndian(id[44..], uint.MaxValue);
        return message;
    }

    /// <summary>
    /// Reads the inode out of a reply, checking it is the socket that was asked about.
    /// </summary>
    /// <remarks>
    /// A TCP lookup that finds no connection falls back to a listener on the same port, and a
    /// UDP lookup can land on a socket bound to the port more widely than asked. Only the local
    /// port is certain to match what was asked, and for TCP the peer's too; anything else is
    /// reported as not found rather than as somebody else's socket.
    /// </remarks>
    /// <returns>False when the reply is not one this code can read.</returns>
    public static bool TryReadInode(
        ReadOnlySpan<byte> reply, ProtocolType protocol, IPEndPoint local, IPEndPoint remote, out long? inode)
    {
        inode = null;
        if (reply.Length < NlMsgHeaderBytes)
        {
            return false;
        }

        var type = BinaryPrimitives.ReadUInt16LittleEndian(reply[4..]);
        if (type == NlmsgError)
        {
            // ENOENT is an answer — there is no such socket — and anything else is not.
            return reply.Length >= NlMsgHeaderBytes + 4 &&
                   -BinaryPrimitives.ReadInt32LittleEndian(reply[NlMsgHeaderBytes..]) == 2;
        }

        if (type != SockDiagByFamily || reply.Length < InodeOffset + 4)
        {
            return false;
        }

        var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(reply[(NlMsgHeaderBytes + 4)..]);
        var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(reply[(NlMsgHeaderBytes + 6)..]);

        // The reply always names the socket's own address as the source, whatever the request did.
        var matches = sourcePort == local.Port &&
                      (protocol != ProtocolType.Tcp || destinationPort == remote.Port);
        if (matches)
        {
            inode = BinaryPrimitives.ReadUInt32LittleEndian(reply[InodeOffset..]);
        }

        return true;
    }

    private static void WriteAddress(Span<byte> destination, IPAddress address)
    {
        destination.Clear();
        Span<byte> bytes = stackalloc byte[16];
        if (address.TryWriteBytes(bytes, out var written))
        {
            bytes[..written].CopyTo(destination);
        }
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
