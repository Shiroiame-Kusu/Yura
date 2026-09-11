using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Tests;

/// <summary>
/// The <c>SOCK_DESTROY</c> request, byte for byte.
/// </summary>
/// <remarks>
/// This is the message that makes a rule reach a connection older than itself, and it is a
/// raw kernel structure: one field at the wrong offset means the kernel either refuses it or,
/// worse, matches a different socket. Asserting the layout here is cheaper than discovering
/// that against a live kernel, and it documents where each field came from.
///
/// Offsets are from <c>linux/netlink.h</c> and <c>linux/inet_diag.h</c>:
/// <c>nlmsghdr</c> is 16 bytes, then <c>inet_diag_req_v2</c> (8 bytes of header and a
/// 48-byte <c>inet_diag_sockid</c>).
/// </remarks>
public sealed class SocketResetTests
{
    private const int Header = 16;
    private const int Body = Header + 8;

    private static byte[] Tcp(string local, string remote) =>
        SocketReset.BuildDestroyRequest(7, new ResetTarget(
            ProtocolType.Tcp, IPEndPoint.Parse(local), IPEndPoint.Parse(remote)));

    [Fact]
    public void The_message_is_the_size_the_kernel_expects_and_says_so()
    {
        var message = Tcp("192.168.1.24:54321", "104.18.32.7:443");

        Assert.Equal(72, message.Length);
        Assert.Equal(72u, BinaryPrimitives.ReadUInt32LittleEndian(message));
    }

    [Fact]
    public void It_is_a_SOCK_DESTROY_request_that_asks_for_an_acknowledgement()
    {
        var message = Tcp("192.168.1.24:54321", "104.18.32.7:443");

        Assert.Equal(21, BinaryPrimitives.ReadUInt16LittleEndian(message.AsSpan(4)));      // SOCK_DESTROY
        Assert.Equal(0x05, BinaryPrimitives.ReadUInt16LittleEndian(message.AsSpan(6)));    // REQUEST | ACK
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(8)));      // our sequence
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(12)));     // to the kernel
    }

    [Fact]
    public void An_IPv4_TCP_socket_carries_its_family_protocol_and_both_ends()
    {
        var message = Tcp("192.168.1.24:54321", "104.18.32.7:443");

        Assert.Equal(2, message[Body - 8]);      // AF_INET
        Assert.Equal(6, message[Body - 7]);      // IPPROTO_TCP
        Assert.Equal(0, message[Body - 6]);      // no extensions
        Assert.Equal(uint.MaxValue, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Body - 4)));

        // Ports are network order; the source is the application's, which is what identifies
        // the socket together with the destination.
        Assert.Equal(54321, BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(Body)));
        Assert.Equal(443, BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(Body + 2)));

        Assert.Equal(new byte[] { 192, 168, 1, 24 }, message[(Body + 4)..(Body + 8)]);
        Assert.Equal(new byte[] { 104, 18, 32, 7 }, message[(Body + 20)..(Body + 24)]);

        // The three unused words of each 16-byte address field stay zero for IPv4.
        Assert.All(message[(Body + 8)..(Body + 20)], b => Assert.Equal(0, b));
        Assert.All(message[(Body + 24)..(Body + 36)], b => Assert.Equal(0, b));
    }

    [Fact]
    public void The_socket_is_looked_up_by_its_addresses_rather_than_a_cookie()
    {
        var message = Tcp("192.168.1.24:54321", "104.18.32.7:443");

        // INET_DIAG_NOCOOKIE in both words. We never dumped the socket, so we have no cookie
        // to quote; the 4-tuple identifies it.
        Assert.Equal(uint.MaxValue, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Body + 40)));
        Assert.Equal(uint.MaxValue, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Body + 44)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(Body + 36))); // any interface
    }

    [Fact]
    public void A_UDP_socket_asks_for_the_UDP_protocol()
    {
        var message = SocketReset.BuildDestroyRequest(1, new ResetTarget(
            ProtocolType.Udp, IPEndPoint.Parse("192.168.1.24:5000"), IPEndPoint.Parse("8.8.8.8:53")));

        Assert.Equal(17, message[Body - 7]); // IPPROTO_UDP
    }

    [Fact]
    public void An_IPv6_socket_carries_the_whole_address()
    {
        var message = SocketReset.BuildDestroyRequest(1, new ResetTarget(
            ProtocolType.Tcp,
            new IPEndPoint(IPAddress.Parse("2001:db8::1"), 40000),
            new IPEndPoint(IPAddress.Parse("2606:4700::6810:2007"), 443)));

        Assert.Equal(10, message[Body - 8]); // AF_INET6
        Assert.Equal(
            IPAddress.Parse("2001:db8::1").GetAddressBytes(),
            message[(Body + 4)..(Body + 20)]);
        Assert.Equal(
            IPAddress.Parse("2606:4700::6810:2007").GetAddressBytes(),
            message[(Body + 20)..(Body + 36)]);
    }

    // -- reading the kernel's answer -------------------------------------------

    private static byte[] Ack(int errno)
    {
        var reply = new byte[20];
        BinaryPrimitives.WriteUInt32LittleEndian(reply, 20);
        BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(4), 2); // NLMSG_ERROR
        BinaryPrimitives.WriteInt32LittleEndian(reply.AsSpan(16), -errno);
        return reply;
    }

    [Fact]
    public void An_acknowledgement_with_no_error_means_the_socket_was_aborted()
    {
        Assert.Equal(0, SocketReset.ReadError(Ack(0)));
    }

    [Fact]
    public void A_refusal_is_reported_as_the_errno_the_kernel_sent()
    {
        Assert.Equal(95, SocketReset.ReadError(Ack(95)));  // EOPNOTSUPP: no CONFIG_INET_DIAG_DESTROY
        Assert.Equal(1, SocketReset.ReadError(Ack(1)));    // EPERM: no CAP_NET_ADMIN
        Assert.Equal(2, SocketReset.ReadError(Ack(2)));    // ENOENT: the socket had already gone
    }

    [Fact]
    public void An_answer_too_short_to_read_is_not_taken_for_success()
    {
        Assert.NotEqual(0, SocketReset.ReadError([1, 2, 3]));
    }
}
