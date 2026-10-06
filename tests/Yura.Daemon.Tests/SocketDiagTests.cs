using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Tests;

/// <summary>
/// Finding one socket's inode through <c>NETLINK_SOCK_DIAG</c>, which is how a captured flow is
/// attributed to the process that opened it.
/// </summary>
/// <remarks>
/// It replaced reading <c>/proc/net/tcp</c> once per flow — the whole table, as text, for every
/// connection. The live tests below ask the running kernel about sockets this test owns; a
/// lookup needs no privilege, the same as <c>ss</c>.
/// </remarks>
public sealed class SocketDiagTests
{
    private const int Header = 16;
    private const int Id = Header + 8;

    // -- the request, byte for byte --------------------------------------------

    [Fact]
    public void A_TCP_lookup_names_the_sockets_own_address_as_the_source()
    {
        var message = SocketDiag.BuildLookupRequest(
            3, ProtocolType.Tcp, IPEndPoint.Parse("192.168.1.24:54321"), IPEndPoint.Parse("104.18.32.7:443"));

        Assert.Equal(72, message.Length);
        Assert.Equal(20, BinaryPrimitives.ReadUInt16LittleEndian(message.AsSpan(4)));
        Assert.Equal(2, message[Header]);
        Assert.Equal(6, message[Header + 1]);
        Assert.Equal(54321, BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(Id)));
        Assert.Equal(443, BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(Id + 2)));
        Assert.Equal(IPAddress.Parse("192.168.1.24"), new IPAddress(message.AsSpan(Id + 4, 4)));
        Assert.Equal(IPAddress.Parse("104.18.32.7"), new IPAddress(message.AsSpan(Id + 20, 4)));
    }

    [Fact]
    public void A_UDP_lookup_swaps_source_and_destination_the_way_the_kernel_expects()
    {
        // The kernel answers a UDP lookup by asking which socket a datagram from src to dst
        // would reach, so the socket's own address goes in dst.
        var message = SocketDiag.BuildLookupRequest(
            3, ProtocolType.Udp, IPEndPoint.Parse("192.168.1.24:54321"), IPEndPoint.Parse("1.1.1.1:53"));

        Assert.Equal(17, message[Header + 1]);
        Assert.Equal(53, BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(Id)));
        Assert.Equal(54321, BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(Id + 2)));
        Assert.Equal(IPAddress.Parse("1.1.1.1"), new IPAddress(message.AsSpan(Id + 4, 4)));
        Assert.Equal(IPAddress.Parse("192.168.1.24"), new IPAddress(message.AsSpan(Id + 20, 4)));
    }

    [Fact]
    public void A_listener_found_instead_of_the_connection_is_not_reported_as_it()
    {
        // A TCP lookup with no such connection falls back to a listener on the port; that is
        // somebody else's socket as far as the question was concerned.
        var reply = new byte[Header + 72];
        BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(4), 20);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(Header + 4), 8080);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(Header + 6), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(Header + 68), 4242);

        var read = SocketDiag.TryReadInode(
            reply, ProtocolType.Tcp, IPEndPoint.Parse("127.0.0.1:8080"), IPEndPoint.Parse("127.0.0.1:50000"), out var inode);

        Assert.True(read);
        Assert.Null(inode);
    }

    // -- the running kernel ----------------------------------------------------

    [Fact]
    public void Finds_a_TCP_connection_this_process_holds()
    {
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Connect(listener.LocalEndPoint!);
        using var accepted = listener.Accept();

        var found = Lookup(ProtocolType.Tcp, (IPEndPoint)client.LocalEndPoint!, (IPEndPoint)client.RemoteEndPoint!);

        Assert.Equal(InodeOf(client), found);
    }

    [Fact]
    public void Finds_a_dual_stack_socket_by_its_IPv4_addresses()
    {
        // How Java opens every connection, Minecraft's included: an IPv6 socket talking to an
        // IPv4 address. The text tables list it under tcp6 as ::ffff:a.b.c.d, where a search
        // of the IPv4 table never looked, so its traffic was attributed to no process.
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        using var client = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp) { DualMode = true };
        client.Connect(new IPEndPoint(IPAddress.Loopback.MapToIPv6(), ((IPEndPoint)listener.LocalEndPoint!).Port));
        using var accepted = listener.Accept();

        // What the daemon sees is the IPv4 packet: both ends as IPv4 addresses.
        var local = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)client.LocalEndPoint!).Port);
        var remote = (IPEndPoint)listener.LocalEndPoint!;

        Assert.Equal(InodeOf(client), Lookup(ProtocolType.Tcp, local, remote));
    }

    [Fact]
    public void Finds_a_UDP_socket_by_where_its_datagram_was_going()
    {
        using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sender.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        var found = Lookup(ProtocolType.Udp, (IPEndPoint)sender.LocalEndPoint!, (IPEndPoint)peer.LocalEndPoint!);

        Assert.Equal(InodeOf(sender), found);
    }

    [Fact]
    public void A_socket_that_does_not_exist_is_an_answer_of_none()
    {
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.LocalEndPoint!).Port;
        listener.Dispose();

        var asked = SocketDiag.TryFindInode(
            ProtocolType.Tcp, new IPEndPoint(IPAddress.Loopback, port), new IPEndPoint(IPAddress.Loopback, 9), out var inode);

        Assert.SkipUnless(asked, "socket diagnostics are not available here");
        Assert.Null(inode);
    }

    private static long? Lookup(ProtocolType protocol, IPEndPoint local, IPEndPoint remote)
    {
        var asked = SocketDiag.TryFindInode(protocol, local, remote, out var inode);
        Assert.SkipUnless(asked, "socket diagnostics are not available here");
        return inode;
    }

    /// <summary>The inode the kernel shows for one of this process's sockets.</summary>
    private static long InodeOf(Socket socket)
    {
        var target = new FileInfo($"/proc/self/fd/{socket.Handle}").LinkTarget
                     ?? throw new InvalidOperationException("the socket's descriptor has no link");
        // "socket:[12345]"
        return long.Parse(target.AsSpan()[8..^1], System.Globalization.CultureInfo.InvariantCulture);
    }
}
