using System.Net.Sockets;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// The handful of Linux socket options .NET does not name.
/// </summary>
/// <remarks>
/// Values are from the Linux UAPI headers and are stable across architectures for the
/// options used here. They are applied through <see cref="Socket.SetRawSocketOption"/>,
/// which is the supported escape hatch and needs no P/Invoke.
/// </remarks>
internal static class LinuxSocketOptions
{
    private const int SolSocket = 1;
    private const int SolIp = 0;
    private const int SolIpv6 = 41;

    private const int SoMark = 36;
    private const int IpTransparent = 19;
    private const int Ipv6Transparent = 75;

    /// <summary>
    /// Lets a socket bind to, and accept for, addresses that are not local. This is what
    /// turns a plain listener into a TPROXY target, and it is why the accepted socket's
    /// local address is the client's original destination rather than ours.
    /// </summary>
    public static void SetTransparent(this Socket socket)
    {
        var one = BitConverter.GetBytes(1);
        socket.SetRawSocketOption(SolIp, IpTransparent, one);
        if (socket.AddressFamily == AddressFamily.InterNetworkV6)
        {
            socket.SetRawSocketOption(SolIpv6, Ipv6Transparent, one);
        }
    }

    /// <summary>
    /// Stamps every packet the socket sends with an fwmark. Applied to the daemon's own
    /// upstream sockets so the classifier can recognise and skip them.
    /// </summary>
    public static void SetMark(this Socket socket, uint mark) =>
        socket.SetRawSocketOption(SolSocket, SoMark, BitConverter.GetBytes(mark));
}
