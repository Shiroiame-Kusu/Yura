using System.Net;
using System.Net.Sockets;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// The TCP and UDP transparent listeners for one slot, on one shared port.
/// </summary>
/// <remarks>
/// Both transports must share a port because the nftables rule sends them to the same
/// <c>tproxy ip to :port</c>. The port is asked of the kernel rather than chosen, because
/// <c>ip_local_port_range</c> routinely covers any range we might reserve and an unrelated
/// outgoing connection can already hold it. TCP is bound first and UDP is then bound to the
/// port TCP was given; if that exact UDP port is taken the pair is retried, because half a
/// pair would silently drop one transport.
/// </remarks>
public sealed class SlotListener : IAsyncDisposable
{
    private const int BindAttempts = 16;

    private SlotListener(int port, TransparentTcpListener tcp, TransparentUdpListener udp)
    {
        Port = port;
        Tcp = tcp;
        Udp = udp;
    }

    public int Port { get; }

    public TransparentTcpListener Tcp { get; }

    public TransparentUdpListener Udp { get; }

    /// <summary>
    /// Binds both transports on one kernel-assigned port.
    /// </summary>
    /// <exception cref="SocketException">
    /// Thrown only when no port could be found for both transports, which means the machine is
    /// out of ports rather than that this rule is wrong.
    /// </exception>
    public static SlotListener Start(RuleSlot slot, IRouteDecider decider, FlowRegistry flows, Action<string> log)
    {
        SocketException? last = null;

        for (var attempt = 0; attempt < BindAttempts; attempt++)
        {
            // Port 0 lets the kernel pick one it knows is free for TCP.
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            probe.Bind(new IPEndPoint(IPAddress.Any, 0));
            var port = ((IPEndPoint)probe.LocalEndPoint!).Port;
            probe.Close();

            TransparentTcpListener? tcp = null;
            TransparentUdpListener? udp = null;
            try
            {
                tcp = new TransparentTcpListener(slot, port, decider, flows, log);
                tcp.Start();
                udp = new TransparentUdpListener(slot, port, decider, flows, log);
                udp.Start();
                return new SlotListener(port, tcp, udp);
            }
            catch (SocketException e)
            {
                last = e;
                tcp?.DisposeAsync().AsTask().GetAwaiter().GetResult();
                udp?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        throw last ?? new SocketException((int)SocketError.AddressAlreadyInUse);
    }

    public async ValueTask DisposeAsync()
    {
        await Tcp.DisposeAsync().ConfigureAwait(false);
        await Udp.DisposeAsync().ConfigureAwait(false);
    }
}
