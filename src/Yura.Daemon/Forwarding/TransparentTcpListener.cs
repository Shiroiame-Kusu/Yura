using System.Net;
using System.Net.Sockets;
using Yura.Core.Proxies;
using Yura.Core.Rules;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Accepts the TCP flows TPROXY redirects to one slot and tunnels each through that
/// slot's proxy.
/// </summary>
/// <remarks>
/// One listener per Proxy slot, on that slot's port. Because TPROXY delivers a flow to the
/// listener bound to the port the classifier chose, arriving here already tells us which
/// rule — and which proxy — the flow belongs to. There is no per-connection lookup.
///
/// The accepted socket's <see cref="Socket.LocalEndPoint"/> is the application's original
/// destination, not our listening address. That is the property TPROXY plus
/// <c>IP_TRANSPARENT</c> provides, and it was verified by the routing spike.
/// </remarks>
public sealed class TransparentTcpListener : IAsyncDisposable
{
    private readonly RuleSlot _slot;
    private readonly ProxyEndpoint _proxy;
    private readonly string? _password;
    private readonly FlowRegistry _flows;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _stopping = new();
    private Socket? _listener;
    private Task? _acceptLoop;

    public TransparentTcpListener(
        RuleSlot slot, ProxyEndpoint proxy, string? password, FlowRegistry flows, Action<string> log)
    {
        _slot = slot;
        _proxy = proxy;
        _password = password;
        _flows = flows;
        _log = log;
    }

    public int Port => _slot.Port;

    /// <summary>The proxy this listener tunnels through. Lets the runtime spot a changed rule.</summary>
    public Guid ProxyId => _proxy.Id;

    public void Start()
    {
        var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.SetTransparent();
        listener.Bind(new IPEndPoint(IPAddress.Any, _slot.Port));
        listener.Listen(256);
        _listener = listener;
        _acceptLoop = AcceptLoopAsync(listener, _stopping.Token);
        _log($"slot {_slot.Name}: tcp listener on :{_slot.Port} -> {_proxy}");
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException)
            {
                break;
            }

            _ = HandleAsync(client, ct);
        }
    }

    private async Task HandleAsync(Socket client, CancellationToken ct)
    {
        var original = (IPEndPoint)client.LocalEndPoint!;
        var peer = (IPEndPoint)client.RemoteEndPoint!;
        var flow = new Flow(peer, original, TransportProtocol.Tcp, _slot.Rule.Id, _proxy.Name);
        _flows.Add(flow);

        Socket? upstream = null;
        try
        {
            upstream = await DialProxyAsync(ct).ConfigureAwait(false);
            await ProxyClients.TunnelAsync(upstream, _proxy, _password, original, ct).ConfigureAwait(false);
            flow.MarkEstablished();
            await FlowPump.RunAsync(client, upstream, flow, ct).ConfigureAwait(false);
            flow.MarkClosed();
        }
        catch (ProxyHandshakeException e)
        {
            flow.MarkFailed(e.Message);
            _log($"slot {_slot.Name}: {peer} -> {original} failed at proxy: {e.Message}");
        }
        catch (SocketException e)
        {
            flow.MarkFailed($"Could not reach the proxy: {e.Message}");
            _log($"slot {_slot.Name}: {peer} -> {original}: cannot reach proxy {_proxy.Authority}: {e.SocketErrorCode}");
        }
        catch (OperationCanceledException)
        {
            flow.MarkClosed();
        }
        finally
        {
            client.Dispose();
            upstream?.Dispose();
        }
    }

    private async Task<Socket> DialProxyAsync(CancellationToken ct)
    {
        IPAddress address;
        if (!IPAddress.TryParse(_proxy.Host, out address!))
        {
            var addresses = await Dns.GetHostAddressesAsync(_proxy.Host, ct).ConfigureAwait(false);
            address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                      ?? addresses.FirstOrDefault()
                      ?? throw new SocketException((int)SocketError.HostNotFound);
        }

        var upstream = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        // The bypass mark is what stops the classifier from capturing this very socket and
        // feeding the forwarder back into itself.
        upstream.SetMark(PolicyRouting.BypassMark);
        upstream.NoDelay = true;
        await upstream.ConnectAsync(new IPEndPoint(address, _proxy.Port), ct).ConfigureAwait(false);
        return upstream;
    }

    public async ValueTask DisposeAsync()
    {
        _stopping.Cancel();
        _listener?.Dispose();
        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The loop is being torn down; its last error is not interesting.
            }
        }

        _stopping.Dispose();
    }
}
