using System.Net;
using System.Net.Sockets;
using Yura.Core.Connections;
using Yura.Core.Rules;
using Yura.Daemon.Runtime;

namespace Yura.Daemon.Forwarding;

/// <summary>
/// Accepts the TCP flows TPROXY redirects to one slot and carries out the per-flow decision.
/// </summary>
/// <remarks>
/// One listener per Capture slot, on that slot's port. Because TPROXY delivers a flow to the
/// listener bound to the port the classifier chose, arriving here already tells us which
/// rule first claimed the flow. The runtime then evaluates the ordered list for this flow,
/// with the destination name if one can be learned, and the listener does what it says:
/// tunnel through a proxy or chain, relay directly, or refuse.
///
/// The accepted socket's <see cref="Socket.LocalEndPoint"/> is the application's original
/// destination, not our listening address. That is the property TPROXY plus
/// <c>IP_TRANSPARENT</c> provides, and it was verified by the routing spike.
/// </remarks>
public sealed class TransparentTcpListener : IAsyncDisposable
{
    private static readonly TimeSpan SniffWindow = TimeSpan.FromMilliseconds(300);

    private readonly RuleSlot _slot;
    private readonly int _port;
    private readonly IRouteDecider _decider;
    private readonly FlowRegistry _flows;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _stopping = new();
    private Socket? _listener;
    private Task? _acceptLoop;

    public TransparentTcpListener(RuleSlot slot, int port, IRouteDecider decider, FlowRegistry flows, Action<string> log)
    {
        _slot = slot;
        _port = port;
        _decider = decider;
        _flows = flows;
        _log = log;
    }

    public void Start()
    {
        var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.SetTransparent();
        listener.Bind(new IPEndPoint(IPAddress.Any, _port));
        listener.Listen(256);
        _listener = listener;
        _acceptLoop = AcceptLoopAsync(listener, _stopping.Token);
        _log($"slot {_slot.Name}: tcp listener on :{_port} for '{_slot.Rule.Name}'");
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
        var flow = new Flow(peer, original, TransportProtocol.Tcp, _slot.Rule.Id);
        _flows.Add(flow);

        UpstreamLeg? upstream = null;
        try
        {
            client.NoDelay = true;

            // Only look at the first bytes when a rule could use the name; the wait costs
            // server-speaks-first protocols a short delay and buys nothing otherwise.
            var host = _decider.SniffHosts
                ? await HostSniffer.PeekHostAsync(client, SniffWindow, ct).ConfigureAwait(false)
                : null;

            var plan = _decider.Decide(_slot, peer, original, TransportProtocol.Tcp, host);
            flow.Describe(plan);

            switch (plan.Kind)
            {
                case FlowPlanKind.Block:
                    flow.MarkBlocked();
                    Reset(client);
                    return;

                case FlowPlanKind.Fail:
                    flow.MarkFailed(plan.FailureReason ?? "The rule could not be carried out.");
                    _log($"slot {_slot.Name}: {peer} -> {original} refused: {plan.FailureReason}");
                    Reset(client);
                    return;

                case FlowPlanKind.Direct:
                    upstream = await ProxyDialer.OpenDirectAsync(original, ct).ConfigureAwait(false);
                    flow.MarkEstablished(RouteObservation.ConfirmedDirect);
                    break;

                default:
                    upstream = await ProxyDialer.OpenAsync(plan.Hops, original, ct).ConfigureAwait(false);
                    flow.MarkEstablished(RouteObservation.ConfirmedProxied);
                    break;
            }

            await FlowPump.RunAsync(client, upstream, flow, ct).ConfigureAwait(false);
            flow.MarkClosed();
        }
        catch (ProxyHandshakeException e)
        {
            flow.MarkFailed(e.Message);
            _log($"slot {_slot.Name}: {peer} -> {original} failed at proxy: {e.Message}");
            Reset(client);
        }
        catch (SocketException e)
        {
            var reason = flow.Route == RouteObservation.ConfirmedDirect || upstream is null && flow.ProxyName is null
                ? $"Could not reach {original}: {e.SocketErrorCode}"
                : $"Could not reach the proxy: {e.SocketErrorCode}";
            flow.MarkFailed(reason);
            _log($"slot {_slot.Name}: {peer} -> {original}: {reason}");
            Reset(client);
        }
        catch (OperationCanceledException)
        {
            flow.MarkClosed();
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            flow.MarkFailed(e.Message);
        }
        finally
        {
            client.Dispose();
            if (upstream is not null)
            {
                await upstream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Closes with a reset rather than a FIN, so a refused flow looks refused, not finished.</summary>
    private static void Reset(Socket client)
    {
        try
        {
            client.LingerState = new LingerOption(true, 0);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException)
        {
        }
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
