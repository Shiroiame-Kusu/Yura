using System.Net;
using System.Net.Sockets;
using System.Text;
using Yura.Core.Agent;

namespace Yura.Agent.Tests;

/// <summary>
/// A real agent, on a real port, with a real key.
/// </summary>
/// <remarks>
/// Nothing here is mocked. The agent's whole job is to be on the other side of a socket, and
/// a test that replaces the socket would only prove the test's own idea of the protocol. The
/// policy is opened up to loopback because that is where a test's destinations are — which is
/// itself worth stating, since it is refused by default.
/// </remarks>
internal sealed class AgentHarness : IAsyncDisposable
{
    private readonly string _state;

    private AgentHarness(string state, AgentServer server, AgentIdentity identity)
    {
        _state = state;
        Server = server;
        Identity = identity;
    }

    public AgentServer Server { get; }

    public AgentIdentity Identity { get; }

    public List<string> Log { get; } = [];

    /// <summary>The ports these tests give full-cone channels, away from a real agent's default.</summary>
    public static readonly Core.Net.PortRange TestConePorts = new(47000, 47999);

    public static AgentHarness Start(
        bool udp = true, DestinationPolicy? policy = null, bool fullCone = true, Core.Net.PortRange? conePorts = null)
    {
        var state = Path.Combine(Path.GetTempPath(), "yura-agent-test-" + Guid.NewGuid().ToString("N"));
        var identity = AgentIdentity.LoadOrCreate(state, "test-agent");
        AgentHarness? harness = null;
        var server = new AgentServer(
            new AgentOptions
            {
                Listen = IPAddress.Loopback,
                Port = 0,
                Udp = udp,
                // Every destination in these tests is on loopback, which the default policy
                // refuses on purpose.
                Policy = policy ?? new DestinationPolicy { AllowPrivate = true },
                FullCone = fullCone,
                ConePorts = conePorts ?? TestConePorts,
            },
            identity,
            message => harness?.Log.Add(message));

        harness = new AgentHarness(state, server, identity);
        server.Start();
        return harness;
    }

    /// <summary>Client options that will connect: right address, right token, right key.</summary>
    public AgentClientOptions Client() => new()
    {
        Host = IPAddress.Loopback.ToString(),
        Port = Server.Port,
        Token = AgentConnection.Encode(Identity.Token),
        Fingerprint = Identity.Fingerprint,
        Label = "test",
        Timeout = TimeSpan.FromSeconds(5),
    };

    public Task<AgentSession> SessionAsync(CancellationToken ct) => AgentSession.ConnectAsync(Client(), ct);

    public async ValueTask DisposeAsync()
    {
        await Server.DisposeAsync().ConfigureAwait(false);
        try
        {
            Directory.Delete(_state, recursive: true);
        }
        catch (Exception e) when (e is DirectoryNotFoundException or IOException)
        {
        }
    }
}

/// <summary>A TCP server that sends back whatever it is sent, on loopback.</summary>
internal sealed class EchoServer : IDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _stopping = new();

    public EchoServer(string? greeting = null)
    {
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(8);
        EndPoint = (IPEndPoint)_listener.LocalEndPoint!;
        _ = AcceptAsync(greeting, _stopping.Token);
    }

    public IPEndPoint EndPoint { get; }

    /// <summary>Set when a connection read end-of-stream, which is how a half close is observed.</summary>
    public TaskCompletionSource SawEndOfStream { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private async Task AcceptAsync(string? greeting, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            _ = ServeAsync(client, greeting, ct);
        }
    }

    private async Task ServeAsync(Socket client, string? greeting, CancellationToken ct)
    {
        using (client)
        {
            var buffer = new byte[4096];
            if (greeting is not null)
            {
                await client.SendAsync(Encoding.UTF8.GetBytes(greeting), ct).ConfigureAwait(false);
            }

            while (!ct.IsCancellationRequested)
            {
                int read;
                try
                {
                    read = await client.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
                {
                    return;
                }

                if (read == 0)
                {
                    SawEndOfStream.TrySetResult();
                    // Answer after the half close, which is the point of allowing one.
                    try
                    {
                        await client.SendAsync(Encoding.UTF8.GetBytes("bye"), ct).ConfigureAwait(false);
                        client.Shutdown(SocketShutdown.Send);
                    }
                    catch (Exception e) when (e is SocketException or ObjectDisposedException)
                    {
                    }

                    return;
                }

                try
                {
                    await client.SendAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException)
                {
                    return;
                }
            }
        }
    }

    public void Dispose()
    {
        _stopping.Cancel();
        _listener.Dispose();
        _stopping.Dispose();
    }
}

/// <summary>A UDP server that echoes, and remembers who sent what.</summary>
internal sealed class UdpEchoServer : IDisposable
{
    private readonly Socket _socket;
    private readonly CancellationTokenSource _stopping = new();

    public UdpEchoServer()
    {
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        EndPoint = (IPEndPoint)_socket.LocalEndPoint!;
        _ = ReceiveAsync(_stopping.Token);
    }

    public IPEndPoint EndPoint { get; }

    /// <summary>Every datagram received, with the address it came from.</summary>
    public List<(IPEndPoint From, string Text)> Received { get; } = [];

    private async Task ReceiveAsync(CancellationToken ct)
    {
        var buffer = new byte[2048];
        var from = new IPEndPoint(IPAddress.Any, 0);
        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, from, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException or OperationCanceledException)
            {
                return;
            }

            lock (Received)
            {
                Received.Add(((IPEndPoint)result.RemoteEndPoint,
                    Encoding.UTF8.GetString(buffer, 0, result.ReceivedBytes)));
            }

            try
            {
                await _socket.SendToAsync(buffer.AsMemory(0, result.ReceivedBytes), SocketFlags.None,
                    result.RemoteEndPoint, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException)
            {
                return;
            }
        }
    }

    public IReadOnlyList<(IPEndPoint From, string Text)> Snapshot()
    {
        lock (Received)
        {
            return Received.ToArray();
        }
    }

    public void Dispose()
    {
        _stopping.Cancel();
        _socket.Dispose();
        _stopping.Dispose();
    }
}

/// <summary>
/// A destination that answers once and closes, the way an HTTP server with
/// <c>Connection: close</c> does — which is also what the acceptance suite's marker does.
/// </summary>
internal sealed class OneShotServer : IDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _stopping = new();

    public OneShotServer(string reply)
    {
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(8);
        EndPoint = (IPEndPoint)_listener.LocalEndPoint!;
        _ = AcceptAsync(reply, _stopping.Token);
    }

    public IPEndPoint EndPoint { get; }

    private async Task AcceptAsync(string reply, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket client;
            try { client = await _listener.AcceptAsync(ct).ConfigureAwait(false); }
            catch { return; }

            _ = Task.Run(async () =>
            {
                using (client)
                {
                    var buffer = new byte[4096];
                    try
                    {
                        await client.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                        await client.SendAsync(Encoding.UTF8.GetBytes(reply), ct).ConfigureAwait(false);
                        client.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    {
                    }
                }
            }, ct);
        }
    }

    public void Dispose()
    {
        _stopping.Cancel();
        _listener.Dispose();
        _stopping.Dispose();
    }
}
