using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Yura.App.Services;
using Yura.Core.Ipc;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// The app's socket client against a stand-in daemon on a real Unix socket: what it concludes
/// about the daemon from the answers it gets, and from the ones it does not.
/// </summary>
public sealed class DaemonClientTests : IAsyncDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"yura-ipc-{Guid.NewGuid():N}.sock");
    private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _serving;

    public DaemonClientTests()
    {
        _listener.Bind(new UnixDomainSocketEndPoint(_path));
        _listener.Listen();
        _serving = ServeAsync();
    }

    /// <summary>Which run of the daemon is answering. Changes when it "restarts".</summary>
    private string _instance = "first";

    private TimeSpan _delay = TimeSpan.Zero;

    private Func<IpcResponse> _answer = () => new IpcResponse { Ok = true };

    private async Task ServeAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_stop.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }

            _ = Task.Run(async () =>
            {
                using (client)
                {
                    try
                    {
                        using var stream = new NetworkStream(client);
                        using var reader = new StreamReader(stream);
                        if (await reader.ReadLineAsync(_stop.Token) is null)
                        {
                            return;
                        }

                        await Task.Delay(_delay, _stop.Token);
                        var response = _answer();
                        response.Instance = _instance;
                        var line = JsonSerializer.Serialize(response, IpcProtocol.Json) + "\n";
                        await stream.WriteAsync(Encoding.UTF8.GetBytes(line), _stop.Token);
                    }
                    catch (Exception e) when (e is OperationCanceledException or IOException or SocketException)
                    {
                        // The client went away first, which is what some of these tests do.
                    }
                }
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Dispose();
        await _serving;
        File.Delete(_path);
    }

    private static readonly RoutingRule Rule = new()
    {
        Id = Guid.NewGuid(),
        Order = 100,
        Name = "curl direct",
        Origin = RuleOrigin.Manual,
        Lifetime = RuleLifetime.Persistent,
        Process = new ProcessSelector { Kind = ProcessSelectorKind.ProcessName, ProcessName = "curl" },
        Action = RuleAction.Direct.Instance,
        CreatedAtUtc = DateTimeOffset.UnixEpoch,
    };

    [Fact]
    public async Task Cancelling_a_request_says_nothing_about_the_daemon()
    {
        // Pressing Stop during a measurement used to leave the whole app believing there was no
        // daemon: every privileged action disabled until something asked again.
        var client = new UnixSocketDaemonClient(_path);
        await client.ConnectAsync(TestContext.Current.CancellationToken);
        Assert.Equal(DaemonState.Connected, client.State);
        var changes = new List<DaemonState>();
        client.StateChanged += (_, state) => changes.Add(state);

        _delay = TimeSpan.FromSeconds(2);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var measurement = await client.MeasureAsync("203.0.113.5", 27015, null, null, 5, cancel.Token);

        Assert.Null(measurement);
        Assert.Equal(DaemonState.Connected, client.State);
        Assert.Empty(changes);
    }

    [Fact]
    public async Task An_answer_from_a_new_run_of_the_daemon_is_noticed()
    {
        var client = new UnixSocketDaemonClient(_path);
        var restarts = 0;
        client.InstanceChanged += (_, _) => Interlocked.Increment(ref restarts);
        var ct = TestContext.Current.CancellationToken;

        await client.ConnectAsync(ct);
        Assert.True(await client.PingAsync(ct));

        // The first daemon seen is not a restart.
        Assert.Equal(0, restarts);

        _instance = "second";
        Assert.True(await client.PingAsync(ct));

        Assert.Equal(1, restarts);
        Assert.Equal(DaemonState.Connected, client.State);
    }

    [Fact]
    public async Task A_refusal_is_an_answer_and_silence_is_not()
    {
        var ct = TestContext.Current.CancellationToken;
        _answer = () => IpcResponse.Failure("The rule's process has exited.");
        var client = new UnixSocketDaemonClient(_path);

        var refused = await client.ApplyRuleAsync(Rule, false, ct);

        Assert.False(refused.Succeeded);
        Assert.True(refused.Answered);

        var nobody = new UnixSocketDaemonClient(Path.Combine(Path.GetTempPath(), $"yura-none-{Guid.NewGuid():N}.sock"));
        var unreachable = await nobody.ApplyRuleAsync(Rule, false, ct);

        Assert.False(unreachable.Succeeded);
        Assert.False(unreachable.Answered);
        Assert.Equal(DaemonState.Disconnected, nobody.State);
    }
}
