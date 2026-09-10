using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Yura.Core.Ipc;
using Yura.Core.Processes;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon;

internal static class Program
{
    public const string Version = "0.1.0";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "ctl")
        {
            return await ControlAsync(args[1..]).ConfigureAwait(false);
        }

        return await RunDaemonAsync(args).ConfigureAwait(false);
    }

    // -- daemon --------------------------------------------------------------

    private static async Task<int> RunDaemonAsync(string[] args)
    {
        var socketPath = IpcProtocol.DefaultSocketPath;
        var allowedUids = new HashSet<uint> { 0 };
        var verbose = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--socket" when i + 1 < args.Length:
                    socketPath = args[++i];
                    break;
                case "--allow-uid" when i + 1 < args.Length && uint.TryParse(args[i + 1], out var uid):
                    allowedUids.Add(uid);
                    i++;
                    break;
                case "--verbose":
                    verbose = true;
                    break;
                case "-h" or "--help":
                    Console.WriteLine("yura-daemon [--socket PATH] [--allow-uid UID]... [--verbose]");
                    Console.WriteLine("yura-daemon ctl [--socket PATH] <op> [json]");
                    return 0;
            }
        }

        // The user who started us via sudo is, by construction, the desktop user who
        // will run the app.
        if (Environment.GetEnvironmentVariable("SUDO_UID") is { } sudoUid && uint.TryParse(sudoUid, out var parsedSudoUid))
        {
            allowedUids.Add(parsedSudoUid);
        }

        void Log(string message)
        {
            if (verbose || !message.StartsWith("exec:", StringComparison.Ordinal) && !message.StartsWith("stdin:", StringComparison.Ordinal))
            {
                Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} {message}");
            }
        }

        // ---- preflight: fail fast with a reason a person can act on.
        if (geteuid() != 0)
        {
            Console.Error.WriteLine("yura-daemon must run as root: it configures nftables, policy routing and cgroups.");
            return 1;
        }

        if (!CgroupManager.IsCgroup2Available())
        {
            Console.Error.WriteLine("cgroup v2 unified hierarchy is not mounted at /sys/fs/cgroup.");
            return 1;
        }

        var commands = new CommandRunner(Log);
        var probe = await commands.RunAsync("nft", ["--version"]).ConfigureAwait(false);
        if (!probe.Succeeded)
        {
            Console.Error.WriteLine($"nft is not usable: {probe.FailureText}");
            return 1;
        }

        Log($"yura-daemon {Version} starting; {probe.StandardOutput.Trim()}");

        var processes = new ProcProcessSource();
        var cgroups = new CgroupManager(Log, processes);
        var nftables = new NftablesManager(commands, Log);
        var routing = new PolicyRouting(commands, Log);
        var flows = new FlowRegistry();
        var ownership = new SocketOwnership();

        await using var runtime = new RuleRuntime(cgroups, nftables, processes, flows, ownership, Log);

        if (!await routing.InstallAsync().ConfigureAwait(false))
        {
            Console.Error.WriteLine("could not install policy routing; see log above.");
            return 1;
        }

        // Install the empty ruleset now so a kernel without nft_socket/nft_tproxy fails at
        // startup rather than on the first rule.
        var empty = NftablesManager.Build([], []);
        var check = await nftables.CheckAsync(empty).ConfigureAwait(false);
        if (!check.Succeeded)
        {
            Console.Error.WriteLine($"the kernel rejected Yura's base ruleset: {check.FailureText}");
            await routing.RemoveAsync().ConfigureAwait(false);
            routing.RestoreSysctls();
            return 1;
        }

        await nftables.ApplyAsync(empty).ConfigureAwait(false);

        await using var ipc = new IpcServer(socketPath, allowedUids, runtime, flows, ownership, Log);
        ipc.Start();

        using var shutdown = new CancellationTokenSource();
        // The registrations must be held. PosixSignalRegistration unregisters the handler
        // when it is finalised, so dropping the return value lets the GC silently disarm
        // the signal and the daemon dies without removing its rules from the kernel.
        using var sigterm = PosixSignalRegistration.Create(
            PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; shutdown.Cancel(); });
        using var sigint = PosixSignalRegistration.Create(
            PosixSignal.SIGINT, ctx => { ctx.Cancel = true; shutdown.Cancel(); });

        // Until the process-event watcher lands, instance rules expire on a short poll.
        var expiry = Task.Run(async () =>
        {
            while (!shutdown.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), shutdown.Token).ConfigureAwait(false);
                    await runtime.ExpireDeadInstancesAsync(shutdown.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    Log($"expiry sweep failed: {e.Message}");
                }
            }
        });

        Log("ready");
        try
        {
            await Task.Delay(Timeout.Infinite, shutdown.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        Log("shutting down");
        await expiry.ConfigureAwait(false);
        await runtime.TeardownAsync().ConfigureAwait(false);
        await routing.RemoveAsync().ConfigureAwait(false);
        routing.RestoreSysctls();
        Log("clean shutdown: rules, routing and cgroups removed");
        return 0;
    }

    [DllImport("libc")]
    private static extern uint geteuid();

    // -- ctl -----------------------------------------------------------------

    /// <summary>
    /// A minimal client: <c>yura-daemon ctl status</c>, <c>yura-daemon ctl apply-rule '{...}'</c>.
    /// Exists so the acceptance tests drive the real IPC path rather than a test seam.
    /// </summary>
    private static async Task<int> ControlAsync(string[] args)
    {
        var socketPath = IpcProtocol.DefaultSocketPath;
        var rest = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--socket" && i + 1 < args.Length)
            {
                socketPath = args[++i];
            }
            else
            {
                rest.Add(args[i]);
            }
        }

        if (rest.Count == 0)
        {
            Console.Error.WriteLine("usage: yura-daemon ctl [--socket PATH] <op> [json-body]");
            return 2;
        }

        // The body, if given, is merged with the op so callers write only the payload.
        string requestJson;
        if (rest.Count > 1)
        {
            using var doc = JsonDocument.Parse(rest[1]);
            var merged = new Dictionary<string, object?> { ["op"] = rest[0] };
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                merged[property.Name] = property.Value.Clone();
            }

            requestJson = JsonSerializer.Serialize(merged, IpcProtocol.Json);
        }
        else
        {
            requestJson = JsonSerializer.Serialize(new { op = rest[0] }, IpcProtocol.Json);
        }

        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath)).ConfigureAwait(false);
        }
        catch (SocketException e)
        {
            Console.Error.WriteLine($"cannot connect to {socketPath}: {e.Message}");
            return 1;
        }

        // No half-close: the protocol is one line in, one line out, and NetworkStream
        // refuses to wrap a socket that has been shut down in either direction.
        using var stream = new NetworkStream(socket, ownsSocket: false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        await socket.SendAsync(Encoding.UTF8.GetBytes(requestJson + "\n")).ConfigureAwait(false);
        var line = await reader.ReadLineAsync().ConfigureAwait(false);
        if (line is null)
        {
            Console.Error.WriteLine("daemon closed the connection without answering");
            return 1;
        }

        Console.WriteLine(line);
        using var response = JsonDocument.Parse(line);
        return response.RootElement.TryGetProperty("ok", out var ok) && ok.GetBoolean() ? 0 : 1;
    }
}
