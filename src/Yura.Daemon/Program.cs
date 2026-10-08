using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Yura.Core.Ipc;
using Yura.Core.Processes;
using Yura.Daemon.Diagnostics;
using Yura.Daemon.Forwarding;
using Yura.Daemon.Linux;
using Yura.Daemon.Runtime;

namespace Yura.Daemon;

internal static class Program
{
    /// <summary>Taken from the assembly so the daemon and the app always agree with the build.</summary>
    public static readonly string Version =
        typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

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
        var noWatcher = false;

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
                case "--no-process-events":
                    noWatcher = true;
                    break;
                case "-h" or "--help":
                    Console.WriteLine("yura-daemon [--socket PATH] [--allow-uid UID]... [--verbose] [--no-process-events]");
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

        var logBuffer = new LogBuffer();
        void Log(string message)
        {
            var line = $"{DateTimeOffset.Now:HH:mm:ss.fff} {message}";
            var noisy = message.StartsWith("exec:", StringComparison.Ordinal) || message.StartsWith("stdin:", StringComparison.Ordinal);
            if (!noisy)
            {
                logBuffer.Append(line);
            }

            if (verbose || !noisy)
            {
                Console.WriteLine(line);
            }
        }

        // ---- preflight: fail fast with a reason a person can act on.
        var checks = new List<CheckDto>();
        if (geteuid() != 0)
        {
            Console.Error.WriteLine("yura-daemon must run as root: it configures nftables, policy routing and cgroups.");
            return 1;
        }

        checks.Add(new CheckDto { Name = "Running as root", Passed = true });

        var cgroup2 = CgroupManager.IsCgroup2Available();
        checks.Add(new CheckDto { Name = "cgroup v2 unified hierarchy", Passed = cgroup2, Detail = cgroup2 ? "/sys/fs/cgroup" : "cgroup.controllers not found at /sys/fs/cgroup" });
        if (!cgroup2)
        {
            Console.Error.WriteLine("cgroup v2 unified hierarchy is not mounted at /sys/fs/cgroup.");
            return 1;
        }

        var commands = new CommandRunner(Log);
        var probe = await commands.RunAsync("nft", ["--version"]).ConfigureAwait(false);
        checks.Add(new CheckDto { Name = "nft available", Passed = probe.Succeeded, Detail = probe.Succeeded ? probe.StandardOutput.Trim() : probe.FailureText });
        if (!probe.Succeeded)
        {
            Console.Error.WriteLine($"nft is not usable: {probe.FailureText}");
            return 1;
        }

        var kernel = ReadTrimmed("/proc/sys/kernel/osrelease");
        Log($"yura-daemon {Version} starting on kernel {kernel}; {probe.StandardOutput.Trim()}");

        var processes = new ProcProcessSource();
        var cgroups = new CgroupManager(Log, processes);

        // A daemon that died without cleaning up leaves its groups behind with processes still
        // in them, captured by nothing and remembered by nobody. They are released now: the
        // periodic sweep does not walk /proc while there are no rules, so it would never find
        // them.
        if (cgroups.ListGroups() is { Count: > 0 } leftovers)
        {
            Log($"releasing {leftovers.Count} process group(s) a previous daemon left behind");
            cgroups.RemoveAllGroups();
        }
        var nftables = new NftablesManager(commands, Log);
        var routing = new PolicyRouting(commands, Log);
        var flows = new FlowRegistry();
        var ownership = new SocketOwnership();

        // WireGuard is optional: a machine without the tool or the module still routes through
        // proxies, and any WireGuard exit it is given is refused with the reason found here.
        var wireguard = new WireGuardManager(commands, Log);
        checks.AddRange(await wireguard.CheckAsync().ConfigureAwait(false));
        if (wireguard.IsAvailable)
        {
            await wireguard.CleanupLeftoversAsync().ConfigureAwait(false);
        }

        // Agent exits need nothing installed on this machine: the sessions are opened when the
        // app pushes its proxy list, and an agent that cannot be reached is a warning on that
        // push rather than a startup failure.
        var agents = new AgentSessionManager(Log);
        checks.Add(new CheckDto
        {
            Name = "AES-GCM available (agent datagram channel)",
            Passed = Yura.Core.Agent.AgentDatagramCrypto.IsSupported,
            Detail = Yura.Core.Agent.AgentDatagramCrypto.IsSupported
                ? null
                : "UDP through a Yura agent will be refused; TCP is unaffected",
        });

        await using var runtime = new RuleRuntime(cgroups, nftables, wireguard, agents, processes, flows, ownership, Log);

        var routingOk = await routing.InstallAsync().ConfigureAwait(false);
        checks.Add(new CheckDto { Name = "Policy routing installed", Passed = routingOk, Detail = routingOk ? $"fwmark 0x{PolicyRouting.MarkBase:x}/0x{PolicyRouting.MarkMask:x} -> table {PolicyRouting.RoutingTable}" : "see daemon log" });
        if (!routingOk)
        {
            Console.Error.WriteLine("could not install policy routing; see log above.");
            return 1;
        }

        // Install the empty ruleset now so a kernel without nft_socket/nft_tproxy fails at
        // startup rather than on the first rule.
        var empty = NftablesManager.Build([], []);
        var check = await nftables.CheckAsync(empty).ConfigureAwait(false);
        checks.Add(new CheckDto { Name = "Kernel accepts the base ruleset (nft_socket, nft_tproxy)", Passed = check.Succeeded, Detail = check.Succeeded ? null : check.FailureText });
        if (!check.Succeeded)
        {
            Console.Error.WriteLine($"the kernel rejected Yura's base ruleset: {check.FailureText}");
            await routing.RemoveAsync().ConfigureAwait(false);
            routing.RestoreSysctls();
            return 1;
        }

        await nftables.ApplyAsync(empty).ConfigureAwait(false);
        checks.Add(new CheckDto { Name = "rp_filter relaxed on lo and all", Passed = ReadTrimmed("/proc/sys/net/ipv4/conf/lo/rp_filter") == "0" && ReadTrimmed("/proc/sys/net/ipv4/conf/all/rp_filter") == "0" });

        // Said out loud because the alternative is a silent leak. TPROXY hands a marked packet
        // to a listener with 'tproxy ip', and the policy-routing rule that loops it back is an
        // IPv4 rule; there is no IPv6 counterpart yet. A covered process's IPv6 connections are
        // therefore refused rather than sent out past the route, and applications fall back to
        // IPv4 within a few milliseconds.
        checks.Add(new CheckDto
        {
            Name = "Address families captured",
            Passed = true,
            Detail = "IPv4. IPv6 from a covered process is refused rather than routed, so nothing leaves past its rule.",
        });

        using var shutdown = new CancellationTokenSource();

        // Process events from the kernel, with the sweep below as the fallback either way.
        using var watcher = new ProcessEventWatcher(Log)
        {
            // Neither of these can wait for the event queue: a socket's cgroup is fixed when
            // it is created, so a process placed — or evicted — a few milliseconds late has
            // already opened connections on the wrong route, and they stay there.
            OnForkFastPath = runtime.TryExcludeChildFast,
            OnExecFastPath = runtime.TryIncludeOnExecFast,
        };
        var watching = !noWatcher && watcher.Start();
        if (!watching)
        {
            Log($"process events: unavailable ({watcher.UnavailableReason ?? "disabled"}); membership is polled");
        }

        checks.Add(new CheckDto { Name = "Kernel process events (netlink connector)", Passed = watching, Detail = watching ? null : watcher.UnavailableReason ?? "disabled with --no-process-events" });

        var environment = new DaemonEnvironment
        {
            SocketPath = socketPath,
            Instance = Guid.NewGuid().ToString("N"),
            AllowedUids = allowedUids,
            KernelRelease = kernel,
            NftVersion = probe.StandardOutput.Trim(),
            Checks = checks,
            ProcessWatcherState = () => watcher.IsRunning
                ? watcher.DroppedEvents == 0 ? "netlink" : $"netlink ({watcher.DroppedEvents} events dropped, recovered by sweep)"
                : $"polling: {watcher.UnavailableReason ?? "disabled"}",
        };

        var connections = new ConnectionLister(runtime, flows, ownership, processes);
        await using var ipc = new IpcServer(socketPath, allowedUids, runtime, flows, ownership, connections, nftables, wireguard, commands, logBuffer, environment, Log);
        ipc.Start();

        // The registrations must be held. PosixSignalRegistration unregisters the handler
        // when it is finalised, so dropping the return value lets the GC silently disarm
        // the signal and the daemon dies without removing its rules from the kernel.
        using var sigterm = PosixSignalRegistration.Create(
            PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; shutdown.Cancel(); });
        using var sigint = PosixSignalRegistration.Create(
            PosixSignal.SIGINT, ctx => { ctx.Cancel = true; shutdown.Cancel(); });

        var eventPump = Task.Run(async () =>
        {
            if (!watching)
            {
                return;
            }

            try
            {
                await foreach (var evt in watcher.Events.ReadAllAsync(shutdown.Token).ConfigureAwait(false))
                {
                    try
                    {
                        await runtime.HandleProcessEventAsync(evt, shutdown.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        Log($"process event {evt.Kind} pid {evt.Pid} failed: {e.Message}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
        });

        // The sweep re-derives membership from /proc and expires dead instances. With events
        // flowing it is a safety net and can run slowly; without them it is the mechanism.
        var sweepInterval = watching ? TimeSpan.FromSeconds(2) : TimeSpan.FromMilliseconds(500);
        var sweep = Task.Run(async () =>
        {
            while (!shutdown.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(sweepInterval, shutdown.Token).ConfigureAwait(false);
                    await runtime.SweepAsync(shutdown.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    Log($"process sweep failed: {e.Message}");
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
        await Task.WhenAll(sweep, eventPump).ConfigureAwait(false);
        await runtime.TeardownAsync().ConfigureAwait(false);
        await routing.RemoveAsync().ConfigureAwait(false);
        routing.RestoreSysctls();
        Log("clean shutdown: rules, routing, tunnels and cgroups removed");
        return 0;
    }

    private static string? ReadTrimmed(string path)
    {
        try
        {
            return File.ReadAllText(path).Trim();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
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
        var requestJson = ControlRequest(rest[0], rest.Count > 1 ? rest[1] : null);

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

    /// <summary>
    /// One request line: <c>{"op": …}</c> followed by the body's members, written as they came.
    /// </summary>
    /// <remarks>
    /// Written member by member rather than serialized from a dictionary or an anonymous object,
    /// neither of which NativeAOT can serialize. A body that names its own <c>op</c> still has the
    /// last word, as it did when the members were merged into a dictionary.
    /// </remarks>
    internal static string ControlRequest(string op, string? body)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            if (body is null)
            {
                writer.WriteString("op", op);
            }
            else
            {
                using var document = JsonDocument.Parse(body);
                var properties = document.RootElement.EnumerateObject().ToList();
                if (!properties.Any(p => p.NameEquals("op")))
                {
                    writer.WriteString("op", op);
                }

                foreach (var property in properties)
                {
                    property.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }
}
