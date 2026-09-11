using System.Diagnostics;
using System.Globalization;
using System.Net;
using Yura.Core.Agent;
using Yura.Core.Net;

namespace Yura.Agent;

/// <summary>
/// The agent's command line: run it, or set it up so it runs itself.
/// </summary>
/// <remarks>
/// One binary with a handful of verbs, because the thing it is competing with is "paste this
/// one line into your server" — anything that needs a configuration file written by hand is
/// already too much. <c>install</c> does the whole job and finishes by printing the one string
/// the user has to carry back to Yura.
/// </remarks>
public static class Program
{
    private static string Version =>
        typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0";

    public static async Task<int> Main(string[] args)
    {
        var verb = args.FirstOrDefault() ?? "help";
        var rest = args.Skip(1).ToArray();

        try
        {
            return verb switch
            {
                "run" => await RunAsync(rest).ConfigureAwait(false),
                "init" => Init(rest),
                "show" => Show(rest),
                "rotate" => Rotate(rest),
                "install" => await InstallAsync(rest).ConfigureAwait(false),
                "uninstall" => await UninstallAsync(rest).ConfigureAwait(false),
                "unit" => Unit(rest),
                "--version" or "-v" or "version" => Print(Version),
                "help" or "--help" or "-h" => Help(),
                _ => Fail($"unknown command '{verb}'. Try --help."),
            };
        }
        catch (ArgumentException e)
        {
            return Fail(e.Message);
        }
    }

    // -- run -------------------------------------------------------------------

    private static async Task<int> RunAsync(string[] args)
    {
        var arguments = new Arguments(args);
        var options = arguments.ToOptions();
        var identity = AgentIdentity.LoadOrCreate(arguments.State, arguments.Name);

        if (!AgentDatagramCrypto.IsSupported)
        {
            return Fail("this platform has no AES-GCM, which the datagram channel needs");
        }

        await using var server = new AgentServer(options, identity, Log);
        try
        {
            server.Start();
        }
        catch (Exception e) when (e is System.Net.Sockets.SocketException or ArgumentException)
        {
            return Fail($"could not listen on {options.Listen}:{options.Port}: {e.Message}");
        }

        using var stopping = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stopping.Cancel();
        };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => stopping.Cancel();

        Log("ready");
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, stopping.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        Log("stopping");
        return 0;
    }

    private static void Log(string message) =>
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} yura-agent: {message}"));

    // -- identity --------------------------------------------------------------

    private static int Init(string[] args)
    {
        var arguments = new Arguments(args);
        var existed = AgentIdentity.Load(arguments.State) is not null;
        var identity = AgentIdentity.LoadOrCreate(arguments.State, arguments.Name);

        Console.WriteLine(existed
            ? $"An identity already exists in {identity.Directory}; it was left alone."
            : $"Created an identity in {identity.Directory}.");
        PrintConnection(identity, arguments);
        return 0;
    }

    private static int Show(string[] args)
    {
        var arguments = new Arguments(args);
        if (AgentIdentity.Load(arguments.State) is not { } identity)
        {
            return Fail($"no agent identity in {arguments.State}. Run 'yura-agent init' first.");
        }

        PrintConnection(identity, arguments);
        return 0;
    }

    private static int Rotate(string[] args)
    {
        var arguments = new Arguments(args);
        if (AgentIdentity.Load(arguments.State) is null)
        {
            return Fail($"no agent identity in {arguments.State}.");
        }

        AgentIdentity.RotateToken(arguments.State);
        var identity = AgentIdentity.LoadOrCreate(arguments.State);
        Console.WriteLine("The token has been replaced. Every client must be given the new connect string,");
        Console.WriteLine($"and the agent must be restarted: systemctl restart {AgentUnit.ServiceName}");
        PrintConnection(identity, arguments);
        return 0;
    }

    /// <summary>Prints the one line the user carries back to Yura, and what is in it.</summary>
    private static void PrintConnection(AgentIdentity identity, Arguments arguments)
    {
        var (detected, looksPublic) = AgentIdentity.LikelyAddress();
        var host = arguments.Host ?? detected;
        var port = arguments.Port ?? AgentProtocol.DefaultPort;
        var connection = identity.ConnectionFor(host, port);

        Console.WriteLine();
        Console.WriteLine("Paste this into Yura → Proxies → Add agent:");
        Console.WriteLine();
        Console.WriteLine("  " + connection.ToConnectString());
        Console.WriteLine();
        Console.WriteLine($"  name         {identity.Name}");
        Console.WriteLine($"  address      {connection.Authority}");
        Console.WriteLine($"  key          {connection.FingerprintDisplay}");
        Console.WriteLine();

        if (arguments.Host is null && !looksPublic)
        {
            Console.WriteLine($"The address above ({host}) is this machine's own, and it is not a public one.");
            Console.WriteLine("If clients reach this server at a different address, pass --host to print that instead.");
            Console.WriteLine();
        }

        Console.WriteLine("The string contains the token, which is the whole of a client's authority to");
        Console.WriteLine("use this agent. Treat it like a password: send it over something private, and");
        Console.WriteLine("run 'yura-agent rotate' if it leaks.");
    }

    // -- service ---------------------------------------------------------------

    private static int Unit(string[] args)
    {
        var arguments = new Arguments(args);
        Console.Write(AgentUnit.Generate(arguments.ToOptions(), arguments.Name));
        return 0;
    }

    private static async Task<int> InstallAsync(string[] args)
    {
        if (!Environment.IsPrivilegedProcess)
        {
            return Fail("install must be run as root: sudo yura-agent install");
        }

        var arguments = new Arguments(args, defaultState: AgentUnit.StateDirectory);
        var options = arguments.ToOptions();

        if (Environment.ProcessPath is not { } executable)
        {
            return Fail("could not work out this executable's own path");
        }

        if (!string.Equals(executable, AgentUnit.InstallPath, StringComparison.Ordinal))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(AgentUnit.InstallPath)!);
            File.Copy(executable, AgentUnit.InstallPath, overwrite: true);
            File.SetUnixFileMode(AgentUnit.InstallPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            Console.WriteLine($"Copied the agent to {AgentUnit.InstallPath}.");
        }

        await File.WriteAllTextAsync(AgentUnit.UnitPath, AgentUnit.Generate(options, arguments.Name))
            .ConfigureAwait(false);
        Console.WriteLine($"Wrote {AgentUnit.UnitPath}.");

        if (await Systemctl("daemon-reload").ConfigureAwait(false) != 0 ||
            await Systemctl("enable", "--now", AgentUnit.ServiceName).ConfigureAwait(false) != 0)
        {
            return Fail("systemd would not start the service; see: systemctl status " + AgentUnit.ServiceName);
        }

        Console.WriteLine($"{AgentUnit.ServiceName} is enabled and running.");

        // The service creates its identity on first run, in a directory systemd owns.
        for (var attempt = 0; attempt < 25 && AgentIdentity.Load(AgentUnit.StateDirectory) is null; attempt++)
        {
            await Task.Delay(200).ConfigureAwait(false);
        }

        if (AgentIdentity.Load(AgentUnit.StateDirectory) is not { } identity)
        {
            return Fail($"the service started but wrote no identity to {AgentUnit.StateDirectory}; " +
                        "see: journalctl -u " + AgentUnit.ServiceName);
        }

        PrintConnection(identity, arguments);
        return 0;
    }

    private static async Task<int> UninstallAsync(string[] args)
    {
        if (!Environment.IsPrivilegedProcess)
        {
            return Fail("uninstall must be run as root: sudo yura-agent uninstall");
        }

        var purge = args.Contains("--purge");

        await Systemctl("disable", "--now", AgentUnit.ServiceName).ConfigureAwait(false);
        foreach (var path in new[] { AgentUnit.UnitPath, AgentUnit.InstallPath })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
                Console.WriteLine($"Removed {path}.");
            }
        }

        await Systemctl("daemon-reload").ConfigureAwait(false);

        if (purge && Directory.Exists(AgentUnit.StateDirectory))
        {
            Directory.Delete(AgentUnit.StateDirectory, recursive: true);
            Console.WriteLine($"Removed {AgentUnit.StateDirectory}, including the agent's key and token.");
        }
        else if (Directory.Exists(AgentUnit.StateDirectory))
        {
            Console.WriteLine($"{AgentUnit.StateDirectory} was kept, so reinstalling keeps the same connect");
            Console.WriteLine("string. Pass --purge to delete the key and token as well.");
        }

        return 0;
    }

    private static async Task<int> Systemctl(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("systemctl") { UseShellExecute = false };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return -1;
            }

            await process.WaitForExitAsync().ConfigureAwait(false);
            return process.ExitCode;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Console.Error.WriteLine($"could not run systemctl: {e.Message}");
            return -1;
        }
    }

    // -- arguments -------------------------------------------------------------

    /// <summary>
    /// The options, parsed by hand.
    /// </summary>
    /// <remarks>
    /// By hand because the alternative is a dependency, and a server-side binary that has to
    /// be trusted is worth keeping to the standard library.
    /// </remarks>
    private sealed class Arguments
    {
        public Arguments(string[] args, string defaultState = AgentUnit.StateDirectory)
        {
            State = defaultState;

            for (var i = 0; i < args.Length; i++)
            {
                var argument = args[i];
                string Value()
                {
                    if (i + 1 >= args.Length)
                    {
                        throw new ArgumentException($"{argument} needs a value");
                    }

                    return args[++i];
                }

                switch (argument)
                {
                    case "--state":
                        State = Value();
                        break;
                    case "--name":
                        Name = Value();
                        break;
                    case "--host":
                        Host = Value();
                        break;
                    case "--listen":
                        Listen = IPAddress.TryParse(Value(), out var listen)
                            ? listen
                            : throw new ArgumentException("--listen needs an IP address");
                        break;
                    case "--port":
                        Port = ParsePort(Value(), "--port");
                        break;
                    case "--udp-port":
                        UdpPort = ParsePort(Value(), "--udp-port");
                        break;
                    case "--no-udp":
                        Udp = false;
                        break;
                    case "--allow-private":
                        AllowPrivate = true;
                        break;
                    case "--allow":
                        Allowed.Add(ParseNetwork(Value()));
                        break;
                    case "--deny":
                        Denied.Add(ParseNetwork(Value()));
                        break;
                    case "--ports":
                        foreach (var part in Value().Split(',', StringSplitOptions.RemoveEmptyEntries))
                        {
                            Ports.Add(PortRange.TryParse(part, out var range)
                                ? range
                                : throw new ArgumentException($"'{part}' is not a port or port range"));
                        }

                        break;
                    case "--max-sessions":
                        MaxSessions = int.TryParse(Value(), out var sessions) && sessions > 0
                            ? sessions
                            : throw new ArgumentException("--max-sessions needs a positive number");
                        break;
                    case "--purge":
                        break;
                    default:
                        throw new ArgumentException($"unknown option '{argument}'");
                }
            }
        }

        public string State { get; }

        public string? Name { get; }

        public string? Host { get; }

        public IPAddress Listen { get; } = IPAddress.IPv6Any;

        public ushort? Port { get; }

        public ushort? UdpPort { get; }

        public bool Udp { get; } = true;

        public bool AllowPrivate { get; }

        public List<IPNetwork> Allowed { get; } = [];

        public List<IPNetwork> Denied { get; } = [];

        public List<PortRange> Ports { get; } = [];

        public int MaxSessions { get; } = 64;

        public AgentOptions ToOptions() => new()
        {
            Listen = Listen,
            Port = Port ?? AgentProtocol.DefaultPort,
            UdpPort = UdpPort ?? 0,
            Udp = Udp,
            MaxSessions = MaxSessions,
            Policy = new DestinationPolicy
            {
                AllowPrivate = AllowPrivate,
                Allowed = Allowed,
                Denied = Denied,
                Ports = Ports,
            },
        };

        private static ushort ParsePort(string text, string option) =>
            ushort.TryParse(text, out var port) && port > 0
                ? port
                : throw new ArgumentException($"{option} needs a port number");

        private static IPNetwork ParseNetwork(string text) =>
            IPNetwork.TryParse(text, out var network)
                ? network
                : IPAddress.TryParse(text, out var address)
                    ? new IPNetwork(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)
                    : throw new ArgumentException($"'{text}' is not a network in CIDR form");
    }

    // -- help ------------------------------------------------------------------

    private static int Help()
    {
        Console.WriteLine($"""
            yura-agent {Version} — Yura's server-side relay.

            Put this on a server near the game's servers, then point Yura at it: selected
            games leave through the agent instead of through your own connection.

              yura-agent install                 set it up as a service and print the connect string
              yura-agent run                     run it in the foreground
              yura-agent init                    create the key and token without starting anything
              yura-agent show                    print the connect string again
              yura-agent rotate                  replace the token, invalidating every client
              yura-agent unit                    print the systemd unit that install would write
              yura-agent uninstall [--purge]     remove the service, keeping the key unless purged

            Options for run, install, init, show and unit:

              --state DIR        where the key and token live (default {AgentUnit.StateDirectory})
              --name NAME        what the agent calls itself (default: this host's name)
              --listen ADDRESS   address to listen on (default ::, meaning everything)
              --port PORT        TCP port (default {AgentProtocol.DefaultPort})
              --udp-port PORT    UDP port (default: the same number as --port)
              --no-udp           do not relay UDP at all
              --host HOST        the address to print in the connect string
              --allow-private    relay to private and loopback addresses, which is refused by default
              --allow CIDR       relay only to these networks (repeatable)
              --deny CIDR        never relay to these networks (repeatable)
              --ports LIST       relay only to these destination ports, e.g. 27015-27050,443
              --max-sessions N   how many clients at once (default 64)

            The agent refuses private, loopback and link-local destinations unless told
            otherwise, so a client holding the token cannot use it to reach the server's own
            network.
            """);
        return 0;
    }

    private static int Print(string text)
    {
        Console.WriteLine(text);
        return 0;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"yura-agent: {message}");
        return 1;
    }
}
