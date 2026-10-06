using System.Diagnostics;
using System.Globalization;
using System.Text;
using Yura.Core.Ipc;

namespace Yura.App.Services;

/// <summary>Where a daemon binary can come from, so the Settings page can say so in its own language.</summary>
public enum DaemonSource
{
    /// <summary>The path typed into Settings.</summary>
    Explicit,

    /// <summary><c>YURA_DAEMON</c> in the environment.</summary>
    Environment,

    /// <summary>Next to the application binary, as a packaged install lays it out.</summary>
    Sibling,

    /// <summary>The system install directory a previous install populated.</summary>
    Installed,

    /// <summary>The development tree's build output.</summary>
    Development,
}

/// <summary>Where the daemon was found and how systemd should start it.</summary>
/// <param name="ExecStart">The complete command, as it goes into the unit file.</param>
/// <param name="Directory">The directory holding the daemon and its runtime files.</param>
/// <param name="Source">Where it was found.</param>
/// <param name="InHome">True when it lives under a home directory, which the unit must then be allowed to read.</param>
public sealed record DaemonLocation(string ExecStart, string Directory, DaemonSource Source, bool InHome);

/// <summary>Finds the daemon binary on this machine.</summary>
/// <remarks>
/// The daemon is a framework-dependent .NET build: a <c>yura-daemon.dll</c> next to a
/// <c>yura-daemon</c> apphost. The unit runs the dll through the dotnet host when one can be
/// found, which is the form that does not depend on where the apphost thinks the runtime
/// lives; otherwise the apphost itself.
/// </remarks>
public static class DaemonLocator
{
    public const string InstallDirectory = "/usr/local/lib/yura/daemon";

    private static readonly string[] DotnetHosts =
    [
        "/usr/share/dotnet/dotnet",
        "/usr/lib/dotnet/dotnet",
        "/usr/lib64/dotnet/dotnet",
        "/opt/dotnet/dotnet",
        "/usr/local/share/dotnet/dotnet",
        "/usr/bin/dotnet",
    ];

    /// <summary>Looks in the places a daemon can be, most deliberate first.</summary>
    public static DaemonLocation? Find(string? explicitPath = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return Describe(explicitPath.Trim(), DaemonSource.Explicit);
        }

        if (Environment.GetEnvironmentVariable("YURA_DAEMON") is { Length: > 0 } fromEnvironment)
        {
            if (Describe(fromEnvironment, DaemonSource.Environment) is { } located)
            {
                return located;
            }
        }

        var appDirectory = AppContext.BaseDirectory.TrimEnd('/');
        if (Describe(Path.Combine(appDirectory, "yura-daemon"), DaemonSource.Sibling) is { } sibling)
        {
            return sibling;
        }

        // The development tree: src/Yura.App/bin/<config>/net10.0 → src/Yura.Daemon/bin/<config>/net10.0.
        // Looked at before the system install directory on purpose. What "install" should mean
        // is "install the daemon I have"; preferring the copy already installed made the button
        // reinstall the same files it found, so a rebuilt daemon could never reach the service.
        foreach (var configuration in new[] { "Debug", "Release" })
        {
            var candidate = Path.GetFullPath(Path.Combine(appDirectory, "..", "..", "..", "..", "Yura.Daemon", "bin", configuration, "net10.0", "yura-daemon"));
            if (Describe(candidate, DaemonSource.Development) is { } development)
            {
                return development;
            }
        }

        // Last: the copy a previous install left behind. Enough to run and report, and the only
        // thing available to a machine where the app was moved away from its daemon.
        if (Describe(Path.Combine(InstallDirectory, "yura-daemon"), DaemonSource.Installed) is { } installed)
        {
            return installed;
        }

        return null;
    }

    public static string? FindDotnetHost()
    {
        foreach (var host in DotnetHosts)
        {
            if (File.Exists(host))
            {
                // A symlink such as /usr/bin/dotnet is fine to run but its target is the
                // honest path for a unit file.
                var info = new FileInfo(host);
                return info.LinkTarget is { } target ? Path.GetFullPath(target, Path.GetDirectoryName(host)!) : host;
            }
        }

        return null;
    }

    private static DaemonLocation? Describe(string path, DaemonSource source)
    {
        // Accept the apphost, the dll, or the directory holding them.
        if (Directory.Exists(path))
        {
            path = Path.Combine(path, "yura-daemon");
        }

        var directory = Path.GetDirectoryName(path);
        if (directory is null)
        {
            return null;
        }

        var apphost = Path.Combine(directory, "yura-daemon");
        var dll = Path.Combine(directory, "yura-daemon.dll");
        if (!File.Exists(apphost) && !File.Exists(dll))
        {
            return null;
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var inHome = directory.StartsWith("/home/", StringComparison.Ordinal) ||
                     (home.Length > 1 && directory.StartsWith(home, StringComparison.Ordinal));

        var execStart = File.Exists(dll) && FindDotnetHost() is { } host
            ? $"{host} {dll}"
            : apphost;

        return new DaemonLocation(execStart, directory, source, inHome);
    }
}

/// <summary>Renders the systemd unit that runs the daemon.</summary>
/// <remarks>
/// The hardening is chosen around what the daemon actually touches: nftables and policy
/// routing over netlink, cgroups under <c>/sys/fs/cgroup</c>, <c>/proc</c>, its runtime
/// directory, and nothing in anyone's home. <c>HOME</c> is pointed at the runtime directory
/// so anything the .NET runtime insists on writing lands on tmpfs, never in a user's home.
/// </remarks>
public static class SystemdUnit
{
    public const string UnitName = "yura-daemon.service";
    public const string UnitPath = "/etc/systemd/system/" + UnitName;

    public static string Generate(string execStart, uint allowedUid, string socketPath, bool daemonInHome)
    {
        var sb = new StringBuilder();
        sb.Append("[Unit]\n");
        sb.Append("Description=Yura per-process routing daemon\n");
        sb.Append("After=network-online.target\n");
        sb.Append("Wants=network-online.target\n");
        sb.Append('\n');
        sb.Append("[Service]\n");
        sb.Append("Type=simple\n");
        sb.Append(CultureInfo.InvariantCulture, $"ExecStart={execStart} --socket {socketPath} --allow-uid {allowedUid}\n");
        sb.Append("Restart=on-failure\n");
        sb.Append("RestartSec=2\n");
        sb.Append("RuntimeDirectory=yura\n");
        sb.Append("RuntimeDirectoryMode=0755\n");
        sb.Append("# The runtime directory is the only place the daemon may write, and it is tmpfs.\n");
        sb.Append("Environment=HOME=/run/yura DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1\n");
        sb.Append('\n');
        sb.Append("# Hardening. The daemon needs the network, netlink, cgroups and /proc; nothing else.\n");
        sb.Append(daemonInHome
            ? "# The daemon lives under a home directory (a development build), so home stays readable.\nProtectHome=read-only\n"
            : "ProtectHome=yes\n");
        sb.Append("ProtectSystem=strict\n");
        sb.Append("ReadWritePaths=/run/yura\n");
        sb.Append("PrivateTmp=yes\n");
        sb.Append("NoNewPrivileges=yes\n");
        sb.Append("LockPersonality=yes\n");
        sb.Append("RestrictRealtime=yes\n");
        sb.Append("RestrictSUIDSGID=yes\n");
        sb.Append("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n");
        sb.Append("SystemCallArchitectures=native\n");
        sb.Append('\n');
        sb.Append("[Install]\n");
        sb.Append("WantedBy=multi-user.target\n");
        return sb.ToString();
    }
}

public enum ServiceState
{
    /// <summary>systemd is not the init system, or systemctl is missing.</summary>
    Unsupported,
    NotInstalled,
    Stopped,
    Running,
    Failed,
}

/// <summary>What systemd says about the unit right now.</summary>
public sealed record ServiceStatus(ServiceState State, bool Enabled, string? ExecStart, string? Detail);

/// <summary>The privileged operations the Settings page needs, so a demo can stand in for them.</summary>
public interface IServiceManager
{
    bool HasSystemd { get; }

    bool HasPolkit { get; }

    Task<ServiceStatus> QueryAsync(CancellationToken ct = default);

    Task<(bool Succeeded, string Output)> RunAsRootAsync(string script, CancellationToken ct = default);

    Task<(bool Succeeded, string Output)> ControlAsync(string verb, CancellationToken ct = default);

    Task<string> JournalTailAsync(int lines, CancellationToken ct = default);
}

/// <summary>A service manager for design review: reports an installed, running service.</summary>
public sealed class SimulatedServiceManager : IServiceManager
{
    public bool HasSystemd => true;

    public bool HasPolkit => true;

    public Task<ServiceStatus> QueryAsync(CancellationToken ct = default) =>
        Task.FromResult(new ServiceStatus(ServiceState.Running, true,
            "/usr/share/dotnet/dotnet /usr/local/lib/yura/daemon/yura-daemon.dll --socket /run/yura/yura.sock --allow-uid 1000", "running"));

    public Task<(bool Succeeded, string Output)> RunAsRootAsync(string script, CancellationToken ct = default) =>
        Task.FromResult((true, "(simulated)"));

    public Task<(bool Succeeded, string Output)> ControlAsync(string verb, CancellationToken ct = default) =>
        Task.FromResult((true, string.Empty));

    public Task<string> JournalTailAsync(int lines, CancellationToken ct = default) => Task.FromResult(string.Empty);
}

/// <summary>
/// Installs, removes and controls the daemon's systemd unit from the unprivileged app.
/// </summary>
/// <remarks>
/// Writing to <c>/etc</c> and <c>/usr/local</c> needs root, so installation goes through
/// <c>pkexec</c>: the desktop's polkit agent asks the user for their password, exactly as a
/// settings panel would. The whole install is one script so there is one prompt, and the
/// script is shown in full before it runs. Start, stop and restart go straight to
/// <c>systemctl</c>, which asks polkit itself.
///
/// Nothing here edits sudoers or stores a credential. Where there is no polkit agent, the
/// same script is offered for the user to run with sudo.
/// </remarks>
public sealed class ServiceManager : IServiceManager
{
    private readonly string? _systemctl = Which("systemctl");
    private readonly string? _pkexec = Which("pkexec");

    public bool HasSystemd => _systemctl is not null && Directory.Exists("/run/systemd/system");

    public bool HasPolkit => _pkexec is not null;

    public async Task<ServiceStatus> QueryAsync(CancellationToken ct = default)
    {
        if (!HasSystemd)
        {
            return new ServiceStatus(ServiceState.Unsupported, false, null, "systemd is not running this machine.");
        }

        var (exit, output) = await RunAsync(_systemctl!,
            ["show", SystemdUnit.UnitName, "-p", "LoadState,ActiveState,SubState,UnitFileState,ExecStart,Result"], ct)
            .ConfigureAwait(false);
        if (exit != 0)
        {
            return new ServiceStatus(ServiceState.NotInstalled, false, null, output.Trim());
        }

        var properties = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('=', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.Ordinal);

        if (properties.GetValueOrDefault("LoadState") is "not-found" or null)
        {
            return new ServiceStatus(ServiceState.NotInstalled, false, null, null);
        }

        var enabled = properties.GetValueOrDefault("UnitFileState") == "enabled";
        var state = properties.GetValueOrDefault("ActiveState") switch
        {
            "active" or "reloading" or "activating" => ServiceState.Running,
            "failed" => ServiceState.Failed,
            _ => ServiceState.Stopped,
        };

        // ExecStart is rendered as "{ path=... ; argv[]=a b c ; ... }"; the argv is the part a person wants.
        string? execStart = null;
        if (properties.GetValueOrDefault("ExecStart") is { } raw)
        {
            var start = raw.IndexOf("argv[]=", StringComparison.Ordinal);
            if (start >= 0)
            {
                var end = raw.IndexOf(" ;", start, StringComparison.Ordinal);
                execStart = end > start ? raw[(start + 7)..end] : raw[(start + 7)..];
            }
        }

        var detail = state == ServiceState.Failed
            ? $"{properties.GetValueOrDefault("SubState")} ({properties.GetValueOrDefault("Result")})"
            : properties.GetValueOrDefault("SubState");
        return new ServiceStatus(state, enabled, execStart, detail);
    }

    /// <summary>
    /// The exact script that installation runs as root.
    /// </summary>
    /// <remarks>
    /// Three things this has to survive, all learned the hard way. The daemon it is installing
    /// can already <em>be</em> the installed copy — reinstalling to pick up a rebuild, or a path
    /// typed by hand — and <c>cp</c> refuses to copy a directory onto itself, which under
    /// <c>set -e</c> aborted the script before the unit was ever written. The copy is staged
    /// beside the target and moved into place, so a failure part way through leaves the previous
    /// install as it was rather than half of it. And the files end up belonging to root: they
    /// are what the service runs as root, and a copy that kept the build directory's owner —
    /// which <c>cp -a</c> does when root runs it — left them writable by the desktop user, so
    /// anything running as that user could replace the daemon and be root at its next start.
    /// </remarks>
    public static string BuildInstallScript(DaemonLocation location, string unitText)
    {
        var target = DaemonLocator.InstallDirectory;
        var sb = new StringBuilder();
        sb.Append("#!/bin/sh\n");
        sb.Append("# Installs the Yura daemon as a systemd service. Generated by the Yura application.\n");
        sb.Append("set -eu\n");
        sb.Append(CultureInfo.InvariantCulture, $"src={Quote(location.Directory)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"dst={Quote(target)}\n");
        sb.Append("install -d -m 755 \"$(dirname \"$dst\")\"\n");
        sb.Append("# The daemon and its runtime files are copied out of the build directory so the\n");
        sb.Append("# service does not depend on a home directory or a source tree. When they are\n");
        sb.Append("# already there, there is nothing to copy.\n");
        sb.Append("if [ \"$(cd \"$src\" && pwd -P)\" = \"$(cd \"$dst\" 2>/dev/null && pwd -P || echo none)\" ]; then\n");
        sb.Append("  echo \"the daemon is already in the install directory; leaving the files as they are\"\n");
        sb.Append("else\n");
        sb.Append("  rm -rf \"$dst.new\"\n");
        sb.Append("  install -d -m 755 \"$dst.new\"\n");
        sb.Append("  # Not -a: that would keep the build directory's owner on files root is about to run.\n");
        sb.Append("  cp -R \"$src/.\" \"$dst.new/\"\n");
        sb.Append("  rm -rf \"$dst\"\n");
        sb.Append("  mv \"$dst.new\" \"$dst\"\n");
        sb.Append("fi\n");
        sb.Append("# Root runs these files, so only root may change them — including a copy an earlier\n");
        sb.Append("# install left owned by the desktop user.\n");
        sb.Append("chown -R 0:0 \"$dst\"\n");
        sb.Append("chmod -R u+rwX,go+rX,go-w \"$dst\"\n");
        sb.Append(CultureInfo.InvariantCulture, $"chmod 755 {Quote(target + "/yura-daemon")} 2>/dev/null || true\n");
        sb.Append(CultureInfo.InvariantCulture, $"cat > {Quote(SystemdUnit.UnitPath)} <<'YURA_UNIT'\n");
        sb.Append(RelocateExecStart(unitText, location.Directory, target));
        sb.Append("YURA_UNIT\n");
        sb.Append(CultureInfo.InvariantCulture, $"chmod 644 {Quote(SystemdUnit.UnitPath)}\n");
        sb.Append("systemctl daemon-reload\n");
        sb.Append(CultureInfo.InvariantCulture, $"systemctl enable --now {SystemdUnit.UnitName}\n");
        sb.Append(CultureInfo.InvariantCulture, $"systemctl --no-pager --lines=0 status {SystemdUnit.UnitName} || true\n");
        return sb.ToString();
    }

    /// <summary>The unit as it will be installed: pointing at the copied daemon, with home fully protected.</summary>
    public static string InstalledUnitText(DaemonLocation location, string unitText) =>
        RelocateExecStart(unitText, location.Directory, DaemonLocator.InstallDirectory);

    private static string RelocateExecStart(string unitText, string fromDirectory, string toDirectory)
    {
        var relocated = unitText.Replace(fromDirectory + "/", toDirectory + "/", StringComparison.Ordinal);
        // Once copied out of a home directory, the read-only exception is no longer needed.
        return relocated
            .Replace("# The daemon lives under a home directory (a development build), so home stays readable.\nProtectHome=read-only\n",
                "ProtectHome=yes\n", StringComparison.Ordinal);
    }

    public static string BuildUninstallScript()
    {
        var sb = new StringBuilder();
        sb.Append("#!/bin/sh\n");
        sb.Append("# Removes the Yura daemon service. Generated by the Yura application.\n");
        sb.Append("set -u\n");
        sb.Append(CultureInfo.InvariantCulture, $"systemctl disable --now {SystemdUnit.UnitName} 2>/dev/null || true\n");
        sb.Append(CultureInfo.InvariantCulture, $"rm -f {Quote(SystemdUnit.UnitPath)}\n");
        sb.Append(CultureInfo.InvariantCulture, $"rm -rf {Quote(DaemonLocator.InstallDirectory)}\n");
        sb.Append("rmdir /usr/local/lib/yura 2>/dev/null || true\n");
        sb.Append("systemctl daemon-reload\n");
        return sb.ToString();
    }

    /// <summary>Runs a generated script as root through polkit. One prompt, one script.</summary>
    public async Task<(bool Succeeded, string Output)> RunAsRootAsync(string script, CancellationToken ct = default)
    {
        if (_pkexec is null)
        {
            return (false, "pkexec is not available, so the script cannot be run from here. Copy it and run it with sudo.");
        }

        // A private directory: a script that root is about to run must not sit somewhere
        // another local user could swap it between writing and running.
        var runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        var directory = Path.Combine(
            string.IsNullOrEmpty(runtime) || !Directory.Exists(runtime) ? Path.GetTempPath() : runtime,
            $"yura-privileged-{Environment.ProcessId}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var path = Path.Combine(directory, "run.sh");
        try
        {
            await File.WriteAllTextAsync(path, script, ct).ConfigureAwait(false);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var (exit, output) = await RunAsync(_pkexec, ["/bin/sh", path], ct, TimeSpan.FromMinutes(3)).ConfigureAwait(false);
            return exit switch
            {
                0 => (true, output),
                126 => (false, "The authorisation was dismissed; nothing was changed."),
                127 => (false, "Authorisation failed; nothing was changed."),
                _ => (false, output.Length > 0 ? output : $"The script exited with status {exit}."),
            };
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>start | stop | restart | enable | disable, through systemctl, which asks polkit itself.</summary>
    public async Task<(bool Succeeded, string Output)> ControlAsync(string verb, CancellationToken ct = default)
    {
        if (_systemctl is null)
        {
            return (false, "systemctl is not available.");
        }

        var (exit, output) = await RunAsync(_systemctl, [verb, SystemdUnit.UnitName], ct, TimeSpan.FromMinutes(2)).ConfigureAwait(false);
        return (exit == 0, output.Trim());
    }

    /// <summary>The last lines of the daemon's journal, for the Settings page when the service failed.</summary>
    public async Task<string> JournalTailAsync(int lines, CancellationToken ct = default)
    {
        if (Which("journalctl") is not { } journalctl)
        {
            return string.Empty;
        }

        var (_, output) = await RunAsync(journalctl, ["-u", SystemdUnit.UnitName, "-n", lines.ToString(CultureInfo.InvariantCulture), "--no-pager", "-o", "cat"], ct)
            .ConfigureAwait(false);
        return output.Trim();
    }

    private static async Task<(int Exit, string Output)> RunAsync(string fileName, string[] arguments, CancellationToken ct, TimeSpan? timeout = null)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return (-1, $"could not start {fileName}");
            }

            using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
            limit.CancelAfter(timeout ?? TimeSpan.FromSeconds(20));
            var stdout = process.StandardOutput.ReadToEndAsync(limit.Token);
            var stderr = process.StandardError.ReadToEndAsync(limit.Token);
            try
            {
                await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }

                return (-1, $"{fileName} did not finish in time.");
            }

            var output = (await stdout.ConfigureAwait(false) + await stderr.ConfigureAwait(false)).Trim();
            return (process.ExitCode, output);
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return (-1, e.Message);
        }
    }

    /// <summary>POSIX single-quoting: safe for any path, including one with quotes or spaces.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    private static string? Which(string tool)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "/usr/bin:/bin";
        foreach (var directory in path.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(directory, tool);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
