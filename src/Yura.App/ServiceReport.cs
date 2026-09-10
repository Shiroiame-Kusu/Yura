using Yura.App.Services;
using Yura.Core.Ipc;

namespace Yura.App;

/// <summary>
/// Prints what the Settings page would install: where the daemon was found, the unit, and
/// the script that runs as root.
/// </summary>
/// <remarks>
/// Run with <c>--service-report</c>. It exists so the privileged step can be reviewed and,
/// on a machine with no polkit agent, run by hand with sudo, with nothing hidden.
/// </remarks>
internal static class ServiceReport
{
    public static int Run()
    {
        var manager = new ServiceManager();
        var location = DaemonLocator.Find(Environment.GetEnvironmentVariable("YURA_DAEMON"));
        var status = manager.QueryAsync().GetAwaiter().GetResult();

        Console.WriteLine($"systemd          : {(manager.HasSystemd ? "yes" : "no")}");
        Console.WriteLine($"polkit (pkexec)  : {(manager.HasPolkit ? "yes" : "no")}");
        Console.WriteLine($"service state    : {status.State}{(status.Enabled ? ", enabled" : string.Empty)}{(status.Detail is null ? string.Empty : " (" + status.Detail + ")")}");
        Console.WriteLine($"service exec     : {status.ExecStart ?? "(not installed)"}");
        Console.WriteLine($"daemon found     : {(location is null ? "no" : location.Source.ToString().ToLowerInvariant() + ": " + location.Directory)}");
        if (location is null)
        {
            Console.WriteLine("build it first   : dotnet build src/Yura.Daemon");
            return 1;
        }

        // Under sudo the desktop user is the one who invoked it, not root.
        var uid = Environment.GetEnvironmentVariable("SUDO_UID") is { } sudoUid && uint.TryParse(sudoUid, out var parsed)
            ? parsed
            : CurrentUid();
        var unit = SystemdUnit.Generate(location.ExecStart, uid, IpcProtocol.DefaultSocketPath, location.InHome);
        Console.WriteLine();
        Console.WriteLine("---- unit as installed ----");
        Console.Write(ServiceManager.InstalledUnitText(location, unit));
        Console.WriteLine("---- install script (run with sudo sh) ----");
        Console.Write(ServiceManager.BuildInstallScript(location, unit));
        Console.WriteLine("---- uninstall script ----");
        Console.Write(ServiceManager.BuildUninstallScript());
        return 0;
    }

    private static uint CurrentUid()
    {
        try
        {
            return geteuid();
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return 1000;
        }
    }

    [System.Runtime.InteropServices.DllImport("libc")]
    private static extern uint geteuid();
}
