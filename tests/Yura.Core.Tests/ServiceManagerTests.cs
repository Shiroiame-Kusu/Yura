using Yura.App.Services;

namespace Yura.Core.Tests;

/// <summary>
/// The unit and the install script are what the user is shown before anything runs as
/// root, so their exact text is worth pinning: the hardening, the paths, and the quoting.
/// </summary>
public sealed class ServiceManagerTests
{
    private const string Exec = "/usr/share/dotnet/dotnet /home/someone/src/Yura/src/Yura.Daemon/bin/Debug/net10.0/yura-daemon.dll";

    [Fact]
    public void The_unit_runs_the_daemon_for_the_desktop_user_with_home_removed()
    {
        var unit = SystemdUnit.Generate(Exec, 1000, "/run/yura/yura.sock", daemonInHome: false);

        Assert.Contains($"ExecStart={Exec} --socket /run/yura/yura.sock --allow-uid 1000\n", unit);
        Assert.Contains("ProtectHome=yes\n", unit);
        Assert.Contains("ProtectSystem=strict\n", unit);
        Assert.Contains("RuntimeDirectory=yura\n", unit);
        Assert.Contains("Environment=HOME=/run/yura", unit);
        Assert.Contains("NoNewPrivileges=yes\n", unit);
        Assert.Contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n", unit);
        Assert.Contains("WantedBy=multi-user.target\n", unit);
        // The daemon writes to /proc/sys and /sys/fs/cgroup, which these would forbid.
        Assert.DoesNotContain("ProtectKernelTunables", unit);
        Assert.DoesNotContain("ProtectControlGroups", unit);
    }

    [Fact]
    public void A_daemon_that_lives_in_a_home_directory_only_gets_read_access_to_it()
    {
        var unit = SystemdUnit.Generate(Exec, 1000, "/run/yura/yura.sock", daemonInHome: true);

        Assert.Contains("ProtectHome=read-only\n", unit);
        Assert.DoesNotContain("ProtectHome=yes", unit);
    }

    [Fact]
    public void Installing_copies_the_daemon_out_of_home_and_then_protects_home_fully()
    {
        var location = new DaemonLocation(Exec, "/home/someone/src/Yura/src/Yura.Daemon/bin/Debug/net10.0", DaemonSource.Development, InHome: true);
        var unit = SystemdUnit.Generate(Exec, 1000, "/run/yura/yura.sock", daemonInHome: true);

        var script = ServiceManager.BuildInstallScript(location, unit);

        Assert.Contains("cp -a '/home/someone/src/Yura/src/Yura.Daemon/bin/Debug/net10.0/.' '/usr/local/lib/yura/daemon'/", script);
        Assert.Contains("ExecStart=/usr/share/dotnet/dotnet /usr/local/lib/yura/daemon/yura-daemon.dll --socket", script);
        Assert.Contains("ProtectHome=yes\n", script);
        Assert.DoesNotContain("ProtectHome=read-only", script);
        Assert.Contains("systemctl enable --now yura-daemon.service", script);
        Assert.Contains("cat > '/etc/systemd/system/yura-daemon.service' <<'YURA_UNIT'", script);

        var installed = ServiceManager.InstalledUnitText(location, unit);
        Assert.Contains("/usr/local/lib/yura/daemon/yura-daemon.dll", installed);
        Assert.DoesNotContain("/home/someone", installed);
    }

    [Fact]
    public void Paths_with_quotes_and_spaces_are_quoted_for_the_shell()
    {
        Assert.Equal("'/tmp/it'\\''s here/x y'", ServiceManager.Quote("/tmp/it's here/x y"));

        var location = new DaemonLocation("/opt/y d/yura-daemon", "/opt/y d", DaemonSource.Explicit, InHome: false);
        var script = ServiceManager.BuildInstallScript(location, SystemdUnit.Generate("/opt/y d/yura-daemon", 1000, "/run/yura/yura.sock", false));
        Assert.Contains("cp -a '/opt/y d/.'", script);
    }

    [Fact]
    public void Uninstalling_removes_exactly_what_installing_created()
    {
        var script = ServiceManager.BuildUninstallScript();

        Assert.Contains("systemctl disable --now yura-daemon.service", script);
        Assert.Contains("rm -f '/etc/systemd/system/yura-daemon.service'", script);
        Assert.Contains("rm -rf '/usr/local/lib/yura/daemon'", script);
        Assert.Contains("systemctl daemon-reload", script);
    }
}
