using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Processes;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// Keeping the daemon in step with the app when the daemon comes, goes, or restarts.
/// </summary>
/// <remarks>
/// The daemon keeps nothing across a restart, and nothing listened for one: a daemon restarted
/// by an upgrade, or by systemd after a crash, was handed no proxies and no rules until someone
/// pressed Reconnect, while every page went on calling the rules active.
/// </remarks>
public sealed class ShellDaemonSyncTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("yura-shell-tests-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private ShellViewModel New(RecordingDaemonClient daemon) =>
        new(daemon, new InMemorySecretStore(), new ConfigStore(_directory), new SimulatedServiceManager());

    private static RoutingRule Saved() => new()
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

    private static RoutingRule Temporary() => Saved() with
    {
        Id = Guid.NewGuid(),
        Name = "curl, this run",
        Lifetime = RuleLifetime.Instance,
        Process = new ProcessSelector
        {
            Kind = ProcessSelectorKind.Instance,
            Identity = new ProcessIdentity { Pid = 4242, StartTicks = 9, Uid = 1000, BootId = "b" },
        },
    };

    [Fact]
    public async Task A_daemon_that_restarted_is_handed_its_rules_again()
    {
        var daemon = new RecordingDaemonClient();
        using var shell = New(daemon);
        var rule = Saved();
        shell.Rules.Add(rule);
        await shell.RefreshDaemonStateAsync();
        Assert.NotNull(Assert.Single(shell.Rules.Rules).AppliedAtUtc);

        // A new run of the daemon holds nothing, and says so only by being a new run.
        daemon.Applied.Clear();
        daemon.Installed.Clear();
        daemon.RaiseInstanceChanged();

        Assert.Equal(rule.Id, Assert.Single(daemon.Applied).Rule.Id);
        Assert.Equal(rule.Id, Assert.Single(daemon.Installed).Id);
        Assert.NotNull(Assert.Single(shell.Rules.Rules).AppliedAtUtc);
    }

    [Fact]
    public async Task Rules_read_as_pending_while_the_daemon_is_away_and_are_pushed_when_it_returns()
    {
        var daemon = new RecordingDaemonClient();
        using var shell = New(daemon);
        var rule = Saved();
        shell.Rules.Add(rule);
        await shell.RefreshDaemonStateAsync();

        daemon.RaiseStateChanged(DaemonState.Disconnected);

        Assert.False(shell.IsDaemonConnected);
        Assert.NotNull(shell.DaemonBannerDetail);
        Assert.Null(Assert.Single(shell.Rules.Rules).AppliedAtUtc);

        daemon.Applied.Clear();
        daemon.RaiseStateChanged(DaemonState.Connecting);
        daemon.RaiseStateChanged(DaemonState.Connected);

        Assert.True(shell.IsDaemonConnected);
        Assert.Equal(rule.Id, Assert.Single(daemon.Applied).Rule.Id);
        Assert.NotNull(Assert.Single(shell.Rules.Rules).AppliedAtUtc);
    }

    [Fact]
    public async Task A_push_the_daemon_never_received_does_not_drop_a_temporary_rule()
    {
        var daemon = new RecordingDaemonClient();
        using var shell = New(daemon);
        shell.Rules.Add(Temporary());
        await shell.RefreshDaemonStateAsync();

        // Gone again before it answered: that says nothing about the rule.
        daemon.NextApplyResult = new RuleApplyResult
        {
            Succeeded = false, Answered = false, FailureReason = "Could not reach the daemon.",
        };
        daemon.RaiseStateChanged(DaemonState.Disconnected);
        daemon.RaiseStateChanged(DaemonState.Connected);

        Assert.Single(shell.Rules.Rules);

        // A daemon that answered no is another matter: the process the rule was for is gone.
        daemon.NextApplyResult = new RuleApplyResult { Succeeded = false, FailureReason = "No such process." };
        daemon.RaiseStateChanged(DaemonState.Disconnected);
        daemon.RaiseStateChanged(DaemonState.Connected);

        Assert.Empty(shell.Rules.Rules);
    }

    [Fact]
    public async Task A_rule_the_daemon_holds_and_the_app_does_not_is_taken_out()
    {
        var daemon = new RecordingDaemonClient();
        var stray = Guid.NewGuid();
        daemon.Installed.Add((stray, "left over"));
        using var shell = New(daemon);

        await shell.RefreshDaemonStateAsync();

        Assert.Contains(stray, daemon.Removed);
        Assert.Empty(daemon.Installed);
        Assert.Contains("left over", shell.ConfigWarning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_saved_theme_survives_a_launch_that_names_none()
    {
        // The command line's defaults were applied after the configuration was loaded, so every
        // launch came up dark and then saved dark over the user's choice.
        await new ConfigStore(_directory).SaveAsync(new ConfigSnapshot
        {
            Settings = new PersistedSettings { Theme = "light" },
            Proxies = [],
            Rules = [],
            Chains = [],
            Games = [],
        }, TestContext.Current.CancellationToken);
        using var shell = New(new RecordingDaemonClient());
        Assert.False(shell.IsDarkTheme);

        shell.ApplyStartupOverrides(dark: null, chinese: null);
        Assert.False(shell.IsDarkTheme);

        // Named on the command line, it applies to this launch.
        shell.ApplyStartupOverrides(dark: true, chinese: null);
        Assert.True(shell.IsDarkTheme);
    }
}
