using Yura.Core.Processes;

namespace Yura.Core.Tests;

/// <summary>
/// Exercises the /proc reader against the live process table of the machine running the
/// tests. These are deliberately not mocked: the failure modes worth catching here are the
/// ones real /proc produces — processes exiting mid-read, unreadable links, and comm names
/// containing spaces and parentheses.
/// </summary>
public sealed class ProcProcessSourceTests
{
    [Fact]
    public void Enumerates_the_live_process_table()
    {
        var source = new ProcProcessSource();
        var processes = source.Enumerate();

        Assert.NotEmpty(processes);

        // Whatever else is running, the test host itself must be in there.
        var self = processes.SingleOrDefault(p => p.Identity.Pid == Environment.ProcessId);
        Assert.NotNull(self);
        Assert.Equal(ExecutablePathState.Resolved, self.ExecutablePathState);
        Assert.NotNull(self.ExecutablePath);
        Assert.True(self.Identity.StartTicks > 0, "start ticks must be populated for instance identity");
    }

    [Fact]
    public void Boot_id_is_stable_and_shared_by_every_snapshot()
    {
        var source = new ProcProcessSource();
        var processes = source.Enumerate();

        Assert.NotEqual("unknown-boot", source.BootId);
        Assert.All(processes, p => Assert.Equal(source.BootId, p.Identity.BootId));
    }

    [Fact]
    public void Reading_a_pid_that_does_not_exist_returns_null_rather_than_throwing()
    {
        var source = new ProcProcessSource();

        // Above the configured pid_max, so it can never exist.
        Assert.Null(source.TryRead(int.MaxValue));
    }

    [Fact]
    public void Comm_names_containing_spaces_are_parsed_without_corrupting_later_fields()
    {
        var source = new ProcProcessSource();
        var processes = source.Enumerate(includeKernelThreads: true);

        // Kernel worker threads are routinely named things like "kworker/u32:1-events".
        // If the stat parser split on whitespace instead of anchoring on the last ')', the
        // parent pid and start time of any process with a space in its name would be junk.
        var awkward = processes.Where(p => p.Name.Contains(' ', StringComparison.Ordinal)).ToList();
        Assert.All(awkward, p =>
        {
            Assert.True(p.Identity.StartTicks > 0);
            Assert.True(p.ParentPid >= 0);
        });
    }

    [Fact]
    public void Unreadable_processes_report_why_rather_than_showing_a_blank_path()
    {
        var source = new ProcProcessSource();
        var processes = source.Enumerate(includeKernelThreads: true);

        // Every snapshot must carry a state that explains a missing path. A null path with
        // a Resolved state would mean the UI has nothing honest to display.
        Assert.All(processes, p =>
        {
            if (p.ExecutablePath is null)
            {
                Assert.NotEqual(ExecutablePathState.Resolved, p.ExecutablePathState);
            }
        });
    }

    [Fact]
    public void Every_process_has_a_user_name_even_when_passwd_lookup_fails()
    {
        var source = new ProcProcessSource();
        Assert.All(source.Enumerate(), p => Assert.False(string.IsNullOrWhiteSpace(p.UserName)));
    }

    [Fact]
    public void The_environment_is_read_only_when_asked_for_and_the_wine_target_never_needs_it()
    {
        // The daemon rescans every process every two seconds, and reading each one's environment
        // costs a file per process. It reads them only while a rule matches on a Wine prefix,
        // which is the one thing that lives there; the Windows executable a game rule matches
        // comes from the command line and must be found either way.
        // A shell that stays alive with a Windows executable on its command line; the trailing
        // ':' stops it handing itself over to sleep.
        var start = new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-c", "sleep 30; :", "Game.exe"])
        {
            UseShellExecute = false,
        };
        start.Environment["SteamAppId"] = "1245620";
        start.Environment["WINEPREFIX"] = "/tmp/yura-test-prefix";
        using var child = System.Diagnostics.Process.Start(start)!;
        try
        {
            var read = new ProcProcessSource().TryRead(child.Id);
            var unread = new ProcProcessSource { ReadEnvironment = false }.TryRead(child.Id);

            Assert.NotNull(read);
            Assert.NotNull(unread);
            Assert.Equal("1245620", read.SteamAppId);
            Assert.Equal("/tmp/yura-test-prefix", read.Wine?.Prefix);
            Assert.Null(unread.SteamAppId);
            Assert.Null(unread.Wine?.Prefix);
            Assert.Equal("Game.exe", read.Wine?.TargetExecutable);
            Assert.Equal("Game.exe", unread.Wine?.TargetExecutable);
        }
        finally
        {
            child.Kill(entireProcessTree: true);
        }
    }

    [Fact]
    public void Connection_count_is_null_not_zero_when_unavailable()
    {
        // The unprivileged /proc reader does not own socket attribution; reporting 0 would
        // be indistinguishable from "this process genuinely has no connections".
        var source = new ProcProcessSource();
        Assert.All(source.Enumerate(), p => Assert.Null(p.ConnectionCount));
    }
}
