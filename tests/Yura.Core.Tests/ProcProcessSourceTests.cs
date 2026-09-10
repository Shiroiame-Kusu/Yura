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
    public void Connection_count_is_null_not_zero_when_unavailable()
    {
        // The unprivileged /proc reader does not own socket attribution; reporting 0 would
        // be indistinguishable from "this process genuinely has no connections".
        var source = new ProcProcessSource();
        Assert.All(source.Enumerate(), p => Assert.Null(p.ConnectionCount));
    }
}
