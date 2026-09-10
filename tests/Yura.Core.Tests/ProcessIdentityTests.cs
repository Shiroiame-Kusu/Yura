using Yura.Core.Processes;

namespace Yura.Core.Tests;

/// <summary>
/// Covers mandatory acceptance test 4: a rule bound to one instance must never reach a
/// later process that happens to reuse the pid.
/// </summary>
public sealed class ProcessIdentityTests
{
    private static ProcessIdentity Identity(int pid = 4821, ulong start = 193847231, uint uid = 1000,
        string boot = "8f14e45f-ceea-467a-9575-1cd0a4f1e2a0") =>
        new() { Pid = pid, StartTicks = start, Uid = uid, BootId = boot };

    [Fact]
    public void Matches_itself()
    {
        var identity = Identity();
        Assert.True(identity.Matches(Identity()));
    }

    [Fact]
    public void A_reused_pid_does_not_match()
    {
        // Same pid, different start time: the kernel handed the number to a new process.
        var original = Identity(pid: 4821, start: 193847231);
        var reused = Identity(pid: 4821, start: 205991044);

        Assert.False(original.Matches(reused));
    }

    [Fact]
    public void A_different_user_does_not_match()
    {
        Assert.False(Identity(uid: 1000).Matches(Identity(uid: 1001)));
    }

    [Fact]
    public void An_identity_from_a_previous_boot_does_not_match()
    {
        // Start ticks are measured from boot, so after a reboot they collide freely.
        var before = Identity(boot: "aaaaaaaa-0000-0000-0000-000000000000");
        var after = Identity(boot: "bbbbbbbb-0000-0000-0000-000000000000");

        Assert.False(before.Matches(after));
    }
}
