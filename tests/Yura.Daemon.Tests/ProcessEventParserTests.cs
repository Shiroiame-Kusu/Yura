using System.Buffers.Binary;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Tests;

/// <summary>
/// The netlink wire layout is fixed by the kernel's <c>cn_proc.h</c>; these build datagrams
/// the way the kernel does and check that fork, exec and exit come out right, and that
/// thread events do not masquerade as process events.
/// </summary>
public sealed class ProcessEventParserTests
{
    private static byte[] Message(uint what, params int[] payload)
    {
        // nlmsghdr(16) + cn_msg(20) + proc_event header(16) + payload
        var length = 16 + 20 + 16 + payload.Length * 4;
        var buffer = new byte[(length + 3) & ~3];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(4), 3); // NLMSG_DONE
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(36), what);
        for (var i = 0; i < payload.Length; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(52 + i * 4), payload[i]);
        }

        return buffer;
    }

    [Fact]
    public void A_fork_of_a_new_process_yields_parent_and_child_tgids()
    {
        var events = ProcessEventWatcher.Parse(Message(0x1, /*parent_pid*/ 100, /*parent_tgid*/ 100, /*child_pid*/ 200, /*child_tgid*/ 200));

        var evt = Assert.Single(events);
        Assert.Equal(ProcessEventKind.Fork, evt.Kind);
        Assert.Equal(100, evt.Pid);
        Assert.Equal(200, evt.ChildPid);
    }

    [Fact]
    public void A_new_thread_is_not_a_fork()
    {
        // child_pid != child_tgid: a thread of process 100.
        var events = ProcessEventWatcher.Parse(Message(0x1, 100, 100, 201, 100));

        Assert.Empty(events);
    }

    [Fact]
    public void Exec_and_exit_are_reported_for_the_thread_group_leader_only()
    {
        var exec = ProcessEventWatcher.Parse(Message(0x2, 300, 300));
        Assert.Equal(ProcessEventKind.Exec, Assert.Single(exec).Kind);
        Assert.Equal(300, exec[0].Pid);

        var exit = ProcessEventWatcher.Parse(Message(0x80000000, 300, 300, 7, 0));
        Assert.Equal(ProcessEventKind.Exit, Assert.Single(exit).Kind);
        Assert.Equal(7, exit[0].ExitCode);

        var threadExit = ProcessEventWatcher.Parse(Message(0x80000000, 301, 300, 0, 0));
        Assert.Empty(threadExit);
    }

    [Fact]
    public void Several_messages_in_one_datagram_are_all_read()
    {
        var datagram = Message(0x1, 1, 1, 2, 2).Concat(Message(0x2, 2, 2)).Concat(Message(0x4, 2, 2)).ToArray();

        var events = ProcessEventWatcher.Parse(datagram);

        Assert.Equal(2, events.Count);
        Assert.Equal(ProcessEventKind.Fork, events[0].Kind);
        Assert.Equal(ProcessEventKind.Exec, events[1].Kind);
    }

    [Fact]
    public void A_truncated_datagram_does_not_throw()
    {
        var events = ProcessEventWatcher.Parse(Message(0x1, 1, 1, 2, 2).AsSpan(0, 40));

        Assert.Empty(events);
    }
}
