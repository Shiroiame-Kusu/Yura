using System.Runtime.InteropServices;

namespace Yura.Agent;

/// <summary>
/// Who owns a file, and handing a file to the owner of its directory, which .NET has no API for.
/// </summary>
/// <remarks>
/// The service runs as a user systemd allocates, and its state directory belongs to that user.
/// A file root writes there from the command line, such as a token from <c>rotate</c>, belongs
/// to root, mode 0600, so the service cannot read it once it next starts. systemd does not put
/// that right: it fixes ownership only when the directory itself has the wrong owner, which here
/// it never does. The agent then fails at every start until someone notices.
/// </remarks>
internal static class FileOwnership
{
    private const int CurrentDirectory = -100; // AT_FDCWD
    private const uint WantUid = 0x8;          // STATX_UID
    private const uint WantGid = 0x10;         // STATX_GID

    /// <summary>The owner of a file or directory, following symbolic links; null if unknown.</summary>
    public static (uint Uid, uint Gid)? Of(string path)
    {
        // struct statx, unlike struct stat, has the same layout on every architecture: 256 bytes,
        // with stx_uid at offset 20 and stx_gid at offset 24.
        var buffer = new byte[256];
        try
        {
            if (statx(CurrentDirectory, path, 0, WantUid | WantGid, buffer) != 0)
            {
                return null;
            }
        }
        catch (Exception e) when (e is EntryPointNotFoundException or DllNotFoundException)
        {
            return null;
        }

        return (BitConverter.ToUInt32(buffer, 20), BitConverter.ToUInt32(buffer, 24));
    }

    /// <summary>
    /// Gives <paramref name="path"/> to the owner of <paramref name="directory"/>, when this
    /// process is root and they differ. Anyone else creates files as themselves anyway.
    /// </summary>
    public static void MatchDirectory(string path, string directory)
    {
        if (!Environment.IsPrivilegedProcess || Of(directory) is not { } owner)
        {
            return;
        }

        if (Of(path) is not { } current || current != owner)
        {
            Give(path, owner);
        }
    }

    /// <summary>
    /// Gives every file in <paramref name="directory"/> to the directory's owner, when this
    /// process is root. Puts right what an earlier version left owned by root.
    /// </summary>
    /// <returns>How many files changed hands.</returns>
    public static int Repair(string directory)
    {
        if (!Environment.IsPrivilegedProcess || !Directory.Exists(directory) || Of(directory) is not { } owner)
        {
            return 0;
        }

        var repaired = 0;
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            if (Of(file) is not { } current || current != owner)
            {
                Give(file, owner);
                repaired++;
            }
        }

        return repaired;
    }

    private static void Give(string path, (uint Uid, uint Gid) owner)
    {
        if (chown(path, owner.Uid, owner.Gid) != 0)
        {
            throw new IOException(
                $"could not give {path} to {owner.Uid}:{owner.Gid} (errno {Marshal.GetLastPInvokeError()})");
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int statx(
        int directoryFd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, byte[] buffer);

    [DllImport("libc", SetLastError = true)]
    private static extern int chown([MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint owner, uint group);
}
