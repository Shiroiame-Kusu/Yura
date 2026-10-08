namespace Yura.Daemon.Diagnostics;

/// <summary>
/// A file lines are appended to, moved aside when it grows past a size: name, name.1, name.2.
/// </summary>
/// <remarks>
/// The daemon runs for months, and a game that resolves a name every second writes a line for
/// each, so a log that only grew would end up filling the disk. Not thread-safe:
/// <see cref="DaemonJournal"/> writes from one task.
/// </remarks>
internal sealed class RotatingFile : IDisposable
{
    private readonly long _limit;
    private readonly int _keep;
    private FileStream? _stream;

    /// <param name="limit">Bytes a file may hold before it is moved aside.</param>
    /// <param name="keep">How many moved-aside files are kept beside the current one.</param>
    public RotatingFile(string path, long limit, int keep)
    {
        FilePath = path;
        _limit = limit;
        _keep = keep;
        _stream = Open();
    }

    public string FilePath { get; }

    public void Append(ReadOnlySpan<byte> line)
    {
        _stream ??= Open();
        if (_stream.Length > 0 && _stream.Length + line.Length + 1 > _limit)
        {
            Rotate();
        }

        _stream.Write(line);
        _stream.WriteByte((byte)'\n');
    }

    public void Flush() => _stream?.Flush();

    public void Dispose()
    {
        _stream?.Flush();
        _stream?.Dispose();
        _stream = null;
    }

    private FileStream Open()
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.Append,
            Access = FileAccess.Write,
            Share = FileShare.Read | FileShare.Delete,
        };
        if (!OperatingSystem.IsWindows())
        {
            // Readable by its owner and group only: it names every destination the routed programs reached.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead;
        }

        return new FileStream(FilePath, options);
    }

    private void Rotate()
    {
        _stream!.Flush();
        _stream.Dispose();
        _stream = null;
        for (var i = _keep - 1; i >= 1; i--)
        {
            var older = $"{FilePath}.{i}";
            if (File.Exists(older))
            {
                File.Move(older, $"{FilePath}.{i + 1}", overwrite: true);
            }
        }

        File.Move(FilePath, $"{FilePath}.1", overwrite: true);
        _stream = Open();
    }
}
