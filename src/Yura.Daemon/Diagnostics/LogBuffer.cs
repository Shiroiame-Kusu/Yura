namespace Yura.Daemon.Diagnostics;

/// <summary>
/// The daemon's recent log lines, kept in memory so the app's Diagnostics page can show
/// them without the daemon writing anywhere on disk.
/// </summary>
public sealed class LogBuffer
{
    private readonly int _capacity;
    private readonly Queue<string> _lines;
    private readonly object _lock = new();

    public LogBuffer(int capacity = 1000)
    {
        _capacity = capacity;
        _lines = new Queue<string>(capacity);
    }

    public void Append(string line)
    {
        lock (_lock)
        {
            if (_lines.Count == _capacity)
            {
                _lines.Dequeue();
            }

            _lines.Enqueue(line);
        }
    }

    public IReadOnlyList<string> Tail(int count)
    {
        lock (_lock)
        {
            return _lines.TakeLast(Math.Max(0, count)).ToArray();
        }
    }
}
