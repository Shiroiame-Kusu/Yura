using System.Collections.Concurrent;

namespace Yura.Daemon.Forwarding;

/// <summary>Every flow the daemon has handled recently, live or finished.</summary>
/// <remarks>
/// Finished flows are kept briefly so the Connections page can show a failure reason
/// after the fact instead of the row simply vanishing.
/// </remarks>
public sealed class FlowRegistry
{
    private static readonly TimeSpan Retention = TimeSpan.FromSeconds(60);
    private readonly ConcurrentDictionary<long, Flow> _flows = new();

    public void Add(Flow flow) => _flows[flow.Id] = flow;

    public IReadOnlyList<Flow> Snapshot()
    {
        Prune();
        return _flows.Values.OrderBy(f => f.CreatedAtUtc).ToArray();
    }

    public int ActiveCount => _flows.Values.Count(f =>
        f.State is Core.Connections.ConnectionState.Establishing or Core.Connections.ConnectionState.Established);

    private void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow - Retention;
        foreach (var (id, flow) in _flows)
        {
            if (flow.State is Core.Connections.ConnectionState.Closed or Core.Connections.ConnectionState.Failed &&
                flow.CreatedAtUtc < cutoff)
            {
                _flows.TryRemove(id, out _);
            }
        }
    }
}
