using System.Collections.Concurrent;
using Yura.Core.Connections;

namespace Yura.Daemon.Forwarding;

/// <summary>Every flow the daemon has handled recently, live or finished.</summary>
/// <remarks>
/// Finished flows are kept briefly so the Connections page can show a failure reason
/// after the fact instead of the row simply vanishing.
///
/// Pruning happens as flows arrive and as they are counted, not only when someone lists them:
/// the daemon runs as a service with the app closed for days at a time, and a registry that
/// only shrank while a page was watching it grew by one entry for every connection and every
/// DNS lookup it relayed in between.
/// </remarks>
public sealed class FlowRegistry
{
    private static readonly TimeSpan Retention = TimeSpan.FromSeconds(60);

    /// <summary>
    /// A flow still setting up after this long never will: every step of setting one up has a
    /// timeout of its own well inside it. Kept past this, it would sit in the list as a
    /// connection being established forever.
    /// </summary>
    private static readonly TimeSpan SetupLimit = TimeSpan.FromMinutes(2);

    /// <summary>Finished flows kept at most, whatever their age, so a burst cannot outgrow the retention.</summary>
    private const int MaxFinished = 4096;

    private static readonly TimeSpan PruneEvery = TimeSpan.FromSeconds(5);

    private readonly ConcurrentDictionary<long, Flow> _flows = new();
    private readonly TimeProvider _time;
    private long _lastPruneAt;

    public FlowRegistry(TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
        _lastPruneAt = _time.GetTimestamp();
    }

    /// <summary>Told of every flow added from now on, when it is established and when it ends.</summary>
    public IFlowObserver? Observer { get; init; }

    public void Add(Flow flow)
    {
        flow.Observer ??= Observer;
        _flows[flow.Id] = flow;
        PruneIfDue();
    }

    public IReadOnlyList<Flow> Snapshot()
    {
        Prune();
        return _flows.Values.OrderBy(f => f.CreatedAtUtc).ToArray();
    }

    public int ActiveCount
    {
        get
        {
            PruneIfDue();
            return _flows.Values.Count(f => f.State is ConnectionState.Establishing or ConnectionState.Established);
        }
    }

    /// <summary>Flows held right now, finished ones included. For tests and diagnostics.</summary>
    public int Count => _flows.Count;

    private void PruneIfDue()
    {
        var now = _time.GetTimestamp();
        var last = Interlocked.Read(ref _lastPruneAt);
        if (_time.GetElapsedTime(last, now) < PruneEvery ||
            Interlocked.CompareExchange(ref _lastPruneAt, now, last) != last)
        {
            return;
        }

        Prune();
    }

    private void Prune()
    {
        var now = _time.GetUtcNow();
        var finished = new List<Flow>();
        foreach (var (id, flow) in _flows)
        {
            if (flow.ClosedAtUtc is { } closed)
            {
                // Aged from when it ended, not when it started: a download that ran for an hour
                // and then failed still gets its minute on the page.
                if (now - closed > Retention)
                {
                    _flows.TryRemove(id, out _);
                }
                else
                {
                    finished.Add(flow);
                }
            }
            else if (flow.State == ConnectionState.Establishing && now - flow.CreatedAtUtc > SetupLimit)
            {
                _flows.TryRemove(id, out _);
            }
        }

        if (finished.Count > MaxFinished)
        {
            foreach (var flow in finished.OrderBy(f => f.ClosedAtUtc).Take(finished.Count - MaxFinished))
            {
                _flows.TryRemove(flow.Id, out _);
            }
        }
    }
}
