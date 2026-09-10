using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>Which processes the user wants to see.</summary>
public enum ProcessFilterScope
{
    /// <summary>Processes owned by the signed-in user. The useful default.</summary>
    MyProcesses,

    /// <summary>Everything, including root and system service processes.</summary>
    AllProcesses,
}

/// <summary>The Processes page: the primary general-purpose entry point.</summary>
public sealed partial class ProcessesPageViewModel : ObservableObject, IDisposable
{
    private readonly ProcProcessSource _source;
    private readonly IDaemonClient _daemon;
    private readonly RuleStore _rules;
    private readonly Dictionary<string, ProcessRowViewModel> _rows = [];
    private readonly DispatcherTimer _timer;
    private readonly uint _currentUid;
    private IReadOnlyDictionary<int, int>? _connectionCounts;
    private bool _countsInFlight;

    public ProcessesPageViewModel(ProcProcessSource source, IDaemonClient daemon, RuleStore rules)
    {
        _source = source;
        _daemon = daemon;
        _rules = rules;
        _currentUid = ParseUid();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => Refresh();

        Refresh();
        _timer.Start();
    }

    private static uint ParseUid()
    {
        // Environment.UserName is not enough: we need the numeric uid to compare against
        // /proc. Reading it from our own status file avoids a P/Invoke.
        try
        {
            foreach (var line in File.ReadLines("/proc/self/status"))
            {
                if (line.StartsWith("Uid:", StringComparison.Ordinal))
                {
                    var parts = line[4..].Split('\t', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0 && uint.TryParse(parts[0].Trim(), out var uid))
                    {
                        return uid;
                    }
                }
            }
        }
        catch (IOException)
        {
            // Fall through.
        }

        return 1000;
    }

    /// <summary>The filtered, ordered rows the table binds to.</summary>
    public ObservableCollection<ProcessRowViewModel> Processes { get; } = [];

    public ObservableCollection<ProxyEndpoint> AvailableProxies => _rules.Proxies;

    [ObservableProperty]
    public partial string SearchText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial ProcessFilterScope FilterScope { get; set; } = ProcessFilterScope.MyProcesses;

    /// <summary>
    /// When paused, the table stops taking updates entirely. Explicit control over live
    /// updates is required: a table that reorders itself mid-click is unusable.
    /// </summary>
    [ObservableProperty]
    public partial bool IsPaused { get; set; }

    /// <summary>
    /// When off, rows keep their position even if their sort key changes. New rows are
    /// still inserted in order.
    /// </summary>
    [ObservableProperty]
    public partial bool LiveSorting { get; set; }

    [ObservableProperty]
    public partial ProcessRowViewModel? SelectedProcess { get; set; }

    [ObservableProperty]
    public partial RuleScopeChoice ScopeChoice { get; set; } = RuleScopeChoice.Instance;

    [ObservableProperty]
    public partial ProxyEndpoint? SelectedProxy { get; set; }

    /// <summary>Set after a rule is applied, describing exactly what changed and what did not.</summary>
    [ObservableProperty]
    public partial AppliedRuleNotice? LastApplied { get; set; }

    [ObservableProperty]
    public partial string? ErrorMessage { get; set; }

    [ObservableProperty]
    public partial string? ErrorDiagnostics { get; set; }

    [ObservableProperty]
    public partial bool IsApplying { get; set; }

    public bool HasSelection => SelectedProcess is not null;

    /// <summary>
    /// True when the window is too narrow to dock the inspector beside the table.
    /// </summary>
    /// <remarks>
    /// Set by the view from its own bounds rather than from the window's, so the threshold
    /// stays correct whatever the navigation sidebar's width happens to be.
    /// </remarks>
    [ObservableProperty]
    public partial bool IsCompact { get; set; }

    /// <summary>The inspector floats only when it is needed and cannot be docked.</summary>
    public bool ShowOverlayInspector => IsCompact && HasSelection;

    public bool CanApply => SelectedProcess is not null && !IsApplying;

    /// <summary>
    /// Explains why Apply is unavailable, shown next to the control rather than as a
    /// tooltip, so the reason is visible without hovering.
    /// </summary>
    public string? ApplyBlockedReason
    {
        get
        {
            if (SelectedProcess is null)
            {
                return Loc.Current["Processes.Inspector.NoSelection"];
            }

            if (_daemon.State != DaemonState.Connected)
            {
                return _daemon.UnavailableReason;
            }

            return null;
        }
    }

    public int TotalProcessCount => _rows.Count;

    public int VisibleProcessCount => Processes.Count;

    /// <summary>
    /// "42 of 727 processes" when filtered, "727 processes" when not. Showing only the
    /// filtered number would hide that a filter is hiding things.
    /// </summary>
    public string CountSummary => VisibleProcessCount == TotalProcessCount
        ? string.Format(System.Globalization.CultureInfo.CurrentCulture,
            Loc.Current["Processes.Count"], TotalProcessCount)
        : string.Format(System.Globalization.CultureInfo.CurrentCulture,
            Loc.Current["Processes.CountFiltered"], VisibleProcessCount, TotalProcessCount);

    public bool IsEmpty => Processes.Count == 0;

    // -- refresh ------------------------------------------------------------

    [RelayCommand]
    public void Refresh()
    {
        if (IsPaused)
        {
            return;
        }

        var snapshots = _source.Enumerate();
        var seen = new HashSet<string>(snapshots.Count);

        // Only the daemon can attribute sockets to processes it does not own. With no daemon —
        // or before its first answer has arrived — the count is genuinely unknown, and null
        // renders as "—" rather than a misleading 0.
        var counts = _daemon.State == DaemonState.Connected ? _connectionCounts : null;

        foreach (var raw in snapshots)
        {
            var snapshot = counts is null
                ? raw
                : raw with { ConnectionCount = counts.GetValueOrDefault(raw.Identity.Pid) };

            var key = ProcessRowViewModel.MakeKey(snapshot.Identity);
            seen.Add(key);

            if (_rows.TryGetValue(key, out var existing))
            {
                existing.Update(snapshot);
            }
            else
            {
                _rows[key] = new ProcessRowViewModel(snapshot);
            }
        }

        // Drop rows whose process exited. Their instance rules expire with them; a later
        // process reusing the pid gets a different key and therefore a different row.
        foreach (var key in _rows.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            _rows.Remove(key);
            _rules.ExpireInstanceRulesFor(key);
        }

        ApplyPolicies();
        RebuildView();

        // Fetched out of band: the table must not stall on a daemon round trip, and a
        // count that is one refresh stale is better than a list that stutters.
        _ = RefreshConnectionCountsAsync();
    }

    private async Task RefreshConnectionCountsAsync()
    {
        if (_countsInFlight || _daemon.State != DaemonState.Connected)
        {
            return;
        }

        _countsInFlight = true;
        try
        {
            _connectionCounts = await _daemon.GetConnectionCountsAsync().ConfigureAwait(true);
        }
        catch (Exception)
        {
            // A daemon that went away mid-refresh is not an error worth surfacing here;
            // the column reverts to "unknown" rather than claiming zero.
            _connectionCounts = null;
        }
        finally
        {
            _countsInFlight = false;
        }
    }

    private void ApplyPolicies()
    {
        RefreshCoveringRules();

        foreach (var row in _rows.Values)
        {
            var (kind, detail) = _rules.DescribePolicy(row.Snapshot);
            row.Policy = kind;
            row.PolicyDetail = detail;
        }
    }

    private void RebuildView()
    {
        var desired = _rows.Values
            .Where(PassesScope)
            .Where(r => r.MatchesFilter(SearchText))
            .OrderBy(r => r.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(r => r.Pid)
            .ToList();

        var desiredKeys = new HashSet<string>(desired.Select(r => r.Key));

        // Remove departed rows first, back to front so indices stay valid.
        for (var i = Processes.Count - 1; i >= 0; i--)
        {
            if (!desiredKeys.Contains(Processes[i].Key))
            {
                Processes.RemoveAt(i);
            }
        }

        if (LiveSorting)
        {
            // The user asked for the order to track the data, so reconcile fully.
            for (var i = 0; i < desired.Count; i++)
            {
                if (i >= Processes.Count)
                {
                    Processes.Add(desired[i]);
                }
                else if (!ReferenceEquals(Processes[i], desired[i]))
                {
                    var currentIndex = Processes.IndexOf(desired[i]);
                    if (currentIndex >= 0)
                    {
                        Processes.Move(currentIndex, i);
                    }
                    else
                    {
                        Processes.Insert(i, desired[i]);
                    }
                }
            }
        }
        else
        {
            // Live sorting off: existing rows never move. New rows are inserted where they
            // belong so the list still reads as sorted, but nothing shifts under the pointer.
            var present = new HashSet<string>(Processes.Select(r => r.Key));
            for (var i = 0; i < desired.Count; i++)
            {
                if (present.Contains(desired[i].Key))
                {
                    continue;
                }

                var insertAt = Math.Min(i, Processes.Count);
                Processes.Insert(insertAt, desired[i]);
            }
        }

        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(TotalProcessCount));
        OnPropertyChanged(nameof(VisibleProcessCount));
        OnPropertyChanged(nameof(CountSummary));
    }

    private bool PassesScope(ProcessRowViewModel row) => FilterScope switch
    {
        ProcessFilterScope.MyProcesses => row.Snapshot.Identity.Uid == _currentUid,
        _ => true,
    };

    partial void OnSearchTextChanged(string value) => RebuildView();

    partial void OnFilterScopeChanged(ProcessFilterScope value) => RebuildView();

    partial void OnLiveSortingChanged(bool value)
    {
        if (value)
        {
            RebuildView();
        }
    }

    partial void OnIsPausedChanged(bool value)
    {
        if (!value)
        {
            Refresh();
        }
    }

    /// <summary>Every rule covering the selected process, in evaluation order.</summary>
    public ObservableCollection<CoveringRule> CoveringRules { get; } = [];

    public bool HasCoveringRules => CoveringRules.Count > 0;

    private void RefreshCoveringRules()
    {
        CoveringRules.Clear();
        if (SelectedProcess is not { } row)
        {
            OnPropertyChanged(nameof(HasCoveringRules));
            return;
        }

        var covering = _rules.RulesFor(row.Snapshot);
        for (var i = 0; i < covering.Count; i++)
        {
            var rule = covering[i];
            var routeName = rule.Action switch
            {
                RuleAction.Proxy p => _rules.RouteName(p.EndpointId),
                RuleAction.Chain c => _rules.RouteName(c.ChainId),
                _ => null,
            };
            var detail = rule.Destination.IsUnconstrained
                ? Localization.RuleDescriber.Route(rule.Action, routeName)
                : $"{Localization.RuleDescriber.Destination(rule.Destination)} ⇒ {Localization.RuleDescriber.Route(rule.Action, routeName)}";
            CoveringRules.Add(new CoveringRule(
                rule.Order.ToString(System.Globalization.CultureInfo.CurrentCulture),
                rule.Name,
                detail,
                // Only the first enabled one decides anything; the rest are shadowed.
                IsWinner: rule.Enabled && covering.Take(i).All(r => !r.Enabled)));
        }

        OnPropertyChanged(nameof(HasCoveringRules));
    }

    /// <summary>
    /// Raised when the user asks to see a process's connections. The shell switches page and
    /// filters, rather than this page reaching into another one.
    /// </summary>
    public event EventHandler<ProcessSnapshot>? InspectConnectionsRequested;

    /// <summary>Raised when the user wants to treat a running process as a game.</summary>
    public event EventHandler<ProcessSnapshot>? AddAsGameRequested;

    [RelayCommand]
    private void InspectConnections()
    {
        if (SelectedProcess is { } row)
        {
            InspectConnectionsRequested?.Invoke(this, row.Snapshot);
        }
    }

    [RelayCommand]
    private void AddAsGame()
    {
        if (SelectedProcess is { } row)
        {
            AddAsGameRequested?.Invoke(this, row.Snapshot);
        }
    }

    /// <summary>
    /// Stops the refresh timer while the page is not visible.
    /// </summary>
    /// <remarks>
    /// Enumerating /proc for several hundred processes twice a second is not free, and a page
    /// nobody is looking at should not cost it. The specification asks for exactly this:
    /// reduce visual refresh work when the window is not in use.
    /// </remarks>
    public void SetActive(bool active)
    {
        if (active)
        {
            if (!IsPaused)
            {
                Refresh();
                _timer.Start();
            }
        }
        else
        {
            _timer.Stop();
        }
    }

    /// <summary>Re-evaluates everything gated on the daemon being reachable.</summary>
    public void NotifyDaemonStateChanged()
    {
        OnPropertyChanged(nameof(CanApply));
        OnPropertyChanged(nameof(ApplyBlockedReason));
    }

    partial void OnIsCompactChanged(bool value) => OnPropertyChanged(nameof(ShowOverlayInspector));

    partial void OnSelectedProcessChanged(ProcessRowViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(ShowOverlayInspector));
        OnPropertyChanged(nameof(CanApply));
        OnPropertyChanged(nameof(ApplyBlockedReason));
        LastApplied = null;
        ErrorMessage = null;
        RefreshCoveringRules();
    }

    // -- actions -------------------------------------------------------------

    [RelayCommand]
    private Task ProxyThisInstanceAsync() =>
        ApplyAsync(RuleScopeChoice.Instance, SelectedProxy is { } p
            ? new RuleAction.Proxy(p.Id)
            : RuleAction.Direct.Instance);

    [RelayCommand]
    private Task AlwaysProxyExecutableAsync() =>
        ApplyAsync(RuleScopeChoice.Executable, SelectedProxy is { } p
            ? new RuleAction.Proxy(p.Id)
            : RuleAction.Direct.Instance);

    [RelayCommand]
    private Task RouteDirectAsync() => ApplyAsync(ScopeChoice, RuleAction.Direct.Instance);

    [RelayCommand]
    private Task BlockAsync() => ApplyAsync(ScopeChoice, RuleAction.Block.Instance);

    [RelayCommand]
    private async Task RemoveOverrideAsync()
    {
        if (SelectedProcess is not { } row)
        {
            return;
        }

        var existing = _rules.FindOverrideFor(row.Snapshot);
        if (existing is null)
        {
            return;
        }

        IsApplying = true;
        try
        {
            var result = await _daemon.RemoveRuleAsync(existing.Id).ConfigureAwait(true);
            if (result.Succeeded)
            {
                _rules.Remove(existing.Id);
                LastApplied = null;
            }
            else
            {
                ErrorMessage = result.FailureReason;
                ErrorDiagnostics = result.Diagnostics;
            }

            ApplyPolicies();
        }
        finally
        {
            IsApplying = false;
        }
    }

    /// <summary>
    /// Builds the rule the user described, sends it, and reports precisely what the daemon
    /// confirmed — never more than that.
    /// </summary>
    private async Task ApplyAsync(RuleScopeChoice scope, RuleAction action)
    {
        if (SelectedProcess is not { } row || IsApplying)
        {
            return;
        }

        ErrorMessage = null;
        ErrorDiagnostics = null;
        IsApplying = true;
        OnPropertyChanged(nameof(CanApply));

        // Show the change as pending immediately, then let the daemon's answer decide.
        row.IsPending = true;
        row.Policy = PolicyKind.Pending;

        try
        {
            var rule = _rules.BuildRule(row.Snapshot, scope, action, IncludeChildren);
            var result = await _daemon.ApplyRuleAsync(rule).ConfigureAwait(true);

            if (result.Succeeded)
            {
                _rules.Add(rule with { AppliedAtUtc = result.ConfirmedAtUtc });
                LastApplied = new AppliedRuleNotice
                {
                    RouteName = DescribeAction(action),
                    PreExistingConnections = result.PreExistingConnections,
                };
            }
            else
            {
                ErrorMessage = result.FailureReason;
                ErrorDiagnostics = result.Diagnostics;
            }
        }
        finally
        {
            row.IsPending = false;
            IsApplying = false;
            ApplyPolicies();
            OnPropertyChanged(nameof(CanApply));
            OnPropertyChanged(nameof(ApplyBlockedReason));
        }
    }

    private string DescribeAction(RuleAction action) => action switch
    {
        RuleAction.Proxy p => _rules.Proxies.FirstOrDefault(x => x.Id == p.EndpointId)?.Name ?? "the selected proxy",
        RuleAction.Block => Loc.Current["Processes.Policy.Blocked"],
        _ => Loc.Current["Processes.Policy.Direct"],
    };

    [ObservableProperty]
    public partial bool IncludeChildren { get; set; }

    public void Dispose() => _timer.Stop();
}

/// <summary>One rule that covers the selected process, and whether it is the one that wins.</summary>
public sealed record CoveringRule(string Position, string Name, string Detail, bool IsWinner);

/// <summary>The three rule scopes offered on the Processes page.</summary>
public enum RuleScopeChoice
{
    Instance,
    Executable,
    Tree,
}

/// <summary>
/// What actually changed after a rule was applied.
/// </summary>
/// <remarks>
/// Deliberately separates "new connections will use the proxy" from "existing connections
/// are on the proxy". Only the first is knowable at apply time.
/// </remarks>
public sealed record AppliedRuleNotice
{
    public required string RouteName { get; init; }

    /// <summary>Null when the daemon could not count pre-existing connections.</summary>
    public int? PreExistingConnections { get; init; }

    public string Headline => Loc.Current["Processes.Applied.Title"];

    public string Body => string.Format(
        System.Globalization.CultureInfo.CurrentCulture,
        Loc.Current["Processes.Applied.Body"],
        RouteName);

    public bool HasPreExisting => PreExistingConnections is > 0;
}
