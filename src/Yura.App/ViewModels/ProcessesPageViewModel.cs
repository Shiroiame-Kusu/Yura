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
    private bool _refreshing;

    public ProcessesPageViewModel(ProcProcessSource source, IDaemonClient daemon, RuleStore rules)
    {
        _source = source;
        _daemon = daemon;
        _rules = rules;
        _currentUid = ParseUid();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => _ = RefreshInBackgroundAsync();

        // The first read happens now, so the window never opens on an empty table.
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

    /// <summary>
    /// Whether applying a rule also drops the connections the covered processes already have
    /// open, so it governs them too.
    /// </summary>
    /// <remarks>
    /// On by default because "apply this rule" almost always means "now". A socket's cgroup is
    /// fixed when it is created, so a rule can never capture a connection that predates it;
    /// dropping those is the only way the application ends up on the new route without being
    /// restarted. It is a checkbox rather than unconditional because the drop is visible —
    /// a download or a game session breaks off and reconnects — and that is the user's call.
    /// </remarks>
    [ObservableProperty]
    public partial bool ResetExistingConnections { get; set; } = true;

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

    /// <summary>
    /// Whether a rule can be installed at all.
    /// </summary>
    /// <remarks>
    /// The daemon is part of the condition. Without it nothing can reach the kernel, and a
    /// button that is live while the panel explains that nothing will happen is a button that
    /// lies. <see cref="ApplyBlockedReason"/> says which of the two is missing.
    /// </remarks>
    public bool CanApply => SelectedProcess is not null && !IsApplying &&
                            _daemon.State == DaemonState.Connected;

    /// <summary>Proxying additionally needs somewhere to proxy to.</summary>
    public bool CanProxy => CanApply && SelectedProxy is not null;

    /// <summary>
    /// Explains why an action is unavailable, shown next to the control rather than as a
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

            // Said here rather than by quietly routing directly, which is what the two proxy
            // buttons used to do when no route was picked: the rule they installed said
            // "direct" while the button said "proxy".
            return SelectedProxy is null ? Loc.Current["Processes.Inspector.NoRoute"] : null;
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

    /// <summary>Reads the process table now, on the calling thread.</summary>
    [RelayCommand]
    public void Refresh()
    {
        if (IsPaused)
        {
            return;
        }

        Apply(_source.Enumerate());
    }

    /// <summary>
    /// The periodic refresh: the table is read off the UI thread and applied back on it.
    /// </summary>
    /// <remarks>
    /// Reading several hundred processes' worth of files under <c>/proc</c> takes long enough to
    /// be felt, and on the UI thread every two seconds it was — the window stuttered on the
    /// tick whether or not anything had changed.
    /// </remarks>
    private async Task RefreshInBackgroundAsync()
    {
        if (IsPaused || _refreshing)
        {
            return;
        }

        _refreshing = true;
        try
        {
            var snapshots = await Task.Run(() => _source.Enumerate()).ConfigureAwait(true);
            if (!IsPaused)
            {
                Apply(snapshots);
            }
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void Apply(IReadOnlyList<ProcessSnapshot> snapshots)
    {
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

        // The rule list can also change from the Rules page, so the panel's buttons are
        // re-evaluated on the refresh tick rather than only after this page acts.
        RefreshCommandStates();
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
            _ = RefreshInBackgroundAsync();
        }
    }

    /// <summary>Every rule covering the selected process, in evaluation order.</summary>
    public ObservableCollection<CoveringRule> CoveringRules { get; } = [];

    public bool HasCoveringRules => CoveringRules.Count > 0;

    private void RefreshCoveringRules()
    {
        var rebuilt = BuildCoveringRules();

        // Only touched when the content actually differs. This runs on every refresh tick,
        // and clearing an ItemsControl's source twice a second makes the list flicker and
        // drops whatever the pointer was over.
        if (rebuilt.SequenceEqual(CoveringRules))
        {
            return;
        }

        CoveringRules.Clear();
        foreach (var rule in rebuilt)
        {
            CoveringRules.Add(rule);
        }

        OnPropertyChanged(nameof(HasCoveringRules));
    }

    private List<CoveringRule> BuildCoveringRules()
    {
        var rows = new List<CoveringRule>();
        if (SelectedProcess is not { } row)
        {
            return rows;
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
            rows.Add(new CoveringRule(
                rule.Order.ToString(System.Globalization.CultureInfo.CurrentCulture),
                rule.Name,
                detail,
                // Only the first enabled one decides anything; the rest are shadowed.
                IsWinner: rule.Enabled && covering.Take(i).All(r => !r.Enabled)));
        }

        return rows;
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
                _ = RefreshInBackgroundAsync();
                _timer.Start();
            }
        }
        else
        {
            _timer.Stop();
        }
    }

    /// <summary>Re-evaluates everything gated on the daemon being reachable.</summary>
    public void NotifyDaemonStateChanged() => RefreshCommandStates();

    /// <summary>
    /// Re-raises every condition the action buttons are bound to.
    /// </summary>
    /// <remarks>
    /// One place, called from everything that can change an answer. The commands' own
    /// <c>NotifyCanExecuteChanged</c> is what actually enables and disables the buttons;
    /// raising the property alone would leave them stale.
    /// </remarks>
    private void RefreshCommandStates()
    {
        OnPropertyChanged(nameof(CanApply));
        OnPropertyChanged(nameof(CanProxy));
        OnPropertyChanged(nameof(CanRemoveOverride));
        OnPropertyChanged(nameof(RemovableOverride));
        OnPropertyChanged(nameof(ApplyBlockedReason));
        ProxyThisInstanceCommand.NotifyCanExecuteChanged();
        AlwaysProxyExecutableCommand.NotifyCanExecuteChanged();
        RouteDirectCommand.NotifyCanExecuteChanged();
        BlockCommand.NotifyCanExecuteChanged();
        RemoveOverrideCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsCompactChanged(bool value) => OnPropertyChanged(nameof(ShowOverlayInspector));

    partial void OnSelectedProxyChanged(ProxyEndpoint? value) => RefreshCommandStates();

    partial void OnScopeChoiceChanged(RuleScopeChoice value)
    {
        // The checkbox only has a say where children are not already part of the scope.
        OnPropertyChanged(nameof(ChildrenChoiceApplies));
        OnPropertyChanged(nameof(CoversChildren));
        OnPropertyChanged(nameof(ProxyButtonLabel));
    }

    /// <summary>
    /// What the proxy button installs, at the scope chosen above it.
    /// </summary>
    /// <remarks>
    /// The button follows the scope, so its label does too: "Proxy this instance" over a rule
    /// for every future run of the executable was the button saying one thing and doing another.
    /// </remarks>
    public string ProxyButtonLabel => ScopeChoice switch
    {
        RuleScopeChoice.Executable => Loc.Current["Processes.Action.ProxyExecutable"],
        RuleScopeChoice.Tree => Loc.Current["Processes.Action.ProxyTree"],
        _ => Loc.Current["Processes.Action.ProxyInstance"],
    };

    /// <summary>Re-renders every localised string after a language change.</summary>
    public void NotifyLanguageChanged()
    {
        // Empty means "everything": every computed label on the page, re-read in one go.
        OnPropertyChanged(string.Empty);
        foreach (var row in _rows.Values)
        {
            row.NotifyLanguageChanged();
        }

        CoveringRules.Clear();
        RefreshCoveringRules();
    }

    partial void OnIncludeChildrenChanged(bool value) => OnPropertyChanged(nameof(CoversChildren));

    /// <summary>True when the "include child processes" choice is the user's to make.</summary>
    public bool ChildrenChoiceApplies => ScopeChoice != RuleScopeChoice.Tree;

    /// <summary>True when the rule that would be installed covers children at all.</summary>
    public bool CoversChildren => ScopeChoice == RuleScopeChoice.Tree || IncludeChildren;

    partial void OnSelectedProcessChanged(ProcessRowViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(ShowOverlayInspector));
        LastApplied = null;
        ErrorMessage = null;
        ErrorDiagnostics = null;
        RefreshCoveringRules();
        RefreshCommandStates();
    }

    // -- actions -------------------------------------------------------------

    /// <summary>
    /// Routes the selection through the chosen proxy, at the scope the user picked.
    /// </summary>
    /// <remarks>
    /// The scope comes from <see cref="ScopeChoice"/>. It used to be hard-coded to the running
    /// instance here, which made the three radio buttons above decorative: picking "this
    /// process and its children" and pressing this button quietly installed an instance rule
    /// that covered neither the children nor a restart.
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanProxy))]
    private Task ProxyThisInstanceAsync() => SelectedProxy is { } proxy
        ? ApplyAsync(ScopeChoice, new RuleAction.Proxy(proxy.Id))
        : Task.CompletedTask;

    /// <summary>
    /// Proxies every future run of this executable, and says so by moving the scope with it.
    /// </summary>
    /// <remarks>
    /// This is a shortcut for "pick the executable scope, then apply", so it sets the scope
    /// rather than overriding it silently: after pressing it the radio buttons show what was
    /// actually installed.
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanProxy))]
    private Task AlwaysProxyExecutableAsync()
    {
        if (SelectedProxy is not { } proxy)
        {
            return Task.CompletedTask;
        }

        ScopeChoice = RuleScopeChoice.Executable;
        return ApplyAsync(RuleScopeChoice.Executable, new RuleAction.Proxy(proxy.Id));
    }

    [RelayCommand(CanExecute = nameof(CanApply))]
    private Task RouteDirectAsync() => ApplyAsync(ScopeChoice, RuleAction.Direct.Instance);

    [RelayCommand(CanExecute = nameof(CanApply))]
    private Task BlockAsync() => ApplyAsync(ScopeChoice, RuleAction.Block.Instance);

    /// <summary>The override this process has, when it has one that can be taken off.</summary>
    public RoutingRule? RemovableOverride =>
        SelectedProcess is { } row ? _rules.FindOverrideFor(row.Snapshot) : null;

    public bool CanRemoveOverride => RemovableOverride is not null && !IsApplying &&
                                     _daemon.State == DaemonState.Connected;

    [RelayCommand(CanExecute = nameof(CanRemoveOverride))]
    private async Task RemoveOverrideAsync()
    {
        if (RemovableOverride is not { } existing)
        {
            return;
        }

        IsApplying = true;
        RefreshCommandStates();
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
            RefreshCommandStates();
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
        LastApplied = null;
        IsApplying = true;
        RefreshCommandStates();

        // Show the change as pending immediately, then let the daemon's answer decide.
        row.IsPending = true;
        row.Policy = PolicyKind.Pending;

        try
        {
            // Descendants come from the scope when the scope is about a tree; the checkbox
            // only has a say for the two scopes where it is offered.
            var includeChildren = scope != RuleScopeChoice.Tree && IncludeChildren;
            var built = _rules.BuildRule(row.Snapshot, scope, action, includeChildren);

            // A new choice for a process that already has one replaces it in place: same id,
            // same position. The daemon then swaps one rule for the other in a single step,
            // which is what lets it tell which open connections the change moves. Installed
            // beside the old rule and removed afterwards, the old one was still winning at the
            // moment of comparison, and no connection was ever reset.
            var rule = _rules.FindSupersededBy(built) is { } previous
                ? built with { Id = previous.Id, Order = previous.Order }
                : built;

            var result = await _daemon
                .ApplyRuleAsync(rule, ResetExistingConnections)
                .ConfigureAwait(true);

            if (result.Succeeded)
            {
                // Anything else this replaces has to come out of the kernel as well. The store
                // drops a superseded selection from the list, but the daemon keeps every rule
                // it was given, and one left installed would go on deciding routes while the
                // UI showed only the new one — the way a process ends up "proxied" in the list
                // and routed direct in the kernel.
                foreach (var superseded in _rules.Add(rule with { AppliedAtUtc = result.ConfirmedAtUtc }))
                {
                    await RetireAsync(superseded).ConfigureAwait(true);
                }

                LastApplied = new AppliedRuleNotice
                {
                    RouteName = DescribeAction(action),
                    PreExistingConnections = result.PreExistingConnections,
                    ResetConnections = result.ResetConnections,
                    ResetFailure = result.ResetFailure,
                    Warnings = result.Warnings,
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
            RefreshCommandStates();
        }
    }

    /// <summary>
    /// Takes a rule the app no longer lists out of the daemon.
    /// </summary>
    /// <remarks>
    /// A failure here is reported as a warning on the notice rather than as a failed apply:
    /// the new rule is installed, and hiding that the old one is still live would be the worse
    /// of the two lies.
    /// </remarks>
    private async Task RetireAsync(RoutingRule rule)
    {
        var removal = await _daemon.RemoveRuleAsync(rule.Id).ConfigureAwait(true);
        if (!removal.Succeeded)
        {
            ErrorMessage = string.Format(
                System.Globalization.CultureInfo.CurrentCulture,
                Loc.Current["Processes.Applied.StaleRule"], rule.Name);
            ErrorDiagnostics = removal.FailureReason;
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
/// The distinction this type exists for is between the rule being installed and the
/// application actually using it. A rule governs a connection only from the moment that
/// connection is opened, so the two cases read differently: either the connections that were
/// already open were dropped — and the application is on the new route now — or they were
/// left alone and it is not, until it reconnects of its own accord.
/// </remarks>
public sealed record AppliedRuleNotice
{
    private static string Tr(string key) => Loc.Current[key];

    private static string Tr(string key, params object[] arguments) => string.Format(
        System.Globalization.CultureInfo.CurrentCulture, Loc.Current[key], arguments);

    public required string RouteName { get; init; }

    /// <summary>Null when the daemon could not count pre-existing connections.</summary>
    public int? PreExistingConnections { get; init; }

    /// <summary>
    /// Connections the daemon dropped so the rule reaches them too. Null when it was not
    /// asked to, which is a different statement from "there were none".
    /// </summary>
    public int? ResetConnections { get; init; }

    /// <summary>Why connections that should have been dropped were not.</summary>
    public string? ResetFailure { get; init; }

    /// <summary>What the daemon could not do, though the rule went in.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    public bool HasPreExisting => PreExistingConnections is > 0;

    /// <summary>True when the rule governs the traffic the application is sending right now.</summary>
    public bool IsEffectiveNow => ResetConnections is > 0 || PreExistingConnections is 0 or null;

    public string Headline => IsEffectiveNow
        ? Tr("Processes.Applied.TitleNow")
        : Tr("Processes.Applied.Title");

    public string Body => ResetConnections switch
    {
        > 0 => Tr("Processes.Applied.BodyReset", ResetConnections.Value, RouteName),
        // Asked for, nothing to drop: every connection this process makes from here is the
        // rule's, and saying "reset 0" would read as a failure rather than as nothing to do.
        0 => Tr("Processes.Applied.Body", RouteName),
        _ => HasPreExisting
            ? Tr("Processes.Applied.BodyKept", RouteName, PreExistingConnections!.Value)
            : Tr("Processes.Applied.Body", RouteName),
    };

    /// <summary>The caveats, as one line, or null when there are none.</summary>
    public string? Caveat
    {
        get
        {
            var lines = new List<string>();
            if (ResetFailure is { Length: > 0 } failure)
            {
                lines.Add(Tr("Processes.Applied.ResetFailed", failure));
            }

            lines.AddRange(Warnings);
            return lines.Count == 0 ? null : string.Join(" ", lines);
        }
    }
}
