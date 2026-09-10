using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Connections;
using Yura.Core.Net;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>One row of the Connections table.</summary>
/// <remarks>
/// Long-lived and updated in place, for the same reason process rows are: a table that
/// rebuilds its rows on every refresh loses the selection and the keyboard focus, and a
/// connection list refreshes every two seconds.
/// </remarks>
public sealed partial class ConnectionRowViewModel : ObservableObject
{
    public ConnectionRowViewModel(ConnectionRecord record)
    {
        Record = record;
        Id = record.Id;
    }

    public string Id { get; }

    [ObservableProperty]
    public partial ConnectionRecord Record { get; set; }

    public string ProcessDisplay => Record.ProcessDisplayName is { Length: > 0 } name
        ? Record.OwnerPid is { } pid ? $"{name} ({pid})" : name
        : Record.OwnerPid is { } only ? $"pid {only}" : Loc.Current["Common.Unknown"];

    /// <summary>
    /// The peer: its name when one was learned, otherwise the literal address.
    /// </summary>
    /// <remarks>
    /// A name is what the user recognises, and showing both in one cell means neither fits —
    /// an IPv6 literal alone is 45 characters. The pair goes in the tooltip instead.
    /// </remarks>
    public string DestinationDisplay => Record.RemoteHost is { Length: > 0 } host ? host : Record.Remote.ToString();

    public string DestinationTooltip => Record.RemoteHost is { Length: > 0 } host
        ? $"{host} — {Record.Remote}"
        : Record.Remote.ToString();

    public string ProtocolDisplay => Record.Protocol == TransportProtocol.Tcp ? "TCP" : "UDP";

    public string RuleDisplay => Record.MatchedRuleName ?? "—";

    public string RouteDisplay => Record.Route switch
    {
        RouteObservation.ConfirmedProxied => Record.ProxyName ?? Loc.Current["Connections.Route.Proxied"],
        RouteObservation.ConfirmedDirect => Loc.Current["Connections.Route.Direct"],
        RouteObservation.ConfirmedBlocked => Loc.Current["Connections.Route.Blocked"],
        RouteObservation.PreExistingPreviousRoute => Loc.Current["Connections.Route.Previous"],
        RouteObservation.Pending => Loc.Current["Common.Pending"],
        _ => Loc.Current["Common.Unknown"],
    };

    public string StateDisplay => Record.KernelState is { Length: > 0 } kernel
        ? kernel
        : Record.State.ToString();

    /// <summary>
    /// Byte counters, stacked, or a dash when the daemon does not hold the sockets.
    /// </summary>
    /// <remarks>
    /// Two lines rather than one: both figures together need more width than the column has
    /// at the minimum window size, and a clipped byte count is worse than no byte count.
    /// </remarks>
    public string UpDisplay => Record.BytesUp is { } up ? $"↑ {Format(up)}" : "—";

    public string DownDisplay => Record.BytesDown is { } down ? $"↓ {Format(down)}" : string.Empty;

    public string AgeDisplay => Record.CreatedAtUtc is { } created
        ? FormatAge(DateTimeOffset.UtcNow - created)
        : "—";

    /// <summary>The explanation under the row: a note, or the failure, whichever applies.</summary>
    public string? Detail => Record.FailureReason ?? Record.Note;

    public bool IsProxied => Record.Route == RouteObservation.ConfirmedProxied;

    public bool IsPreExisting => Record.Route == RouteObservation.PreExistingPreviousRoute;

    public bool IsBlocked => Record.Route == RouteObservation.ConfirmedBlocked;

    public bool IsFailed => Record.State == ConnectionState.Failed;

    public bool IsPending => Record.Route == RouteObservation.Pending;

    public void Update(ConnectionRecord record)
    {
        var routeChanged = Record.Route != record.Route || Record.State != record.State;
        var trafficChanged = Record.BytesUp != record.BytesUp || Record.BytesDown != record.BytesDown;
        var hostChanged = Record.RemoteHost != record.RemoteHost;
        var ruleChanged = Record.MatchedRuleName != record.MatchedRuleName;
        Record = record;

        // Only what can change between refreshes is re-raised, so a two-second refresh does
        // not invalidate every binding on every row.
        if (trafficChanged)
        {
            OnPropertyChanged(nameof(UpDisplay));
            OnPropertyChanged(nameof(DownDisplay));
        }

        if (hostChanged)
        {
            OnPropertyChanged(nameof(DestinationDisplay));
            OnPropertyChanged(nameof(DestinationTooltip));
        }

        if (ruleChanged)
        {
            OnPropertyChanged(nameof(RuleDisplay));
        }

        if (routeChanged)
        {
            OnPropertyChanged(nameof(RouteDisplay));
            OnPropertyChanged(nameof(StateDisplay));
            OnPropertyChanged(nameof(Detail));
            OnPropertyChanged(nameof(IsProxied));
            OnPropertyChanged(nameof(IsPreExisting));
            OnPropertyChanged(nameof(IsBlocked));
            OnPropertyChanged(nameof(IsFailed));
            OnPropertyChanged(nameof(IsPending));
        }

        OnPropertyChanged(nameof(AgeDisplay));
    }

    public bool MatchesFilter(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return true;
        }

        return ProcessDisplay.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               DestinationTooltip.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               RuleDisplay.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               RouteDisplay.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               ProtocolDisplay.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static string Format(long bytes) => bytes switch
    {
        < 1024 => string.Create(CultureInfo.CurrentCulture, $"{bytes} B"),
        < 1024 * 1024 => string.Create(CultureInfo.CurrentCulture, $"{bytes / 1024.0:0.#} kB"),
        < 1024L * 1024 * 1024 => string.Create(CultureInfo.CurrentCulture, $"{bytes / (1024.0 * 1024):0.#} MB"),
        _ => string.Create(CultureInfo.CurrentCulture, $"{bytes / (1024.0 * 1024 * 1024):0.##} GB"),
    };

    private static string FormatAge(TimeSpan age) => age switch
    {
        { TotalSeconds: < 60 } => string.Create(CultureInfo.CurrentCulture, $"{(int)age.TotalSeconds}s"),
        { TotalMinutes: < 60 } => string.Create(CultureInfo.CurrentCulture, $"{(int)age.TotalMinutes}m"),
        _ => string.Create(CultureInfo.CurrentCulture, $"{(int)age.TotalHours}h"),
    };
}

/// <summary>
/// The Connections page: what is actually flowing, and on which route.
/// </summary>
/// <remarks>
/// Everything here comes from the daemon, because only the daemon can attribute a socket to a
/// process and only the daemon knows which flows it is itself relaying. With no daemon the
/// page says so rather than showing an empty table that looks like "no connections".
/// </remarks>
public sealed partial class ConnectionsPageViewModel : ObservableObject, IDisposable
{
    private readonly IDaemonClient _daemon;
    private readonly RuleStore _rules;
    private readonly Dictionary<string, ConnectionRowViewModel> _rows = [];
    private readonly DispatcherTimer _timer;
    private bool _refreshInFlight;

    public ConnectionsPageViewModel(IDaemonClient daemon, RuleStore rules)
    {
        _daemon = daemon;
        _rules = rules;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => _ = RefreshAsync();
    }

    public ObservableCollection<ConnectionRowViewModel> Connections { get; } = [];

    [ObservableProperty]
    public partial string SearchText { get; set; } = string.Empty;

    /// <summary>Set when the page was opened from one process, to show only its connections.</summary>
    [ObservableProperty]
    public partial int? PidFilter { get; set; }

    [ObservableProperty]
    public partial string? PidFilterLabel { get; set; }

    /// <summary>
    /// The "showing only X" sentence. Composed here because a localised format string cannot
    /// be nested inside a binding's StringFormat.
    /// </summary>
    public string? PidFilterBanner => PidFilterLabel is { Length: > 0 } label
        ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Connections.FilteredTo"], label)
        : null;

    [ObservableProperty]
    public partial bool IsPaused { get; set; }

    [ObservableProperty]
    public partial ConnectionRowViewModel? SelectedConnection { get; set; }

    [ObservableProperty]
    public partial string? StatusMessage { get; set; }

    public bool HasSelection => SelectedConnection is not null;

    public bool IsEmpty => Connections.Count == 0;

    public bool IsDaemonConnected => _daemon.State == DaemonState.Connected;

    public string? UnavailableReason => _daemon.UnavailableReason;

    public string CountSummary => string.Format(
        CultureInfo.CurrentCulture, Loc.Current["Connections.Count"], Connections.Count);

    /// <summary>Starts the live refresh. Called when the page becomes visible.</summary>
    public void Activate()
    {
        _timer.Start();
        _ = RefreshAsync();
    }

    /// <summary>Stops refreshing while the page is not visible, so a hidden table costs nothing.</summary>
    public void Deactivate() => _timer.Stop();

    /// <summary>Shows only one process's connections, as the "inspect connections" action does.</summary>
    public void FilterTo(int pid, string label)
    {
        PidFilter = pid;
        PidFilterLabel = label;
        _ = RefreshAsync();
    }

    [RelayCommand]
    private void ClearPidFilter()
    {
        PidFilter = null;
        PidFilterLabel = null;
        _ = RefreshAsync();
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        if (_refreshInFlight || IsPaused)
        {
            return;
        }

        _refreshInFlight = true;
        try
        {
            var records = await _daemon.GetConnectionsAsync(PidFilter).ConfigureAwait(true);
            Merge(records);
        }
        catch (Exception)
        {
            // A daemon that went away mid-refresh is reported by the banner, not here.
        }
        finally
        {
            _refreshInFlight = false;
            OnPropertyChanged(nameof(IsDaemonConnected));
            OnPropertyChanged(nameof(UnavailableReason));
        }
    }

    private void Merge(IReadOnlyList<ConnectionRecord> records)
    {
        var seen = new HashSet<string>(records.Count);
        foreach (var record in records)
        {
            seen.Add(record.Id);
            if (_rows.TryGetValue(record.Id, out var existing))
            {
                existing.Update(record);
            }
            else
            {
                _rows[record.Id] = new ConnectionRowViewModel(record);
            }
        }

        foreach (var id in _rows.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            _rows.Remove(id);
        }

        var desired = _rows.Values
            .Where(r => r.MatchesFilter(SearchText))
            .OrderBy(r => r.Record.ProcessDisplayName ?? "￿", StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(r => r.Record.OwnerPid ?? int.MaxValue)
            .ThenBy(r => r.Record.Remote.ToString(), StringComparer.Ordinal)
            .ToList();

        var desiredIds = desired.Select(r => r.Id).ToHashSet();
        for (var i = Connections.Count - 1; i >= 0; i--)
        {
            if (!desiredIds.Contains(Connections[i].Id))
            {
                Connections.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            if (i >= Connections.Count)
            {
                Connections.Add(desired[i]);
            }
            else if (!ReferenceEquals(Connections[i], desired[i]))
            {
                var current = Connections.IndexOf(desired[i]);
                if (current >= 0)
                {
                    Connections.Move(current, i);
                }
                else
                {
                    Connections.Insert(i, desired[i]);
                }
            }
        }

        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(CountSummary));
    }

    partial void OnPidFilterLabelChanged(string? value) => OnPropertyChanged(nameof(PidFilterBanner));

    partial void OnSearchTextChanged(string value) => _ = RefreshAsync();

    partial void OnIsPausedChanged(bool value)
    {
        if (!value)
        {
            _ = RefreshAsync();
        }
    }

    partial void OnSelectedConnectionChanged(ConnectionRowViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        StatusMessage = null;
    }

    // -- rules from a connection ---------------------------------------------

    /// <summary>
    /// Creates a destination rule from the selected connection.
    /// </summary>
    /// <remarks>
    /// Prefers the learned host name over the address: a name is what the user recognises and
    /// survives the service moving. Falls back to the literal address with a /32 or /128 so
    /// the rule is exact rather than a guessed subnet.
    /// </remarks>
    [RelayCommand]
    private void CreateDestinationRule()
    {
        if (SelectedConnection is not { } row)
        {
            return;
        }

        var record = row.Record;
        var destination = record.RemoteHost is { Length: > 0 } host
            ? new DestinationSelector
            {
                Hosts = [new HostPattern(HostMatchKind.Exact, host)],
                Ports = [PortRange.Single((ushort)record.Remote.Port)],
            }
            : new DestinationSelector
            {
                Networks = [new System.Net.IPNetwork(record.Remote.Address,
                    record.Remote.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)],
                Ports = [PortRange.Single((ushort)record.Remote.Port)],
            };

        // A destination-only rule cannot be installed without a process constraint — it would
        // capture the whole machine — so it is scoped to the process the connection belongs to.
        var selector = record.OwnerPid is { } pid && record.ProcessDisplayName is { Length: > 0 }
            ? new ProcessSelector { Kind = ProcessSelectorKind.ProcessName, ProcessName = record.ProcessDisplayName }
            : ProcessSelector.Any;

        var name = record.RemoteHost is { Length: > 0 } named
            ? $"{record.ProcessDisplayName ?? "any"} → {named}:{record.Remote.Port}"
            : $"{record.ProcessDisplayName ?? "any"} → {record.Remote}";

        RuleDraft = new RoutingRule
        {
            Id = Guid.NewGuid(),
            Order = _rules.NextOrder(RuleOrigin.Manual),
            Name = name,
            Origin = RuleOrigin.Manual,
            Lifetime = RuleLifetime.Persistent,
            Process = selector,
            Destination = destination,
            Action = RuleAction.Direct.Instance,
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };

        StatusMessage = Loc.Current["Connections.DraftCreated"];
    }

    /// <summary>
    /// A rule built from a connection, handed to the Rules page for the user to finish.
    /// </summary>
    /// <remarks>
    /// Deliberately not applied here: a rule created from one connection needs an action
    /// chosen, and applying a Direct rule silently would change nothing while looking like it
    /// had done something.
    /// </remarks>
    [ObservableProperty]
    public partial RoutingRule? RuleDraft { get; set; }

    public void Dispose() => _timer.Stop();
}
