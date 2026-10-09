using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using System.Net;
using System.Net.Sockets;
using Yura.Core.Connections;
using Yura.Core.Games;
using Yura.Core.Ipc;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>The explicit states an acceleration session moves through.</summary>
public enum BoostState
{
    Ready,
    Testing,
    Starting,
    WaitingForGame,
    Routing,
    Degraded,
    Stopping,
    Failed,
}

/// <summary>A game in the list, with whatever is currently known about it.</summary>
public sealed partial class GameRowViewModel : ObservableObject
{
    public GameRowViewModel(GameProfile profile)
    {
        Profile = profile;
    }

    [ObservableProperty]
    public partial GameProfile Profile { get; set; }

    /// <summary>The running instance this profile is attached to, when one has been found.</summary>
    [ObservableProperty]
    public partial ProcessSnapshot? Running { get; set; }

    public Guid Id => Profile.Id;

    public string Name => Profile.Name;

    public bool IsRunning => Running is not null;

    /// <summary>
    /// What is known about how to route this game, stated rather than implied.
    /// </summary>
    /// <remarks>
    /// A Steam manifest names an install directory, not a binary, so a freshly discovered game
    /// has nothing to match on. Saying so — and asking the user to start it — is honest; guessing
    /// a binary would produce a rule that silently covers nothing.
    /// </remarks>
    public string SubtitleText => Running is { } process
        ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.AttachedTo"], process.DisplayName, process.Identity.Pid)
        : Profile.WineTargetExecutable
          ?? Profile.ExecutablePath
          ?? (Profile.SteamAppId is { } appId
              ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.SteamNotStarted"], appId)
              : Loc.Current["Games.NotStarted"]);

    public void Update(GameProfile profile, ProcessSnapshot? running)
    {
        Profile = profile;
        Running = running;
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(SubtitleText));
        OnPropertyChanged(nameof(IsRunning));
    }

    /// <summary>Re-renders the subtitle, which is localised, after a language change.</summary>
    public void NotifyLanguageChanged() => OnPropertyChanged(nameof(SubtitleText));
}

/// <summary>
/// One measured network figure.
/// </summary>
/// <remarks>
/// The whole point of this type is that <see cref="Value"/> is nullable. A missing
/// measurement renders as "Not measured"; substituting zero would read as a perfect score.
///
/// A class rather than a record. The page binds through a figure to its label, and a binding
/// reads the label again only when it is handed a different figure — which a property setter
/// never does with a record equal to the one it holds. As a record, "Not measured" stayed in
/// the language it was first shown in.
/// </remarks>
public sealed class Metric(double? value, string unit)
{
    public static readonly Metric NotMeasured = new(null, string.Empty);

    public double? Value { get; } = value;

    public string Unit { get; } = unit;

    public bool HasValue => Value is not null;

    public string Display => Value is { } v
        ? string.Create(CultureInfo.CurrentCulture, $"{v:0.#} {Unit}").Trim()
        : Loc.Current["Common.NotMeasured"];

    /// <summary>The same figure as a new object, so whatever shows it reads its label again.</summary>
    public Metric Rerendered() => new(Value, Unit);
}

/// <summary>
/// The Games page: select game, select route, start boost.
/// </summary>
/// <remarks>
/// A session is an ordinary rule with <see cref="RuleOrigin.GameProfile"/>, not a special
/// mechanism, which is what makes its precedence against a manual selection explainable.
/// Everything measured comes from the daemon, against one target, by one method, so the two
/// columns the page shows side by side are actually comparable.
/// </remarks>
public sealed partial class GamesPageViewModel : ObservableObject, IDisposable
{
    private readonly RuleStore _rules;
    private readonly IDaemonClient _daemon;
    private readonly ProcProcessSource _processes;
    private readonly Dictionary<Guid, GameRowViewModel> _rows = [];
    private readonly DispatcherTimer _sessionTimer;
    private readonly DispatcherTimer _attachTimer;
    private DateTimeOffset? _sessionStartedAt;
    private RoutingRule? _sessionRule;

    /// <summary>
    /// The game the running session is for. Not <see cref="SelectedGame"/>: picking another game
    /// in the list while one is being routed must not make the session report on the wrong one.
    /// </summary>
    private GameRowViewModel? _sessionGame;

    /// <summary>The route the last NAT test ran over, which is what its comparison is about.</summary>
    private string? _natRouteName;

    private CancellationTokenSource? _measuring;
    private bool _runningRefreshInFlight;

    // The session's monitor: the target probed once each way, every few seconds, for the chart.
    private readonly DispatcherTimer _sampleTimer;
    private CancellationTokenSource? _sampling;
    private bool _sampleInFlight;
    private bool _arrivalInFlight;

    /// <summary>
    /// What the monitor measures when no target was typed: the server the game is talking to
    /// most, through the route.
    /// </summary>
    private IPEndPoint? _autoTarget;

    /// <summary>
    /// Every process that is the game: whatever matches its profile, and everything those started.
    /// </summary>
    /// <remarks>
    /// Its connections are in one of them, and rarely the one that matched first. Steam starts a
    /// game through a wrapper that never opens a socket, and Proton runs it as a tree of Wine
    /// processes. Reading the wrapper's connections alone, the page reported that nothing from the
    /// game was captured, and drew no chart, however much of its traffic the route was carrying.
    /// </remarks>
    private IReadOnlySet<int> _gamePids = new HashSet<int>();

    /// <summary>
    /// The game's process when the session started, if the game was already running: the
    /// sockets it had opened by then are on their old route, and the reset can only move some.
    /// </summary>
    private ProcessIdentity? _runningAtStart;

    /// <summary>How often the monitor probes the target while a session routes the game.</summary>
    public static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(3);

    public GamesPageViewModel(RuleStore rules, IDaemonClient daemon, ProcProcessSource processes)
    {
        _rules = rules;
        _daemon = daemon;
        _processes = processes;

        _sessionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _sessionTimer.Tick += (_, _) => OnPropertyChanged(nameof(SessionDurationDisplay));

        // While a session is starting, this is what turns "waiting for game" into "routing".
        // It is also where the evidence comes from: a rule being installed says nothing about
        // whether the game's traffic is obeying it.
        _attachTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _attachTimer.Tick += (_, _) =>
        {
            _ = RefreshRunningInBackgroundAsync();
            _ = RefreshEvidenceAsync();
        };

        _sampleTimer = new DispatcherTimer { Interval = SampleInterval };
        _sampleTimer.Tick += (_, _) => _ = SampleAsync();
    }

    public ObservableCollection<GameRowViewModel> Games { get; } = [];

    /// <summary>Proxies and chains: both are routes a game can be sent through.</summary>
    public ObservableCollection<RouteOption> Routes => _rules.Routes;

    [ObservableProperty]
    public partial GameRowViewModel? SelectedGame { get; set; }

    [ObservableProperty]
    public partial RouteOption? SelectedRoute { get; set; }

    [ObservableProperty]
    public partial BoostState State { get; set; } = BoostState.Ready;

    [ObservableProperty]
    public partial string? FailureReason { get; set; }

    [ObservableProperty]
    public partial string? StatusMessage { get; set; }

    public bool HasGames => Games.Count > 0;

    public string StateLabel => State switch
    {
        BoostState.Ready => Loc.Current["Games.State.Ready"],
        BoostState.Testing => Loc.Current["Games.State.Testing"],
        BoostState.Starting => Loc.Current["Games.State.Starting"],
        BoostState.WaitingForGame => Loc.Current["Games.State.WaitingForGame"],
        BoostState.Routing => Loc.Current["Games.State.Routing"],
        BoostState.Degraded => Loc.Current["Games.State.Degraded"],
        BoostState.Stopping => Loc.Current["Games.State.Stopping"],
        _ => Loc.Current["Games.State.Failed"],
    };

    public bool IsRunning => State is BoostState.Starting or BoostState.WaitingForGame
        or BoostState.Routing or BoostState.Degraded;

    // Per-class booleans, because Avalonia cannot bind the Classes collection wholesale.
    public bool IsRouting => State == BoostState.Routing;

    public bool IsDegraded => State == BoostState.Degraded;

    public bool IsFailed => State == BoostState.Failed;

    public bool IsTransitioning => State is BoostState.Testing or BoostState.Starting
        or BoostState.WaitingForGame or BoostState.Stopping;

    public bool CanStart => SelectedGame is not null && SelectedRoute is not null && !IsRunning &&
                            _daemon.State == DaemonState.Connected;

    /// <summary>
    /// A target to measure against: the one saved with the game, or one typed in the box.
    /// </summary>
    /// <remarks>
    /// The typed one counts. Requiring a saved target made the button unusable for every game
    /// that did not have one yet — and measuring is the only thing that saves one.
    /// </remarks>
    public bool CanMeasure => SelectedGame is { } game &&
                              (game.Profile.IsMeasurable || TryParseTarget(MeasurementTargetInput, out _, out _)) &&
                              _daemon.State == DaemonState.Connected && !IsMeasuring;

    /// <summary>True while a measurement is running, whether or not a session is.</summary>
    [ObservableProperty]
    public partial bool IsMeasuring { get; set; }

    partial void OnIsMeasuringChanged(bool value) => OnPropertyChanged(nameof(CanMeasure));

    partial void OnMeasurementTargetInputChanged(string value)
    {
        OnPropertyChanged(nameof(CanMeasure));
        RaiseMonitor();
    }

    /// <summary>Shown next to a disabled Start button, so the reason needs no hovering.</summary>
    public string? StartBlockedReason
    {
        get
        {
            if (SelectedGame is null)
            {
                return Games.Count == 0 ? Loc.Current["Games.NoGames"] : Loc.Current["Games.SelectGame"];
            }

            if (SelectedRoute is null)
            {
                return Loc.Current["Games.SelectRoute"];
            }

            if (_daemon.State != DaemonState.Connected)
            {
                return _daemon.UnavailableReason;
            }

            return null;
        }
    }

    /// <summary>
    /// Said under the controls before a boost: when the game is not running, that starting the
    /// boost first is the expected order, not a mistake to be blocked; when it is, what a boost
    /// can and cannot move of what it already has open.
    /// </summary>
    public string? StartHint => IsRunning || StartBlockedReason is not null || SelectedGame is not { } game
        ? null
        : string.Format(CultureInfo.CurrentCulture,
            Loc.Current[game.Running is null ? "Games.StartBeforeGame" : "Games.StartWhileRunning"], game.Name);

    // -- discovery -------------------------------------------------------------

    /// <summary>
    /// Merges saved profiles with what is installed and what is running.
    /// </summary>
    /// <remarks>
    /// Saved profiles win over discovery for everything the user chose — the route, the paths,
    /// the measurement target. Discovery contributes the facts it owns: the name Steam uses
    /// and where the game is installed, both of which can change under a saved profile.
    /// </remarks>
    /// <param name="scan">The Steam libraries, or null to read this machine's; tests pass their own.</param>
    public void LoadProfiles(IEnumerable<GameProfile> saved, SteamScan? scan = null)
    {
        foreach (var profile in saved)
        {
            _rows[profile.Id] = new GameRowViewModel(profile);
        }

        Merge(scan ?? SteamLibrary.Scan());
        Rebuild();
        RefreshRunning();
    }

    [RelayCommand]
    private void Rescan()
    {
        var added = Merge(SteamLibrary.Scan());

        Rebuild();
        RefreshRunning();
        StatusMessage = added == 0
            ? Loc.Current["Games.RescanNoneNew"]
            : string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.RescanFound"], added);
    }

    /// <summary>Folds a scan into the list, and keeps the account of it for display.</summary>
    /// <returns>How many games the list had never seen.</returns>
    private int Merge(SteamScan scan)
    {
        var added = 0;
        foreach (var discovered in scan.Games)
        {
            if (!_rows.TryGetValue(discovered.Id, out var row))
            {
                _rows[discovered.Id] = new GameRowViewModel(discovered);
                added++;
                continue;
            }

            // A game that was moved to another drive, or renamed by its publisher, is the same
            // game with the same route. Refreshing these is what keeps a saved profile able to
            // recognise its own process after the library changed under it.
            row.Update(row.Profile with
            {
                Name = row.Profile.Source == GameSource.Steam ? discovered.Name : row.Profile.Name,
                InstallDirectory = discovered.InstallDirectory,
                SteamAppId = row.Profile.SteamAppId ?? discovered.SteamAppId,
            }, row.Running);
        }

        _scan = scan;
        OnPropertyChanged(nameof(LibrarySummary));
        OnPropertyChanged(nameof(SkippedLibraries));
        OnPropertyChanged(nameof(HasSkippedLibraries));
        return added;
    }

    private SteamScan _scan = SteamScan.Empty;

    /// <summary>
    /// How many games came from how many libraries.
    /// </summary>
    /// <remarks>
    /// Stated in the page because a scan that reads one library out of six looks exactly like
    /// one that read them all. Yura shipped with that bug; a visible count is what makes it
    /// impossible to ship again unnoticed.
    /// </remarks>
    public string LibrarySummary => _scan.Libraries.Count == 0
        ? Loc.Current["Games.NoLibraries"]
        : string.Format(
            CultureInfo.CurrentCulture,
            Loc.Current["Games.LibrarySummary"],
            _scan.Libraries.Sum(l => l.Games),
            _scan.Libraries.Count);

    public bool HasSkippedLibraries => _scan.Skipped.Count > 0;

    /// <summary>Libraries Steam lists that could not be read, each with the reason.</summary>
    public string SkippedLibraries => string.Join(
        Environment.NewLine,
        _scan.Skipped.Select(s => $"{s.Path} — {SkipReasonText(s)}"));

    private static string SkipReasonText(SkippedLibrary skipped) => skipped.Reason switch
    {
        SkipReason.NotPresent => Loc.Current["Games.Skip.NotPresent"],
        SkipReason.NoSteamApps => Loc.Current["Games.Skip.NoSteamApps"],
        SkipReason.PermissionDenied => Loc.Current["Games.Skip.PermissionDenied"],
        _ => skipped.Detail ?? Loc.Current["Games.Skip.Unreadable"],
    };

    /// <summary>
    /// Adds a game from a running process, which is also how a profile learns what to match.
    /// </summary>
    /// <remarks>
    /// This is the path that makes the Games page work for anything Steam does not know about,
    /// and the only way to bind a Wine or Proton game to the one Windows executable that
    /// distinguishes it from every other game sharing the runtime.
    /// </remarks>
    public void AddFromProcess(ProcessSnapshot process)
    {
        var profile = new GameProfile
        {
            Id = Guid.NewGuid(),
            Name = process.DisplayName,
            ExecutablePath = process.ExecutablePath,
            WineTargetExecutable = process.Wine?.TargetExecutable,
            SteamAppId = process.SteamAppId,
            Source = GameSource.Manual,
        };

        _rows[profile.Id] = new GameRowViewModel(profile) { Running = process };
        Rebuild();
        SelectedGame = _rows[profile.Id];
        StatusMessage = string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Added"], profile.Name);
    }

    /// <summary>
    /// Attaches the selected profile to a running process, filling in what to match on.
    /// </summary>
    public void AttachToProcess(ProcessSnapshot process)
    {
        if (SelectedGame is not { } row)
        {
            return;
        }

        row.Update(row.Profile with
        {
            ExecutablePath = process.ExecutablePath,
            WineTargetExecutable = process.Wine?.TargetExecutable ?? row.Profile.WineTargetExecutable,
            SteamAppId = process.SteamAppId ?? row.Profile.SteamAppId,
        }, process);

        ProfilesChanged?.Invoke(this, EventArgs.Empty);
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(StartBlockedReason));
    }

    /// <summary>Raised when a profile changed in a way worth saving.</summary>
    public event EventHandler? ProfilesChanged;

    /// <summary>Every profile, for persistence.</summary>
    public IEnumerable<GameProfile> Profiles => _rows.Values.Select(r => r.Profile);

    private void Rebuild()
    {
        var desired = _rows.Values.OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

        for (var i = Games.Count - 1; i >= 0; i--)
        {
            if (!desired.Contains(Games[i]))
            {
                Games.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            if (i >= Games.Count)
            {
                Games.Add(desired[i]);
            }
            else if (!ReferenceEquals(Games[i], desired[i]))
            {
                var at = Games.IndexOf(desired[i]);
                if (at >= 0)
                {
                    Games.Move(at, i);
                }
                else
                {
                    Games.Insert(i, desired[i]);
                }
            }
        }

        OnPropertyChanged(nameof(HasGames));
        OnPropertyChanged(nameof(StartBlockedReason));
    }

    /// <summary>
    /// Finds the running process for each profile: by Wine target, executable path, Steam app
    /// id, or a binary living inside the game's own install directory.
    /// </summary>
    /// <remarks>
    /// The last of those is what makes a freshly discovered game work without the user
    /// attaching it by hand. It is evidence rather than a guess — the executable is under
    /// <c>steamapps/common/&lt;this game&gt;</c> and so belongs to this game and nothing else —
    /// which is the standard the rest of the Games page is held to.
    /// </remarks>
    private void RefreshRunning() => ApplyRunning(_processes.Enumerate());

    /// <summary>
    /// The periodic refresh: the process table is read off the UI thread and applied back on it.
    /// </summary>
    /// <remarks>
    /// It runs every two seconds for as long as a session does, whichever page is showing, and
    /// reading all of <c>/proc</c> on the UI thread that often made the window stutter.
    /// </remarks>
    private async Task RefreshRunningInBackgroundAsync()
    {
        if (_runningRefreshInFlight)
        {
            return;
        }

        _runningRefreshInFlight = true;
        try
        {
            var snapshot = await Task.Run(() => _processes.Enumerate()).ConfigureAwait(true);
            ApplyRunning(snapshot);
        }
        finally
        {
            _runningRefreshInFlight = false;
        }
    }

    internal void ApplyRunning(IReadOnlyList<ProcessSnapshot> snapshot)
    {
        var changed = false;

        foreach (var row in _rows.Values)
        {
            var profile = row.Profile;
            var match = snapshot
                .Select(p => (Process: p, Rank: MatchRank(profile, p)))
                .Where(m => m.Rank > 0)
                .OrderByDescending(m => m.Rank)
                .Select(m => m.Process)
                .FirstOrDefault();

            // By identity: every read makes new snapshot objects, so comparing references
            // re-raised every running game's row on every tick whether or not anything changed.
            if (row.Running?.Identity != match?.Identity)
            {
                row.Update(profile, match);
                changed = true;
            }
        }

        if (changed)
        {
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(StartBlockedReason));
            OnPropertyChanged(nameof(StartHint));
            OnPropertyChanged(nameof(CanLaunch));
        }

        // A session that was waiting for its game now has one, and vice versa. One that was started
        // before anything about the game was known gets its rule now, from the process itself.
        var game = _sessionGame ?? SelectedGame;
        _gamePids = game is null ? new HashSet<int>() : GamePids(game.Profile, snapshot);
        LearnWhileRouting(game);
        if (State == BoostState.WaitingForGame && game?.Running is { } process)
        {
            if (NeedsRuleFor(process))
            {
                _ = RouteArrivedGameAsync(game, process);
            }
            else
            {
                State = BoostState.Routing;
            }
        }
        else if (State == BoostState.Routing && game?.Running is null)
        {
            State = BoostState.WaitingForGame;
        }
    }

    /// <summary>
    /// How surely <paramref name="process"/> is the game's own: 0 when it is not the game's at all,
    /// higher for more specific evidence.
    /// </summary>
    /// <remarks>
    /// Several processes match one game. Steam's launch wrapper and every runtime process under it
    /// carry the game's app id; a native game's own binary, inside its folder, outranks them. A
    /// Proton game is different: the wrapper's command line names the game's .exe, so the wrapper
    /// is recognised by it as surely as the Wine process running it — and, being the root of the
    /// tree, it is the better process to route, since everything else descends from it. Either
    /// way the page does not rely on this one process for anything but a rule: the evidence and
    /// the monitor read the whole tree, <see cref="GamePids"/>. The executable path of a Wine game
    /// is the runtime's, shared by every game on that runtime, so such a game is recognised by its
    /// Windows executable alone, as the daemon matches it.
    /// </remarks>
    internal static int MatchRank(GameProfile profile, ProcessSnapshot process)
    {
        var exact = profile.WineTargetExecutable is { Length: > 0 } wine
            ? string.Equals(process.Wine?.TargetExecutable, wine, StringComparison.OrdinalIgnoreCase)
            : profile.ExecutablePath is { Length: > 0 } path &&
              string.Equals(process.ExecutablePath, path, StringComparison.Ordinal);
        if (exact)
        {
            return 3;
        }

        if (profile.MatchesInstalledPath(process.Wine?.TargetExecutable) ||
            profile.MatchesInstalledPath(process.ExecutablePath))
        {
            return 2;
        }

        return profile.SteamAppId is { Length: > 0 } appId &&
               string.Equals(process.SteamAppId, appId, StringComparison.Ordinal)
            ? 1
            : 0;
    }

    /// <summary>Every process of the game in <paramref name="snapshot"/>; see <see cref="_gamePids"/>.</summary>
    internal static HashSet<int> GamePids(GameProfile profile, IReadOnlyList<ProcessSnapshot> snapshot)
    {
        var pids = snapshot.Where(p => MatchRank(profile, p) > 0).Select(p => p.Identity.Pid).ToHashSet();
        var children = snapshot.ToLookup(p => p.ParentPid);
        var pending = new Stack<int>(pids);
        while (pending.TryPop(out var parent))
        {
            foreach (var child in children[parent])
            {
                if (pids.Add(child.Identity.Pid))
                {
                    pending.Push(child.Identity.Pid);
                }
            }
        }

        return pids;
    }

    /// <summary>
    /// Remembers what a game routed by process turned out to be, once its own binary is running.
    /// </summary>
    /// <remarks>
    /// A game launched through Steam is usually found first by its wrapper, a couple of seconds
    /// before the game itself starts, and routed by process from there — which covers the game
    /// too, since it runs under the wrapper. What is learned when the game appears changes nothing
    /// about this run; it is what lets the next boost have its rule in place before the game's
    /// first connection.
    /// </remarks>
    private void LearnWhileRouting(GameRowViewModel? game)
    {
        if (State is not (BoostState.Routing or BoostState.Degraded) ||
            _sessionRule is not { Process.Kind: ProcessSelectorKind.Instance } ||
            game is not { Running: { } running } || game.Profile.IsRoutable ||
            LearnSelector(game.Profile, running).Learned is not { } learned)
        {
            return;
        }

        game.Update(learned, running);
        ProfilesChanged?.Invoke(this, EventArgs.Empty);
        StatusMessage = string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Learned"], game.Name);
    }

    /// <summary>
    /// Whether a game that just appeared still has to be given a rule: the session has none yet,
    /// or it has one for an earlier run of the game that matched by process.
    /// </summary>
    private bool NeedsRuleFor(ProcessSnapshot process) =>
        _sessionRule is not { } rule ||
        (rule.Process.Kind == ProcessSelectorKind.Instance && rule.Process.Identity != process.Identity);

    // -- evidence -------------------------------------------------------------

    /// <summary>
    /// What is actually happening to the game's connections, as opposed to what was asked for.
    /// </summary>
    /// <remarks>
    /// The session state says a rule is installed and the game is running. Neither is evidence
    /// that the game's traffic is going through the route, and the difference is not academic:
    /// a connection the game opened in its first millisecond, a proxy set in the system
    /// environment that sends everything to loopback, or an IPv6 destination, all produce a
    /// page that says "Routing" over traffic that is not. This is the line that tells the
    /// truth instead, and it comes from the daemon's own account of each connection.
    /// </remarks>
    [ObservableProperty]
    public partial string? RoutingEvidence { get; set; }

    /// <summary>True when nothing is being carried and it has been long enough to say so.</summary>
    [ObservableProperty]
    public partial bool RoutingEvidenceIsWarning { get; set; }

    public bool HasRoutingEvidence => RoutingEvidence is not null;

    /// <summary>
    /// The evidence as a quiet line, when there is some and it is not a warning. Shown whenever
    /// it was not a warning, it left an empty line above the session for as long as there was none.
    /// </summary>
    public bool ShowRoutingEvidenceHint => RoutingEvidence is not null && !RoutingEvidenceIsWarning;

    partial void OnRoutingEvidenceChanged(string? value)
    {
        OnPropertyChanged(nameof(HasRoutingEvidence));
        OnPropertyChanged(nameof(ShowRoutingEvidenceHint));
    }

    partial void OnRoutingEvidenceIsWarningChanged(bool value) => OnPropertyChanged(nameof(ShowRoutingEvidenceHint));

    private DateTimeOffset? _routingSince;
    private bool _evidenceInFlight;

    internal async Task RefreshEvidenceAsync()
    {
        if (_evidenceInFlight || (_sessionGame ?? SelectedGame)?.Running is null || !IsRunning ||
            _daemon.State != DaemonState.Connected)
        {
            return;
        }

        _evidenceInFlight = true;
        try
        {
            // Every connection, then the game's: they can be in any process of its tree. Listing
            // them all takes the daemon a few milliseconds.
            var rows = GameRows(await _daemon.GetConnectionsAsync().ConfigureAwait(true), _gamePids, _sessionRule?.Id);
            Describe(rows);
            UpdateAutoTarget(rows);
        }
        finally
        {
            _evidenceInFlight = false;
        }
    }

    /// <summary>
    /// The connections of the game's processes, and any the session's rule decided whatever
    /// process they are now put down to.
    /// </summary>
    internal static List<ConnectionRecord> GameRows(
        IReadOnlyList<ConnectionRecord> rows, IReadOnlySet<int> gamePids, Guid? sessionRuleId) => rows
        .Where(r => (r.OwnerPid is { } pid && gamePids.Contains(pid)) ||
                    (sessionRuleId is { } id && r.MatchedRuleId == id))
        .ToList();

    /// <summary>Turns the daemon's per-connection account into one sentence, or two.</summary>
    private void Describe(IReadOnlyList<ConnectionRecord> rows)
    {
        _routingSince ??= DateTimeOffset.UtcNow;
        var patient = DateTimeOffset.UtcNow - _routingSince.Value > TimeSpan.FromSeconds(15);
        var wasRunning = _runningAtStart is { } atStart && _gamePids.Contains(atStart.Pid);
        var (text, warning) = Summarise(rows, RouteName, patient, wasRunning);
        RoutingEvidence = text;
        RoutingEvidenceIsWarning = warning;
        OnPropertyChanged(nameof(HasRoutingEvidence));
    }

    /// <summary>
    /// What the daemon's account of these connections means, in words.
    /// </summary>
    /// <remarks>
    /// Static and pure so the sentences can be tested directly: they are the part of this page
    /// a user will act on when a route appears to do nothing, and the three causes they name —
    /// a proxy in the environment, connections older than the rule, nothing captured at all —
    /// are each a different thing to go and fix.
    /// </remarks>
    /// <param name="patient">True once enough time has passed that silence is worth reporting.</param>
    /// <param name="gameWasRunning">
    /// The game was already running when the session started. Some of its traffic is then on its
    /// old route whatever the rows say: a socket that is not connected to one address — which is
    /// how games commonly send their play — can be neither captured nor reset, and it appears in
    /// no row with a destination, so the only honest thing is to say so and how to fix it.
    /// </param>
    public static (string? Text, bool IsWarning) Summarise(
        IReadOnlyList<ConnectionRecord> rows, string routeName, bool patient, bool gameWasRunning = false)
    {
        var (text, warning) = SummariseRows(rows, routeName, patient);
        return gameWasRunning
            ? (string.Join(" ", new[] { text, Loc.Current["Games.Evidence.StartedWhileRunning"] }.OfType<string>()), true)
            : (text, warning);
    }

    private static (string? Text, bool IsWarning) SummariseRows(
        IReadOnlyList<ConnectionRecord> rows, string routeName, bool patient)
    {
        var routed = rows.Count(r => r.Route == RouteObservation.ConfirmedProxied);
        var preExisting = rows.Count(r => r.Route == RouteObservation.PreExistingPreviousRoute);
        var loopback = rows.Count(r => IPAddress.IsLoopback(r.Remote.Address));
        var direct = rows.Count(r => r.Route == RouteObservation.ConfirmedDirect &&
                                     !IPAddress.IsLoopback(r.Remote.Address));

        var parts = new List<string>();
        if (routed > 0)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Evidence.Routed"],
                routed, routeName));
        }

        if (loopback > 0)
        {
            // The commonest way for a route to do nothing: a proxy set in the environment, so
            // the game talks to something on this machine and never leaves it on its own.
            parts.Add(string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Evidence.LocalProxy"], loopback));
        }

        if (preExisting > 0)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Evidence.PreExisting"], preExisting));
        }

        if (direct > 0)
        {
            parts.Add(string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Evidence.Direct"], direct));
        }

        if (parts.Count > 0)
        {
            return (string.Join(" ", parts), routed == 0);
        }

        // Nothing at all. Worth saying plainly once it has been long enough that the game has
        // certainly tried to connect.
        return patient
            ? (Loc.Current["Games.Evidence.None"] + " " + Loc.Current["Games.Evidence.NoneHint"], true)
            : (Loc.Current["Games.Evidence.Waiting"], false);
    }

    // -- measurements ---------------------------------------------------------

    [ObservableProperty]
    public partial Metric DirectLatency { get; set; } = Metric.NotMeasured;

    [ObservableProperty]
    public partial Metric DirectJitter { get; set; } = Metric.NotMeasured;

    [ObservableProperty]
    public partial Metric DirectLoss { get; set; } = Metric.NotMeasured;

    [ObservableProperty]
    public partial Metric RoutedLatency { get; set; } = Metric.NotMeasured;

    [ObservableProperty]
    public partial Metric RoutedJitter { get; set; } = Metric.NotMeasured;

    [ObservableProperty]
    public partial Metric RoutedLoss { get; set; } = Metric.NotMeasured;

    /// <summary>
    /// The address both sides are measured against. Shown because a latency comparison is
    /// meaningless unless both figures share a target.
    /// </summary>
    [ObservableProperty]
    public partial string? MeasurementTarget { get; set; }

    /// <summary>How the figures were obtained, so they are not mistaken for ICMP ping.</summary>
    [ObservableProperty]
    public partial string? MeasurementMethod { get; set; }

    /// <summary>
    /// Where the routed time went, when the route can say: this far to the exit, that much
    /// further to the game.
    /// </summary>
    /// <remarks>
    /// Only a Yura agent reports it, because only it will measure the destination from where it
    /// is standing. It answers the question the two columns raise but cannot settle — whether a
    /// better agent would help, or whether the problem is this machine's own connection to it.
    /// </remarks>
    [ObservableProperty]
    public partial string? RouteSplit { get; set; }

    public bool HasRouteSplit => RouteSplit is not null;

    [ObservableProperty]
    public partial DateTimeOffset? LastMeasurementUtc { get; set; }

    /// <summary>Target the user can type, for a game whose server is not yet known.</summary>
    [ObservableProperty]
    public partial string MeasurementTargetInput { get; set; } = string.Empty;

    public string LastMeasurementDisplay => LastMeasurementUtc is { } t
        ? t.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture)
        : Loc.Current["Common.NotMeasured"];

    public string MeasurementTargetDisplay => MeasurementTarget ?? Loc.Current["Common.NotMeasured"];

    public string MeasurementMethodDisplay => MeasurementMethod ?? Loc.Current["Common.NotMeasured"];

    public string SessionDurationDisplay
    {
        get
        {
            if (_sessionStartedAt is not { } start)
            {
                return Loc.Current["Common.Unavailable"];
            }

            var elapsed = DateTimeOffset.UtcNow - start;
            return elapsed.ToString(elapsed.TotalHours >= 1 ? @"h\:mm\:ss" : @"mm\:ss",
                CultureInfo.InvariantCulture);
        }
    }

    // -- transport compatibility ----------------------------------------------

    public CapabilityState UdpSupport => SelectedRoute?.UdpSupport ?? CapabilityState.Unknown;

    public string UdpSupportLabel => UdpSupport switch
    {
        CapabilityState.Supported => Loc.Current["Games.UdpSupported"],
        CapabilityState.Unsupported => Loc.Current["Games.UdpUnsupported"],
        _ => Loc.Current["Games.UdpUnknown"],
    };

    /// <summary>
    /// A UDP-incapable route is a functional warning for games, not a footnote, so it gets
    /// a visible banner instead of a subdued caption.
    /// </summary>
    public bool ShowUdpWarning => UdpSupport == CapabilityState.Unsupported;

    public string RouteName => SelectedRoute?.Name ?? Loc.Current["Games.SelectRoute"];

    partial void OnSelectedRouteChanged(RouteOption? value)
    {
        OnPropertyChanged(nameof(UdpSupport));
        OnPropertyChanged(nameof(UdpSupportLabel));
        OnPropertyChanged(nameof(ShowUdpWarning));
        OnPropertyChanged(nameof(RouteName));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(StartBlockedReason));

        // The figures and the NAT verdict belong to the route they were measured over. Kept
        // across a change, the routed column showed one route's numbers under another's name,
        // and the NAT comparison credited the newly chosen route with the old one's verdict.
        if (!IsRunning)
        {
            ClearMeasurements();
            ClearNat();
        }

        if (SelectedGame is { } row && value is not null)
        {
            row.Update(row.Profile with { RouteId = value.Id, RouteIsChain = value.IsChain }, row.Running);
            ProfilesChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    partial void OnSelectedGameChanged(GameRowViewModel? value)
    {
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanMeasure));
        OnPropertyChanged(nameof(CanLaunch));
        OnPropertyChanged(nameof(StartBlockedReason));
        // Measurements belong to a game/route pair; carrying them across would show one
        // game's numbers under another's name.
        ClearMeasurements();
        ClearNat();
        ClearHistory();
        OnPropertyChanged(nameof(StartHint));

        if (value is null)
        {
            return;
        }

        MeasurementTargetInput = value.Profile.IsMeasurable
            ? $"{value.Profile.MeasurementHost}:{value.Profile.MeasurementPort}"
            : string.Empty;

        // Restore the route the profile remembers, so a saved choice survives a restart.
        if (value.Profile.RouteId is { } routeId)
        {
            SelectedRoute = _rules.FindRoute(routeId);
        }
    }

    partial void OnStateChanged(BoostState value)
    {
        OnPropertyChanged(nameof(StateLabel));
        OnPropertyChanged(nameof(IsRunning));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(IsRouting));
        OnPropertyChanged(nameof(IsDegraded));
        OnPropertyChanged(nameof(IsFailed));
        OnPropertyChanged(nameof(IsTransitioning));
        OnPropertyChanged(nameof(StartHint));
        UpdateSampler();
    }

    private void ClearMeasurements()
    {
        DirectLatency = DirectJitter = DirectLoss = Metric.NotMeasured;
        RoutedLatency = RoutedJitter = RoutedLoss = Metric.NotMeasured;
        LastMeasurementUtc = null;
        MeasurementTarget = null;
        MeasurementMethod = null;
        RouteSplit = null;
        OnPropertyChanged(nameof(LastMeasurementDisplay));
        OnPropertyChanged(nameof(MeasurementTargetDisplay));
        OnPropertyChanged(nameof(MeasurementMethodDisplay));
        OnPropertyChanged(nameof(HasRouteSplit));
    }

    private void ClearNat()
    {
        DirectNat = null;
        RoutedNat = null;
        LastNatTestUtc = null;
        _natRouteName = null;
        RaiseNat();
    }

    private void RaiseNat()
    {
        OnPropertyChanged(nameof(HasNatResult));
        OnPropertyChanged(nameof(DirectNatVerdict));
        OnPropertyChanged(nameof(RoutedNatVerdict));
        OnPropertyChanged(nameof(DirectNatNumber));
        OnPropertyChanged(nameof(RoutedNatNumber));
        OnPropertyChanged(nameof(DirectNatDetail));
        OnPropertyChanged(nameof(RoutedNatDetail));
        OnPropertyChanged(nameof(NatComparison));
        OnPropertyChanged(nameof(NatComparisonIsWarning));
        OnPropertyChanged(nameof(HasNatComparisonInfo));
        OnPropertyChanged(nameof(LastNatTestDisplay));
    }

    /// <summary>Design-review hook: puts the page into a running session with a start time.</summary>
    internal void EnterSimulatedSession(BoostState state, TimeSpan elapsed)
    {
        _sessionStartedAt = DateTimeOffset.UtcNow - elapsed;
        State = state;
        _sessionTimer.Start();
    }

    /// <summary>
    /// Measures the target directly and through the selected route, in one pass.
    /// </summary>
    /// <remarks>
    /// Both sides are measured by the daemon, against the same address, by the same method, in
    /// the same call — which is the only way the two columns can honestly sit side by side.
    /// </remarks>
    [RelayCommand]
    private async Task MeasureAsync()
    {
        if (SelectedGame is not { } row)
        {
            return;
        }

        if (!TryParseTarget(MeasurementTargetInput, out var host, out var port))
        {
            FailureReason = Loc.Current["Games.BadTarget"];
            return;
        }

        row.Update(row.Profile with { MeasurementHost = host, MeasurementPort = port }, row.Running);
        ProfilesChanged?.Invoke(this, EventArgs.Empty);

        _measuring?.Cancel();
        var measuring = new CancellationTokenSource();
        _measuring = measuring;
        var token = measuring.Token;

        // A session keeps its own state while it is measured. Switching it to "Testing" made the
        // page believe no session was running: Stop disappeared and Start came back, for as
        // long as the measurement took — up to half a minute against a target that drops
        // connection attempts.
        var inSession = IsRunning;
        var previous = State;
        if (!inSession)
        {
            State = BoostState.Testing;
        }

        IsMeasuring = true;
        FailureReason = null;

        try
        {
            var (proxyId, chainId) = SelectedRoute is { } route
                ? route.IsChain ? ((Guid?)null, (Guid?)route.Id) : (route.Id, null)
                : (null, null);

            var measurement = await _daemon.MeasureAsync(host, port, proxyId, chainId, 5, token).ConfigureAwait(true);
            if (token.IsCancellationRequested)
            {
                return;
            }

            if (measurement is null)
            {
                FailureReason = _daemon.State == DaemonState.Connected
                    ? Loc.Current["Games.MeasureFailed"]
                    : _daemon.UnavailableReason;
                return;
            }

            Apply(measurement);
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer measurement; that one reports.
        }
        finally
        {
            if (!inSession && State == BoostState.Testing)
            {
                State = previous == BoostState.Testing ? BoostState.Ready : previous;
            }

            // A newer measurement that replaced this one owns the flag now.
            if (ReferenceEquals(_measuring, measuring))
            {
                IsMeasuring = false;
            }
        }
    }

    private void Apply(MeasurementDto measurement)
    {
        MeasurementTarget = measurement.Target;
        MeasurementMethod = measurement.Method;
        LastMeasurementUtc = measurement.MeasuredAtUtc;
        RouteSplit = measurement.RouteAnswersBeforeConnecting
            ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.RouteAnswersEarly"], RouteName)
            : Describe(measurement.Legs);
        OnPropertyChanged(nameof(HasRouteSplit));

        DirectLatency = new Metric(measurement.Direct.LatencyMilliseconds, "ms");
        DirectJitter = new Metric(measurement.Direct.JitterMilliseconds, "ms");
        DirectLoss = new Metric(measurement.Direct.LossPercent, "%");

        if (measurement.Routed is { } routed)
        {
            RoutedLatency = new Metric(routed.LatencyMilliseconds, "ms");
            RoutedJitter = new Metric(routed.JitterMilliseconds, "ms");
            RoutedLoss = new Metric(routed.LossPercent, "%");

            // A route that cannot carry the traffic at all is a degraded session, not a
            // successful one with bad numbers.
            if (State is BoostState.Routing && routed.Successes == 0)
            {
                State = BoostState.Degraded;
                FailureReason = routed.FailureReason;
            }
        }
        else
        {
            RoutedLatency = RoutedJitter = RoutedLoss = Metric.NotMeasured;
        }

        OnPropertyChanged(nameof(LastMeasurementDisplay));
        OnPropertyChanged(nameof(MeasurementTargetDisplay));
        OnPropertyChanged(nameof(MeasurementMethodDisplay));
    }

    // -- the session's monitor ------------------------------------------------

    /// <summary>The session's samples, which the chart draws.</summary>
    public BoostHistory History { get; } = new();

    /// <summary>Changes with every sample, which is what makes the chart redraw.</summary>
    [ObservableProperty]
    public partial int HistoryVersion { get; set; }

    private DateTimeOffset? _sessionEndedAt;

    /// <summary>
    /// The route's proxy reports connections made before it makes them, so the route has no
    /// figure: the daemon found out on this session's first sample.
    /// </summary>
    private bool _routeAnswersEarly;

    /// <summary>The server the samples in <see cref="History"/> are of.</summary>
    private string? _historyTarget;

    public bool HasHistory => !History.IsEmpty;

    /// <summary>The monitor's card shows for the whole session, and afterwards until another starts.</summary>
    public bool ShowMonitor => IsRunning || HasHistory;

    public string MonitorRouteLabel => string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.Through"], RouteName);

    public string MonitorNowDisplay => History.Latest is not { } latest
        ? Loc.Current["Common.NotMeasured"]
        : RouteMilliseconds(latest.RoutedMilliseconds);

    public string MonitorNowDirect => Direct(History.Latest is { } latest ? Milliseconds(latest.DirectMilliseconds) : null);

    public string MonitorAverageDisplay => History.IsEmpty ? Loc.Current["Common.NotMeasured"] : RouteMilliseconds(History.RouteAverage);

    public string MonitorAverageDirect => Direct(History.IsEmpty ? null : Milliseconds(History.DirectAverage));

    public string MonitorJitterDisplay => Jitter(History.RouteJitter, History.Samples.Count < 2 || _routeAnswersEarly);

    public string MonitorJitterDirect => Direct(History.Samples.Count < 2 ? null : Jitter(History.DirectJitter, false));

    public string MonitorLossDisplay => Percent(History.RouteLossPercent);

    public string MonitorLossDirect => Direct(History.IsEmpty ? null : Percent(History.DirectLossPercent));

    /// <summary>Any loss in the last minute: the tile says so with an icon, not with colour alone.</summary>
    public bool MonitorLossIsWarning => History.RouteLossPercent > 0;

    /// <summary>What the monitor is measuring, and where that target came from.</summary>
    public string? MonitorTargetDisplay => IsRunning && MonitorTarget() is { } target
        ? string.Format(CultureInfo.CurrentCulture,
            Loc.Current[target.Typed ? "Games.Monitor.TargetTyped" : "Games.Monitor.TargetAuto"],
            Endpoint(target.Host, target.Port))
        : null;

    /// <summary>Why the chart is empty or what it is waiting for, when it is either.</summary>
    public string? MonitorStatus
    {
        get
        {
            if (State == BoostState.WaitingForGame)
            {
                return Loc.Current[HasHistory ? "Games.Monitor.Paused" : "Games.Monitor.WaitingForGame"];
            }

            if (!IsRunning)
            {
                return _sessionEndedAt is { } ended && HasHistory
                    ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.Ended"],
                        ended.ToLocalTime().ToString("HH:mm", CultureInfo.CurrentCulture))
                    : null;
            }

            if (MonitorTarget() is not { } target)
            {
                return Loc.Current["Games.Monitor.WaitingForTarget"];
            }

            var endpoint = Endpoint(target.Host, target.Port);
            if (History.IsEmpty)
            {
                return string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.Measuring"], endpoint);
            }

            if (_routeAnswersEarly)
            {
                return string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.RouteAnswersEarly"], RouteName);
            }

            if (!History.RouteHasAnswered)
            {
                if (History.Samples.Count < 5)
                {
                    return string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.WaitingForAnswer"], endpoint);
                }

                // Not loss: a target that has never answered is a target that does not answer
                // probes, and saying 100 % would blame the route for it. Answering directly and
                // never through the route is the route's doing, and is said so.
                return History.DirectFirstAnswered is not null
                    ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.RouteNotAnswering"], endpoint, RouteName)
                    : string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.NotAnswering"], endpoint);
            }

            return null;
        }
    }

    public bool HasMonitorStatus => MonitorStatus is not null;

    /// <summary>The chart in one sentence, for a screen reader.</summary>
    public string MonitorSummary => string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.Summary"],
        RouteName, MonitorNowDisplay, MonitorNowDirect, MonitorLossDisplay);

    /// <summary>The last twenty samples, newest first: every value the chart shows, readable without it.</summary>
    public IReadOnlyList<BoostSampleRow> RecentSamples => History.Samples
        .Reverse()
        .Take(20)
        .Select(s => new BoostSampleRow(
            s.At.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture),
            RouteMilliseconds(s.RoutedMilliseconds),
            Milliseconds(s.DirectMilliseconds)))
        .ToList();

    /// <summary>What the chart's tooltip says for a route sample with no figure.</summary>
    public string MonitorRouteMissingLabel => Loc.Current[_routeAnswersEarly ? "Common.NotMeasured" : "Games.Monitor.NoAnswer"];

    private static string Milliseconds(double? value) => value is { } v
        ? string.Create(CultureInfo.CurrentCulture, $"{v:0} ms")
        : Loc.Current["Games.Monitor.NoAnswer"];

    private string RouteMilliseconds(double? value) => value is null ? MonitorRouteMissingLabel : Milliseconds(value);

    /// <summary>Jitter keeps a decimal: it is a few milliseconds, where latency is tens.</summary>
    private static string Jitter(double? value, bool notYet) => notYet
        ? Loc.Current["Common.NotMeasured"]
        : value is { } v ? string.Create(CultureInfo.CurrentCulture, $"{v:0.#} ms") : Loc.Current["Games.Monitor.NoAnswer"];

    private static string Percent(double? value) => value is { } v
        ? string.Create(CultureInfo.CurrentCulture, $"{v:0.#} %")
        : Loc.Current["Common.NotMeasured"];

    private static string Direct(string? value) => value is null
        ? string.Empty
        : string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Monitor.DirectValue"], value);

    private static string Endpoint(string host, ushort port) =>
        host.Contains(':', StringComparison.Ordinal) ? $"[{host}]:{port}" : $"{host}:{port}";

    /// <summary>The target typed in, or saved with the game; failing that, the game's busiest server.</summary>
    private (string Host, ushort Port, bool Typed)? MonitorTarget() =>
        TryParseTarget(MeasurementTargetInput, out var host, out var port)
            ? (host, port, true)
            : _autoTarget is { } auto
                ? (auto.Address.ToString(), (ushort)auto.Port, false)
                : null;

    /// <summary>Runs the monitor while the game is routed, and only then.</summary>
    private void UpdateSampler()
    {
        var routing = State is BoostState.Routing or BoostState.Degraded;
        if (routing && !_sampleTimer.IsEnabled)
        {
            _sampleTimer.Start();
            _ = SampleAsync();
        }
        else if (!routing && _sampleTimer.IsEnabled)
        {
            _sampleTimer.Stop();
            _sampling?.Cancel();
        }

        RaiseMonitor();
    }

    /// <summary>
    /// One tick: the target probed once through the route and once directly, by the daemon.
    /// </summary>
    /// <remarks>
    /// One probe a side keeps the cost to a few small connections every few seconds, and the
    /// chart's loss comes from many ticks rather than from many probes in one. A tick still
    /// running when the next is due is not doubled up: an unanswered probe waits seconds.
    /// </remarks>
    internal async Task SampleAsync()
    {
        if (_sampleInFlight || _daemon.State != DaemonState.Connected || SelectedRoute is not { } route ||
            State is not (BoostState.Routing or BoostState.Degraded))
        {
            return;
        }

        if (MonitorTarget() is not { } target)
        {
            RaiseMonitor();
            return;
        }

        _sampleInFlight = true;
        var sampling = new CancellationTokenSource();
        _sampling = sampling;
        var endpoint = Endpoint(target.Host, target.Port);
        try
        {
            var (proxyId, chainId) = route.IsChain ? ((Guid?)null, (Guid?)route.Id) : (route.Id, null);
            var measurement = await _daemon.MeasureAsync(target.Host, target.Port, proxyId, chainId, 1, sampling.Token)
                .ConfigureAwait(true);
            if (measurement is null || sampling.IsCancellationRequested ||
                State is not (BoostState.Routing or BoostState.Degraded) ||
                MonitorTarget() is not { } now || Endpoint(now.Host, now.Port) != endpoint)
            {
                return;
            }

            // The history is one server's. Carried over to the next, the last server's answers
            // made every probe the new one ignores count as loss: a game's first server is often
            // a web API that answers, and the relay it moves to may answer no probe at all, as
            // PlayFab's do not. That drew a route losing everything, where the page means to say
            // the server does not answer.
            if (_historyTarget != endpoint)
            {
                History.Clear();
                _historyTarget = endpoint;
            }

            _routeAnswersEarly = measurement.RouteAnswersBeforeConnecting;
            History.Add(ToSample(measurement, route.IsChain));
            HistoryVersion = History.Version;
            LastMeasurementUtc = measurement.MeasuredAtUtc;
            OnPropertyChanged(nameof(LastMeasurementDisplay));
            RaiseMonitor();
        }
        catch (OperationCanceledException)
        {
            // The session stopped, or left routing, while the probe was out.
        }
        finally
        {
            _sampleInFlight = false;
        }
    }

    /// <summary>
    /// One measurement as one sample: the route's round trip and the direct one, or null for a
    /// side that got no answer.
    /// </summary>
    /// <remarks>
    /// Through a single agent the route's figure is its two halves added up: the round trip to the
    /// agent, and the agent's own probe of the target from where it stands. That is the path a
    /// game's datagrams take. The connect through the agent that the daemon also measures opens a
    /// fresh TLS stream each time, and its handshakes would be counted as latency the game never
    /// sees. A chain is measured end to end, because the agent's own probe skips the hops after it.
    /// </remarks>
    internal static LatencySample ToSample(MeasurementDto measurement, bool routeIsChain)
    {
        double? routed;
        if (!routeIsChain && measurement.Legs is { } legs)
        {
            routed = legs.ToAgentMilliseconds is { } to && legs.FromAgentMilliseconds is { } from ? to + from : null;
        }
        else
        {
            routed = measurement.Routed is { Successes: > 0 } r ? r.LatencyMilliseconds : null;
        }

        var direct = measurement.Direct is { Successes: > 0 } d ? d.LatencyMilliseconds : null;
        return new LatencySample(measurement.MeasuredAtUtc, routed, direct);
    }

    /// <summary>
    /// Takes the monitor's target from the game's own connections, when none was typed.
    /// </summary>
    /// <remarks>
    /// Kept for as long as the game still talks to it, so the chart does not hop between servers
    /// every time another connection briefly carries more.
    /// </remarks>
    private void UpdateAutoTarget(IReadOnlyList<ConnectionRecord> rows)
    {
        if (_autoTarget is { } current && rows.Any(r => r.Remote.Equals(current)))
        {
            return;
        }

        if (PickServer(rows) is not { } picked || picked.Equals(_autoTarget))
        {
            return;
        }

        _autoTarget = picked;
        RaiseMonitor();
        _ = SampleAsync();
    }

    /// <summary>
    /// The server the game is talking to most: its busiest connection to an address on the
    /// internet, a datagram one first, since that is where a game's play happens.
    /// </summary>
    /// <remarks>
    /// Whether or not the route is carrying it. One the route carries is preferred, but a game
    /// whose play is still going out directly — it was running before the boost — is measured
    /// all the same: what the route would give it is exactly the question, and requiring a routed
    /// connection left the chart empty in the case that most needed it.
    /// </remarks>
    internal static IPEndPoint? PickServer(IReadOnlyList<ConnectionRecord> rows) => rows
        .Where(r => r.Remote.Port is not (0 or 53) && IsInternetAddress(r.Remote.Address))
        .OrderByDescending(r => r.Protocol == TransportProtocol.Udp)
        .ThenByDescending(r => r.Route == RouteObservation.ConfirmedProxied)
        .ThenByDescending(r => (r.BytesUp ?? 0) + (r.BytesDown ?? 0))
        .Select(r => r.Remote)
        .FirstOrDefault();

    /// <summary>Not this machine, not a private network, not multicast: somewhere a game server can be.</summary>
    private static bool IsInternetAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address))
        {
            return false;
        }

        var b = address.GetAddressBytes();
        return !(b[0] is 0 or 10 or >= 224 ||
                 (b[0] == 172 && b[1] is >= 16 and <= 31) ||
                 (b[0] == 192 && b[1] == 168) ||
                 (b[0] == 169 && b[1] == 254) ||
                 (b[0] == 100 && b[1] is >= 64 and <= 127));
    }

    private void ClearHistory()
    {
        History.Clear();
        HistoryVersion = History.Version;
        _historyTarget = null;
        _sessionEndedAt = null;
        _routeAnswersEarly = false;
        RaiseMonitor();
    }

    /// <summary>Design-review hook: a session's worth of samples, so the chart has something to show.</summary>
    internal void SeedHistory(IEnumerable<LatencySample> samples)
    {
        History.Clear();
        _historyTarget = MonitorTarget() is { } target ? Endpoint(target.Host, target.Port) : null;
        foreach (var sample in samples)
        {
            History.Add(sample);
        }

        HistoryVersion = History.Version;
        RaiseMonitor();
    }

    private void RaiseMonitor()
    {
        OnPropertyChanged(nameof(HasHistory));
        OnPropertyChanged(nameof(ShowMonitor));
        OnPropertyChanged(nameof(MonitorRouteLabel));
        OnPropertyChanged(nameof(MonitorNowDisplay));
        OnPropertyChanged(nameof(MonitorNowDirect));
        OnPropertyChanged(nameof(MonitorAverageDisplay));
        OnPropertyChanged(nameof(MonitorAverageDirect));
        OnPropertyChanged(nameof(MonitorJitterDisplay));
        OnPropertyChanged(nameof(MonitorJitterDirect));
        OnPropertyChanged(nameof(MonitorLossDisplay));
        OnPropertyChanged(nameof(MonitorLossDirect));
        OnPropertyChanged(nameof(MonitorLossIsWarning));
        OnPropertyChanged(nameof(MonitorTargetDisplay));
        OnPropertyChanged(nameof(MonitorStatus));
        OnPropertyChanged(nameof(HasMonitorStatus));
        OnPropertyChanged(nameof(MonitorSummary));
        OnPropertyChanged(nameof(MonitorRouteMissingLabel));
        OnPropertyChanged(nameof(RecentSamples));
    }

    // -- NAT type -------------------------------------------------------------

    /// <summary>
    /// What the direct path looks like to a peer, and what the route looks like.
    /// </summary>
    /// <remarks>
    /// Separate from the latency measurement because it answers a different question and
    /// costs different traffic: latency asks "how fast", this asks "can another player reach
    /// me at all". For a peer-to-peer game the second one decides whether there is a match to
    /// have, and routing can move it in either direction — a proxy on a public address can
    /// turn Strict into Open, and a badly chosen one can do the opposite.
    /// </remarks>
    [ObservableProperty]
    public partial NatReportDto? DirectNat { get; set; }

    [ObservableProperty]
    public partial NatReportDto? RoutedNat { get; set; }

    [ObservableProperty]
    public partial DateTimeOffset? LastNatTestUtc { get; set; }

    public bool HasNatResult => DirectNat is not null || RoutedNat is not null;

    public string DirectNatVerdict => VerdictLabel(DirectNat);

    public string RoutedNatVerdict => VerdictLabel(RoutedNat);

    /// <summary>NAT1 to NAT4 beside the verdict, or "NAT2 or NAT3" for a Moderate whose filtering is not known.</summary>
    public string? DirectNatNumber => NumberLabel(DirectNat);

    public string? RoutedNatNumber => NumberLabel(RoutedNat);

    public string DirectNatDetail => Detail(DirectNat);

    public string RoutedNatDetail => Detail(RoutedNat);

    /// <summary>
    /// Said plainly when routing makes peer-to-peer worse, because that is the one outcome a
    /// player would otherwise discover from their friends failing to join.
    /// </summary>
    public string? NatComparison
    {
        get
        {
            // Named after the route the test ran over, which is not necessarily the one
            // selected now.
            var routeName = _natRouteName ?? RouteName;
            return CompareNat() switch
            {
                NatChange.Worse => string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Nat.WorseOnRoute"], routeName),
                NatChange.Better => string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Nat.BetterOnRoute"], routeName),
                NatChange.None => Loc.Current["Games.Nat.Same"],
                _ => null,
            };
        }
    }

    public bool NatComparisonIsWarning => CompareNat() == NatChange.Worse;

    /// <summary>The comparison when it is not a warning, which the page shows in the neutral style.</summary>
    public bool HasNatComparisonInfo => NatComparison is not null && !NatComparisonIsWarning;

    public string LastNatTestDisplay => LastNatTestUtc is { } t
        ? t.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture)
        : Loc.Current["Common.NotMeasured"];

    public bool CanTestNat => _daemon.State == DaemonState.Connected && !IsTestingNat;

    [ObservableProperty]
    public partial bool IsTestingNat { get; set; }

    private enum NatChange
    {
        /// <summary>Not established either way.</summary>
        Unknown,

        None,

        Better,

        Worse,
    }

    /// <summary>Whether the route lets more players connect than going direct, or fewer.</summary>
    /// <remarks>
    /// Judged by who can connect, because that is what a player notices. A NAT2 to NAT3 change
    /// is a real loss though both are Moderate: a NAT3 cannot reach a NAT4 player. NAT1 to NAT2
    /// is not, since hole punching gets a NAT2 to every kind. A label that differs without
    /// changing who can connect gets no sentence, and nor does a pair the measurement leaves open.
    /// </remarks>
    private NatChange CompareNat()
    {
        if (DirectNat is not { } direct || RoutedNat is not { } routed ||
            Reach(direct) is not { } before || Reach(routed) is not { } after)
        {
            return NatChange.Unknown;
        }

        if (after.Most < before.Least)
        {
            return NatChange.Worse;
        }

        if (after.Least > before.Most)
        {
            return NatChange.Better;
        }

        var settled = direct.TypeNumber() is not null || direct.Verdict == NatVerdict.Blocked;
        return settled && routed.Verdict == direct.Verdict && routed.TypeNumber() == direct.TypeNumber()
            ? NatChange.None
            : NatChange.Unknown;
    }

    /// <summary>
    /// Which players can connect, from 3, everyone, through 2, all but NAT4, and 1, NAT1 and NAT2
    /// only, to 0, nobody. A range, because a Moderate with unknown filtering is one of two.
    /// </summary>
    private static (int Least, int Most)? Reach(NatReportDto report) => report.Verdict switch
    {
        NatVerdict.Open => (3, 3),
        NatVerdict.Moderate => report.TypeNumber() switch
        {
            2 => (3, 3),
            3 => (2, 2),
            _ => (2, 3),
        },
        NatVerdict.Strict => (1, 1),
        NatVerdict.Blocked => (0, 0),
        _ => null,
    };

    /// <summary>The number players use: NAT1 to NAT4, and for a Moderate not settled, the two it can be.</summary>
    private static string? NumberLabel(NatReportDto? report)
    {
        if (report?.TypeNumber() is { } number)
        {
            return string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Nat.Number"], number);
        }

        return report?.Verdict == NatVerdict.Moderate ? Loc.Current["Games.Nat.TwoOrThree"] : null;
    }

    /// <summary>The verdict in the words games use, or plainly that it is not known.</summary>
    private static string VerdictLabel(NatReportDto? report) => report?.Verdict switch
    {
        NatVerdict.Open => Loc.Current["Games.Nat.Open"],
        NatVerdict.Moderate => Loc.Current["Games.Nat.Moderate"],
        NatVerdict.Strict => Loc.Current["Games.Nat.Strict"],
        NatVerdict.Blocked => Loc.Current["Games.Nat.Blocked"],
        _ => Loc.Current["Common.Unavailable"],
    };

    /// <summary>
    /// The behaviour behind the verdict, in one line.
    /// </summary>
    /// <remarks>
    /// The verdict alone is a label; this is the part that can be acted on. It says what the
    /// mapping does, whether the filtering question was answered at all, and which address a
    /// peer would be told to use.
    /// </remarks>
    private static string Detail(NatReportDto? report)
    {
        if (report is null)
        {
            return Loc.Current["Common.NotMeasured"];
        }

        var mapping = report.Mapping switch
        {
            NatMapping.EndpointIndependent => Loc.Current["Games.Nat.MappingStable"],
            NatMapping.AddressDependent or NatMapping.AddressAndPortDependent or NatMapping.DestinationDependent =>
                Loc.Current["Games.Nat.MappingVaries"],
            _ => Loc.Current["Games.Nat.MappingUnknown"],
        };

        // A mapping that changes per peer is Strict whatever gets in, and the probe does not ask.
        var filtering = report.Filtering switch
        {
            NatFiltering.EndpointIndependent => Loc.Current["Games.Nat.FilterOpen"],
            NatFiltering.AddressDependent => Loc.Current["Games.Nat.FilterAddress"],
            NatFiltering.AddressAndPortDependent => Loc.Current["Games.Nat.FilterStrict"],
            _ when report.Verdict == NatVerdict.Strict => null,
            _ => Loc.Current["Games.Nat.FilterUnknown"],
        };

        var seen = report.MappedEndpoint is { Length: > 0 } endpoint
            ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Nat.SeenAs"], endpoint)
            : null;

        return string.Join(" ", new[] { mapping, filtering, seen }.Where(s => s is { Length: > 0 }));
    }

    /// <summary>
    /// Tests the NAT behaviour of both paths, in one call, through the daemon.
    /// </summary>
    /// <remarks>
    /// The daemon has to do it: the test must leave by the route the game's traffic leaves by,
    /// and only the daemon can originate traffic inside a WireGuard exit or on a proxy's UDP
    /// association. Both paths are tested in the same call against the same servers, for the
    /// same reason the latency figures are.
    /// </remarks>
    [RelayCommand]
    private async Task TestNatAsync()
    {
        if (IsTestingNat)
        {
            return;
        }

        IsTestingNat = true;
        FailureReason = null;
        OnPropertyChanged(nameof(CanTestNat));
        try
        {
            var (proxyId, chainId) = SelectedRoute is { } route
                ? route.IsChain ? ((Guid?)null, (Guid?)route.Id) : (route.Id, null)
                : (null, null);

            var result = await _daemon.TestNatAsync(proxyId, chainId).ConfigureAwait(true);
            if (result is null)
            {
                FailureReason = _daemon.State == DaemonState.Connected
                    ? Loc.Current["Games.Nat.Failed"]
                    : _daemon.UnavailableReason;
                return;
            }

            DirectNat = result.Direct;
            RoutedNat = result.Routed;
            LastNatTestUtc = result.TestedAtUtc;
            _natRouteName = result.RouteName;
            RaiseNat();
        }
        finally
        {
            IsTestingNat = false;
            OnPropertyChanged(nameof(CanTestNat));
        }
    }

    /// <summary>The two halves of an agent route in one sentence, or null when unknown.</summary>
    private static string? Describe(RouteLegsDto? legs)
    {
        if (legs is null)
        {
            return null;
        }

        var toAgent = legs.ToAgentMilliseconds is { } to
            ? string.Create(CultureInfo.CurrentCulture, $"{to:0.#} ms")
            : Loc.Current["Common.NotMeasured"];

        if (legs.FromAgentMilliseconds is { } from)
        {
            return string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.RouteSplit"],
                legs.AgentName, toAgent, string.Create(CultureInfo.CurrentCulture, $"{from:0.#} ms"));
        }

        return string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.RouteSplitPartial"],
            legs.AgentName, toAgent, legs.Failure ?? Loc.Current["Common.Unknown"]);
    }

    private static bool TryParseTarget(string text, out string host, out ushort port)
    {
        host = string.Empty;
        port = 0;
        text = text.Trim();
        if (text.Length == 0)
        {
            return false;
        }

        var colon = text.LastIndexOf(':');
        if (colon <= 0 || !ushort.TryParse(text.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port == 0)
        {
            return false;
        }

        host = text[..colon].Trim('[', ']');
        return host.Length > 0;
    }

    // -- session --------------------------------------------------------------

    [RelayCommand]
    private async Task StartBoostAsync()
    {
        if (SelectedGame is not { } row || SelectedRoute is null || IsRunning)
        {
            return;
        }

        FailureReason = null;
        State = BoostState.Starting;
        RoutingEvidence = null;
        RoutingEvidenceIsWarning = false;
        _routingSince = null;
        _autoTarget = null;
        _runningAtStart = row.Running?.Identity;
        ClearHistory();
        _sessionStartedAt = DateTimeOffset.UtcNow;
        _sessionTimer.Start();
        _attachTimer.Start();

        if (_daemon.State != DaemonState.Connected)
        {
            Fail(_daemon.UnavailableReason);
            return;
        }

        _sessionGame = row;

        // The rule is the session. A game profile is an ordinary rule in the shared list, so
        // its precedence against a manual selection is visible on the Rules page.
        var (selector, learned) = BuildSelector(row);
        if (selector is null)
        {
            // Nothing to match yet, and nothing running to learn it from: a game Steam knows only
            // by its folder, never started under Yura. The session waits for it, and the moment it
            // appears it is given a rule matching what it turned out to be.
            State = BoostState.WaitingForGame;
            StatusMessage = string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Armed"], row.Name);
            return;
        }

        if (learned is not null)
        {
            row.Update(learned, row.Running);
            ProfilesChanged?.Invoke(this, EventArgs.Empty);
        }

        // A boost is usually asked for while the game is already running and talking to its
        // servers, so the connections that matter are the ones that exist. They cannot be
        // captured where they are — a socket's cgroup is fixed when it is created — so the
        // daemon drops them and the game reconnects through the route. Asked for before the
        // game starts, the rule is in place at its first connection and there is nothing to drop.
        if (await ApplySessionRuleAsync(row, selector).ConfigureAwait(true) is not { } result)
        {
            return;
        }

        State = row.Running is null ? BoostState.WaitingForGame : BoostState.Routing;
        StatusMessage = row.Running is null
            ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.ArmedWithRule"], row.Name)
            : (result.ResetConnections, result.PreExistingConnections) switch
            {
                ( > 0, _) => string.Format(
                    CultureInfo.CurrentCulture, Loc.Current["Games.StartedWithReset"], result.ResetConnections),
                (_, > 0) => string.Format(
                    CultureInfo.CurrentCulture, Loc.Current["Games.StartedWithExisting"], result.PreExistingConnections),
                _ => Loc.Current["Games.Started"],
            };

        // Numbers the moment the session starts, if we know where to measure.
        if (row.Running is not null && (row.Profile.IsMeasurable || TryParseTarget(MeasurementTargetInput, out _, out _)))
        {
            await MeasureAsync().ConfigureAwait(true);
        }
    }

    /// <summary>
    /// Installs the session's rule for <paramref name="row"/>, in place of any rule of the game's
    /// that it supersedes.
    /// </summary>
    /// <returns>The daemon's account, or null when it failed and the session has failed with it.</returns>
    private async Task<RuleApplyResult?> ApplySessionRuleAsync(GameRowViewModel row, ProcessSelector selector)
    {
        var built = new RoutingRule
        {
            Id = Guid.NewGuid(),
            Order = _rules.NextOrder(RuleOrigin.GameProfile),
            Name = string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.RuleName"], row.Name),
            Origin = RuleOrigin.GameProfile,
            // A session lasts as long as the daemon does: it is not written to the config,
            // because a boost the user did not ask for again should not come back.
            Lifetime = RuleLifetime.Session,
            Process = selector,
            Destination = DestinationSelector.Any,
            Action = SelectedRoute!.ToAction(),
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };

        // A boost for a game that still has one replaces it in place — same id, same position —
        // so the daemon swaps the rules in one step and the connections it resets are the ones
        // the change actually moves. See ProcessesPageViewModel.ApplyAsync.
        var rule = _rules.FindSupersededBy(built) is { } previous
            ? built with { Id = previous.Id, Order = previous.Order }
            : built;

        var result = await _daemon.ApplyRuleAsync(rule, resetExisting: true).ConfigureAwait(true);
        if (!result.Succeeded)
        {
            Fail(result.FailureReason);
            return null;
        }

        _sessionRule = rule;
        foreach (var superseded in _rules.Add(rule with { AppliedAtUtc = result.ConfirmedAtUtc }))
        {
            // Also out of the kernel: left installed, it would go on deciding the game's route
            // from its own position.
            await _daemon.RemoveRuleAsync(superseded.Id).ConfigureAwait(true);
        }

        return result;
    }

    /// <summary>
    /// The game a waiting session was started for has appeared: route it, and remember what it is.
    /// </summary>
    /// <remarks>
    /// It has been running for up to a couple of seconds, long enough to have opened connections
    /// the rule cannot reach where they are, so those are dropped and reconnect through the route.
    /// What is learned is saved with the game, so the next boost has its rule in place before the
    /// game's first connection and nothing has to be dropped at all.
    /// </remarks>
    private async Task RouteArrivedGameAsync(GameRowViewModel row, ProcessSnapshot process)
    {
        if (_arrivalInFlight || SelectedRoute is null)
        {
            return;
        }

        _arrivalInFlight = true;
        try
        {
            if (_sessionRule is { Process.Kind: ProcessSelectorKind.Instance } earlier)
            {
                // A rule for an earlier run of the game, matched by process: that process is gone.
                await _daemon.RemoveRuleAsync(earlier.Id).ConfigureAwait(true);
                _rules.Remove(earlier.Id);
                _sessionRule = null;
            }

            // What the profile knows by now comes first: the game may have been learned during an
            // earlier run of this session, routed by process.
            var (selector, learned) = BuildSelector(row);
            if (selector is null)
            {
                return;
            }

            if (learned is not null)
            {
                row.Update(learned, process);
                ProfilesChanged?.Invoke(this, EventArgs.Empty);
            }

            var result = await ApplySessionRuleAsync(row, selector).ConfigureAwait(true);
            if (result is null)
            {
                return;
            }

            if (!ReferenceEquals(_sessionGame, row) || State != BoostState.WaitingForGame)
            {
                // Stopped while the rule was going in: it belongs to no session now.
                if (_sessionRule is { } orphan)
                {
                    await _daemon.RemoveRuleAsync(orphan.Id).ConfigureAwait(true);
                    _rules.Remove(orphan.Id);
                    _sessionRule = null;
                }

                return;
            }

            State = BoostState.Routing;
            var routed = string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.Arrived"], row.Name, RouteName);
            var reset = result.ResetConnections > 0
                ? " " + string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.ArrivedReset"], result.ResetConnections)
                : string.Empty;
            var thisRun = selector.Kind == ProcessSelectorKind.Instance
                ? " " + Loc.Current["Games.ArrivedThisRunOnly"]
                : string.Empty;
            StatusMessage = routed + reset + thisRun;
        }
        finally
        {
            _arrivalInFlight = false;
        }
    }

    /// <summary>
    /// What to match a game that has just appeared, and what about it is worth remembering.
    /// </summary>
    /// <remarks>
    /// Only what is evidently the game's own is remembered: a Windows executable or a binary
    /// inside the game's folder, under <c>steamapps/common/&lt;this game&gt;</c>. A game found by
    /// its Steam app id can be running from outside it, through a Proton or Steam runtime wrapper
    /// every other game shares, and a rule for that binary would route all of them. That run is
    /// routed by process instead, and nothing is remembered.
    /// </remarks>
    /// <returns>The selector, and the profile with what was learned, or null for the profile when nothing was.</returns>
    internal static (ProcessSelector Selector, GameProfile? Learned) LearnSelector(GameProfile profile, ProcessSnapshot process)
    {
        if (process.Wine?.TargetExecutable is { Length: > 0 } wine && profile.MatchesInstalledPath(wine))
        {
            return (new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = process.ExecutablePath,
                WineTargetExecutable = wine,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            }, profile with
            {
                ExecutablePath = process.ExecutablePath,
                WineTargetExecutable = wine,
                SteamAppId = profile.SteamAppId ?? process.SteamAppId,
            });
        }

        if (process.ExecutablePath is { Length: > 0 } path && profile.MatchesInstalledPath(path))
        {
            return (new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = path,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            }, profile with { ExecutablePath = path, SteamAppId = profile.SteamAppId ?? process.SteamAppId });
        }

        return (new ProcessSelector
        {
            Kind = ProcessSelectorKind.Instance,
            Identity = process.Identity,
            Descendants = DescendantPolicy.IncludeExistingAndFuture,
        }, null);
    }

    /// <summary>
    /// Works out what the session's rule should match.
    /// </summary>
    /// <remarks>
    /// Prefers the Wine target, because that is the only thing that distinguishes two games
    /// sharing a runtime. Falls back to the executable path. A profile with no path at all — a
    /// Steam game that has never been attached — is matched by what its running process turns
    /// out to be, as in <see cref="LearnSelector"/>, and by nothing while it is not running.
    /// </remarks>
    /// <returns>
    /// The selector, or null when there is nothing to match yet; and the profile with what was
    /// learned from the running game, or null when nothing was.
    /// </returns>
    private static (ProcessSelector? Selector, GameProfile? Learned) BuildSelector(GameRowViewModel row)
    {
        var profile = row.Profile;

        if (profile.WineTargetExecutable is { Length: > 0 } wine)
        {
            return (new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = profile.ExecutablePath ?? row.Running?.ExecutablePath,
                WineTargetExecutable = wine,
                // Games spawn helpers — launchers, anti-cheat, crash handlers — that need the
                // same route, and they are all children.
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            }, null);
        }

        if (profile.ExecutablePath is { Length: > 0 } path)
        {
            return (new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = path,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            }, null);
        }

        return row.Running is { } running ? LearnSelector(profile, running) : (null, null);
    }

    private void Fail(string? reason)
    {
        State = BoostState.Failed;
        FailureReason = reason;
        _sessionTimer.Stop();
        _attachTimer.Stop();
        _sessionStartedAt = null;
    }

    [RelayCommand]
    private async Task StopBoostAsync()
    {
        State = BoostState.Stopping;
        _measuring?.Cancel();

        if (_sessionRule is { } rule)
        {
            var result = await _daemon.RemoveRuleAsync(rule.Id).ConfigureAwait(true);
            if (!result.Succeeded)
            {
                // The rule is still installed, so the session has not actually stopped.
                Fail(result.FailureReason);
                return;
            }

            _rules.Remove(rule.Id);
            _sessionRule = null;
        }

        _sessionGame = null;
        _sessionTimer.Stop();
        _attachTimer.Stop();
        _sessionStartedAt = null;
        _sessionEndedAt = DateTimeOffset.UtcNow;
        _autoTarget = null;
        _runningAtStart = null;
        _routingSince = null;
        RoutingEvidence = null;
        RoutingEvidenceIsWarning = false;
        OnPropertyChanged(nameof(HasRoutingEvidence));
        State = BoostState.Ready;
        StatusMessage = Loc.Current["Games.Stopped"];
        ClearMeasurements();
    }

    /// <summary>
    /// Launches a Steam game, then waits for it to appear.
    /// </summary>
    /// <remarks>
    /// Launching through Steam's own URL handler rather than executing a binary: Steam has to
    /// set up the Proton prefix and its own environment, and a game started any other way
    /// behaves differently. Yura attaches to whatever appears, which is the same path a game
    /// the user started themselves takes.
    /// </remarks>
    [RelayCommand]
    private void LaunchGame()
    {
        if (SelectedGame?.Profile.SteamAppId is not { Length: > 0 } appId)
        {
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "xdg-open",
                ArgumentList = { $"steam://rungameid/{appId}" },
                UseShellExecute = false,
            });
            StatusMessage = Loc.Current["Games.Launching"];
            _attachTimer.Start();
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            FailureReason = Loc.Current["Games.LaunchFailed"];
        }
    }

    public bool CanLaunch => SelectedGame?.Profile.SteamAppId is { Length: > 0 } && SelectedGame.Running is null;

    /// <summary>Re-raises everything gated on the daemon being reachable.</summary>
    /// <remarks>
    /// The NAT test's button among them. Left out, it kept whatever it had when the page was
    /// first bound — usually before the daemon had answered — and stayed disabled for the session.
    /// </remarks>
    public void NotifyDaemonStateChanged()
    {
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanMeasure));
        OnPropertyChanged(nameof(CanTestNat));
        OnPropertyChanged(nameof(CanLaunch));
        OnPropertyChanged(nameof(StartBlockedReason));
    }

    /// <summary>Re-renders every localised string after a language change.</summary>
    public void NotifyLanguageChanged()
    {
        OnPropertyChanged(string.Empty);
        foreach (var row in _rows.Values)
        {
            row.NotifyLanguageChanged();
        }

        // See Metric: only a new figure makes a cell read its label again.
        DirectLatency = DirectLatency.Rerendered();
        DirectJitter = DirectJitter.Rerendered();
        DirectLoss = DirectLoss.Rerendered();
        RoutedLatency = RoutedLatency.Rerendered();
        RoutedJitter = RoutedJitter.Rerendered();
        RoutedLoss = RoutedLoss.Rerendered();
    }

    public void Activate()
    {
        _attachTimer.Start();
        RefreshRunning();
    }

    public void Deactivate()
    {
        if (!IsRunning)
        {
            _attachTimer.Stop();
        }
    }

    public void Dispose()
    {
        _sessionTimer.Stop();
        _attachTimer.Stop();
        _sampleTimer.Stop();
        _measuring?.Cancel();
        _sampling?.Cancel();
    }
}
