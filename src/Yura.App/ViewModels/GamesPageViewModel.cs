using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Games;
using Yura.Core.Ipc;
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
}

/// <summary>
/// One measured network figure.
/// </summary>
/// <remarks>
/// The whole point of this type is that <see cref="Value"/> is nullable. A missing
/// measurement renders as "Not measured"; substituting zero would read as a perfect score.
/// </remarks>
public sealed record Metric(double? Value, string Unit)
{
    public static readonly Metric NotMeasured = new(null, string.Empty);

    public bool HasValue => Value is not null;

    public string Display => Value is { } v
        ? string.Create(CultureInfo.CurrentCulture, $"{v:0.#} {Unit}").Trim()
        : Loc.Current["Common.NotMeasured"];
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
    private CancellationTokenSource? _measuring;

    public GamesPageViewModel(RuleStore rules, IDaemonClient daemon, ProcProcessSource processes)
    {
        _rules = rules;
        _daemon = daemon;
        _processes = processes;

        _sessionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _sessionTimer.Tick += (_, _) => OnPropertyChanged(nameof(SessionDurationDisplay));

        // While a session is starting, this is what turns "waiting for game" into "routing".
        _attachTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _attachTimer.Tick += (_, _) => RefreshRunning();
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

    public bool CanMeasure => SelectedGame is { } game && game.Profile.IsMeasurable &&
                              _daemon.State == DaemonState.Connected && State != BoostState.Testing;

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

            if (!SelectedGame.Profile.IsRoutable && SelectedGame.Running is null)
            {
                return Loc.Current["Games.StartItFirst"];
            }

            return null;
        }
    }

    // -- discovery -------------------------------------------------------------

    /// <summary>
    /// Merges saved profiles with what is installed and what is running.
    /// </summary>
    /// <remarks>
    /// Saved profiles win over discovery, because they carry the route and the path the user
    /// chose. Discovery only adds games the configuration has never seen.
    /// </remarks>
    public void LoadProfiles(IEnumerable<GameProfile> saved)
    {
        foreach (var profile in saved)
        {
            _rows[profile.Id] = new GameRowViewModel(profile);
        }

        foreach (var discovered in SteamLibrary.Discover())
        {
            _rows.TryAdd(discovered.Id, new GameRowViewModel(discovered));
        }

        Rebuild();
        RefreshRunning();
    }

    [RelayCommand]
    private void Rescan()
    {
        var added = 0;
        foreach (var discovered in SteamLibrary.Discover())
        {
            if (_rows.TryAdd(discovered.Id, new GameRowViewModel(discovered)))
            {
                added++;
            }
        }

        Rebuild();
        RefreshRunning();
        StatusMessage = added == 0
            ? Loc.Current["Games.RescanNoneNew"]
            : string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.RescanFound"], added);
    }

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
            SteamAppId = process.Wine?.SteamAppId,
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
            SteamAppId = process.Wine?.SteamAppId ?? row.Profile.SteamAppId,
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
    /// Finds the running process for each profile, by Wine target, executable path, or Steam id.
    /// </summary>
    private void RefreshRunning()
    {
        var snapshot = _processes.Enumerate();
        var changed = false;

        foreach (var row in _rows.Values)
        {
            var profile = row.Profile;
            var match = snapshot.FirstOrDefault(p =>
                (profile.WineTargetExecutable is { Length: > 0 } wine &&
                 string.Equals(p.Wine?.TargetExecutable, wine, StringComparison.OrdinalIgnoreCase)) ||
                (profile.ExecutablePath is { Length: > 0 } path &&
                 string.Equals(p.ExecutablePath, path, StringComparison.Ordinal)) ||
                (profile.SteamAppId is { Length: > 0 } appId &&
                 string.Equals(p.Wine?.SteamAppId, appId, StringComparison.Ordinal)));

            if (!ReferenceEquals(row.Running, match))
            {
                row.Update(profile, match);
                changed = true;
            }
        }

        if (changed)
        {
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(StartBlockedReason));
        }

        // A session that was waiting for its game now has one, and vice versa.
        if (State == BoostState.WaitingForGame && SelectedGame?.Running is not null)
        {
            State = BoostState.Routing;
        }
        else if (State == BoostState.Routing && SelectedGame?.Running is null)
        {
            State = BoostState.WaitingForGame;
        }
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
        OnPropertyChanged(nameof(StartBlockedReason));
        // Measurements belong to a game/route pair; carrying them across would show one
        // game's numbers under another's name.
        ClearMeasurements();

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
    }

    private void ClearMeasurements()
    {
        DirectLatency = DirectJitter = DirectLoss = Metric.NotMeasured;
        RoutedLatency = RoutedJitter = RoutedLoss = Metric.NotMeasured;
        LastMeasurementUtc = null;
        MeasurementTarget = null;
        MeasurementMethod = null;
        OnPropertyChanged(nameof(LastMeasurementDisplay));
        OnPropertyChanged(nameof(MeasurementTargetDisplay));
        OnPropertyChanged(nameof(MeasurementMethodDisplay));
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
        _measuring = new CancellationTokenSource();
        var token = _measuring.Token;

        var previous = State;
        State = BoostState.Testing;
        FailureReason = null;
        OnPropertyChanged(nameof(CanMeasure));

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
                State = previous == BoostState.Testing ? BoostState.Ready : previous;
                return;
            }

            Apply(measurement);
            State = previous == BoostState.Testing ? BoostState.Ready : previous;
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer measurement; that one reports.
        }
        finally
        {
            OnPropertyChanged(nameof(CanMeasure));
        }
    }

    private void Apply(MeasurementDto measurement)
    {
        MeasurementTarget = measurement.Target;
        MeasurementMethod = measurement.Method;
        LastMeasurementUtc = measurement.MeasuredAtUtc;

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
        _sessionStartedAt = DateTimeOffset.UtcNow;
        _sessionTimer.Start();
        _attachTimer.Start();

        if (_daemon.State != DaemonState.Connected)
        {
            Fail(_daemon.UnavailableReason);
            return;
        }

        // The rule is the session. A game profile is an ordinary rule in the shared list, so
        // its precedence against a manual selection is visible on the Rules page.
        var selector = BuildSelector(row);
        if (selector is null)
        {
            Fail(Loc.Current["Games.StartItFirst"]);
            return;
        }

        var action = SelectedRoute.ToAction();

        var rule = new RoutingRule
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
            Action = action,
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };

        var result = await _daemon.ApplyRuleAsync(rule).ConfigureAwait(true);
        if (!result.Succeeded)
        {
            Fail(result.FailureReason);
            return;
        }

        _sessionRule = rule;
        _rules.Add(rule with { AppliedAtUtc = result.ConfirmedAtUtc });
        State = row.Running is null ? BoostState.WaitingForGame : BoostState.Routing;
        StatusMessage = result.PreExistingConnections is > 0
            ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Games.StartedWithExisting"], result.PreExistingConnections)
            : Loc.Current["Games.Started"];

        // Numbers the moment the session starts, if we know where to measure.
        if (row.Profile.IsMeasurable || TryParseTarget(MeasurementTargetInput, out _, out _))
        {
            await MeasureAsync().ConfigureAwait(true);
        }
    }

    /// <summary>
    /// Works out what the session's rule should match.
    /// </summary>
    /// <remarks>
    /// Prefers the Wine target, because that is the only thing that distinguishes two games
    /// sharing a runtime. Falls back to the executable path, and to the running instance when
    /// the profile has no path at all — which is the case for a Steam game that has never been
    /// attached.
    /// </remarks>
    private ProcessSelector? BuildSelector(GameRowViewModel row)
    {
        var profile = row.Profile;

        if (profile.WineTargetExecutable is { Length: > 0 } wine)
        {
            return new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = profile.ExecutablePath ?? row.Running?.ExecutablePath,
                WineTargetExecutable = wine,
                // Games spawn helpers — launchers, anti-cheat, crash handlers — that need the
                // same route, and they are all children.
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            };
        }

        if (profile.ExecutablePath is { Length: > 0 } path)
        {
            return new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = path,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            };
        }

        if (row.Running is { } running)
        {
            return new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = running.Identity,
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            };
        }

        return null;
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

        _sessionTimer.Stop();
        _attachTimer.Stop();
        _sessionStartedAt = null;
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

    public void NotifyDaemonStateChanged()
    {
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(CanMeasure));
        OnPropertyChanged(nameof(StartBlockedReason));
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
        _measuring?.Cancel();
    }
}
