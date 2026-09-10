using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Proxies;

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

/// <summary>A game Yura knows about.</summary>
public sealed record GameEntry(string Id, string Name, string? ExecutablePath, string? SteamAppId)
{
    public string SubtitleText => ExecutablePath ?? Loc.Current["Common.Unknown"];
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

/// <summary>The Games page: select game, select route, start boost.</summary>
public sealed partial class GamesPageViewModel : ObservableObject
{
    private readonly RuleStore _rules;
    private readonly IDaemonClient _daemon;
    private readonly DispatcherTimer _sessionTimer;
    private DateTimeOffset? _sessionStartedAt;

    public GamesPageViewModel(RuleStore rules, IDaemonClient daemon)
    {
        _rules = rules;
        _daemon = daemon;

        _sessionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _sessionTimer.Tick += (_, _) => OnPropertyChanged(nameof(SessionDurationDisplay));
    }

    public ObservableCollection<GameEntry> Games { get; } = [];

    public ObservableCollection<ProxyEndpoint> Routes => _rules.Proxies;

    [ObservableProperty]
    public partial GameEntry? SelectedGame { get; set; }

    [ObservableProperty]
    public partial ProxyEndpoint? SelectedRoute { get; set; }

    [ObservableProperty]
    public partial BoostState State { get; set; } = BoostState.Ready;

    [ObservableProperty]
    public partial string? FailureReason { get; set; }

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

    public bool CanStart => SelectedGame is not null && SelectedRoute is not null && !IsRunning;

    /// <summary>Shown next to a disabled Start button, so the reason needs no hovering.</summary>
    public string? StartBlockedReason
    {
        get
        {
            if (SelectedGame is null)
            {
                return Loc.Current["Games.NoGames"];
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

    [ObservableProperty]
    public partial DateTimeOffset? LastMeasurementUtc { get; set; }

    public string LastMeasurementDisplay => LastMeasurementUtc is { } t
        ? t.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture)
        : Loc.Current["Common.NotMeasured"];

    public string MeasurementTargetDisplay => MeasurementTarget ?? Loc.Current["Common.NotMeasured"];

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

    partial void OnSelectedRouteChanged(ProxyEndpoint? value)
    {
        OnPropertyChanged(nameof(UdpSupport));
        OnPropertyChanged(nameof(UdpSupportLabel));
        OnPropertyChanged(nameof(ShowUdpWarning));
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(StartBlockedReason));
    }

    partial void OnSelectedGameChanged(GameEntry? value)
    {
        OnPropertyChanged(nameof(CanStart));
        OnPropertyChanged(nameof(StartBlockedReason));
        // Measurements belong to a game/route pair; carrying them across would show one
        // game's numbers under another's name.
        ClearMeasurements();
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
        OnPropertyChanged(nameof(LastMeasurementDisplay));
        OnPropertyChanged(nameof(MeasurementTargetDisplay));
    }

    /// <summary>Design-review hook: puts the page into a running session with a start time.</summary>
    internal void EnterSimulatedSession(BoostState state, TimeSpan elapsed)
    {
        _sessionStartedAt = DateTimeOffset.UtcNow - elapsed;
        State = state;
        _sessionTimer.Start();
    }

    [RelayCommand]
    private async Task StartBoostAsync()
    {
        if (!CanStart)
        {
            return;
        }

        FailureReason = null;
        State = BoostState.Starting;
        _sessionStartedAt = DateTimeOffset.UtcNow;
        _sessionTimer.Start();

        // Without a daemon there is nothing to start, and saying so is more useful than
        // spinning forever in "Starting".
        if (_daemon.State != DaemonState.Connected)
        {
            await Task.Yield();
            State = BoostState.Failed;
            FailureReason = _daemon.UnavailableReason;
            _sessionTimer.Stop();
            _sessionStartedAt = null;
        }
    }

    [RelayCommand]
    private void StopBoost()
    {
        State = BoostState.Stopping;
        _sessionTimer.Stop();
        _sessionStartedAt = null;
        State = BoostState.Ready;
        ClearMeasurements();
    }
}
