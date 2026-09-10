using Avalonia;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Processes;

namespace Yura.App.ViewModels;

/// <summary>One entry in the left navigation.</summary>
public sealed record NavigationItem(string Key, string LabelKey, FluentIcons.Common.Symbol Icon)
{
    public string Label => Loc.Current[LabelKey];
}

/// <summary>The application shell: navigation, daemon status, and global settings.</summary>
public sealed partial class ShellViewModel : ObservableObject
{
    private readonly IDaemonClient _daemon;

    public ShellViewModel(IDaemonClient? daemon = null)
    {
        _daemon = daemon ?? new DisconnectedDaemonClient();
        Rules = new RuleStore();
        var source = new ProcProcessSource();

        Processes = new ProcessesPageViewModel(source, _daemon, Rules);
        Games = new GamesPageViewModel(Rules, _daemon);
        Proxies = new ProxiesPageViewModel(Rules, _daemon);

        SelectedPage = Pages[0];
    }

    public RuleStore Rules { get; }

    public ProcessesPageViewModel Processes { get; }

    public GamesPageViewModel Games { get; }

    public ProxiesPageViewModel Proxies { get; }

    public IReadOnlyList<NavigationItem> Pages { get; } =
    [
        new("processes", "Nav.Processes", FluentIcons.Common.Symbol.AppsList),
        new("games", "Nav.Games", FluentIcons.Common.Symbol.XboxController),
        new("connections", "Nav.Connections", FluentIcons.Common.Symbol.ArrowSwap),
        new("proxies", "Nav.Proxies", FluentIcons.Common.Symbol.Globe),
        new("rules", "Nav.Rules", FluentIcons.Common.Symbol.TextBulletListSquare),
        new("diagnostics", "Nav.Diagnostics", FluentIcons.Common.Symbol.Pulse),
        new("settings", "Nav.Settings", FluentIcons.Common.Symbol.Settings),
    ];

    [ObservableProperty]
    public partial NavigationItem SelectedPage { get; set; }

    public bool IsProcessesSelected => SelectedPage.Key == "processes";

    public bool IsGamesSelected => SelectedPage.Key == "games";

    public bool IsProxiesSelected => SelectedPage.Key == "proxies";

    /// <summary>True for pages that are navigable but not built yet in this milestone.</summary>
    public bool IsPlaceholderSelected =>
        !IsProcessesSelected && !IsGamesSelected && !IsProxiesSelected;

    public string PlaceholderTitle => SelectedPage.Label;

    partial void OnSelectedPageChanged(NavigationItem value)
    {
        OnPropertyChanged(nameof(IsProcessesSelected));
        OnPropertyChanged(nameof(IsGamesSelected));
        OnPropertyChanged(nameof(IsProxiesSelected));
        OnPropertyChanged(nameof(IsPlaceholderSelected));
        OnPropertyChanged(nameof(PlaceholderTitle));
    }

    // -- daemon status -------------------------------------------------------

    public bool IsDaemonConnected => _daemon.State == DaemonState.Connected;

    public string DaemonStatusText =>
        IsDaemonConnected ? Loc.Current["Shell.DaemonConnected"] : Loc.Current["Shell.DaemonDisconnected"];

    /// <summary>
    /// A persistent problem, shown as an actionable banner rather than a toast, because it
    /// stays true until the user does something about it.
    /// </summary>
    public string? DaemonBannerDetail =>
        IsDaemonConnected ? null : Loc.Current["Shell.DaemonDisconnectedDetail"];

    public string? DaemonDiagnostics => _daemon.UnavailableReason;

    // -- appearance ----------------------------------------------------------

    [ObservableProperty]
    public partial bool IsDarkTheme { get; set; } = true;

    partial void OnIsDarkThemeChanged(bool value)
    {
        if (Application.Current is { } app)
        {
            app.RequestedThemeVariant = value ? ThemeVariant.Dark : ThemeVariant.Light;
        }
    }

    [ObservableProperty]
    public partial bool IsChinese { get; set; }

    partial void OnIsChineseChanged(bool value)
    {
        Loc.Current.Language = value ? "zh-Hans" : "en";
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        OnPropertyChanged(nameof(PlaceholderTitle));
    }

    /// <summary>
    /// Honours the user's reduced-motion preference. When set, transitions are removed
    /// entirely rather than merely shortened.
    /// </summary>
    [ObservableProperty]
    public partial bool ReducedMotion { get; set; }

    partial void OnReducedMotionChanged(bool value)
    {
        if (Application.Current?.Resources is not { } resources)
        {
            return;
        }

        resources["YuraDurationFast"] = value ? TimeSpan.Zero : TimeSpan.FromMilliseconds(120);
        resources["YuraDurationNormal"] = value ? TimeSpan.Zero : TimeSpan.FromMilliseconds(180);
        resources["YuraDurationSlow"] = value ? TimeSpan.Zero : TimeSpan.FromMilliseconds(280);
    }

    [RelayCommand]
    private Task ReconnectAsync() => RefreshDaemonStateAsync();

    /// <summary>
    /// Asks the daemon whether it is there, then republishes everything that depends on
    /// the answer. Also pushes the current proxy list, since a daemon that just started
    /// knows nothing about the endpoints the user configured.
    /// </summary>
    public async Task RefreshDaemonStateAsync()
    {
        await _daemon.ConnectAsync().ConfigureAwait(true);

        if (_daemon is UnixSocketDaemonClient socketClient && IsDaemonConnected && Rules.Proxies.Count > 0)
        {
            await socketClient
                .SetProxiesAsync(Rules.Proxies.Select(p => (p, (string?)null)).ToList())
                .ConfigureAwait(true);
        }

        OnPropertyChanged(nameof(IsDaemonConnected));
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        OnPropertyChanged(nameof(DaemonDiagnostics));
        Processes.NotifyDaemonStateChanged();
    }
}
