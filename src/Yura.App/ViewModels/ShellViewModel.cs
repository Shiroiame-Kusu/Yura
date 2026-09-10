using Avalonia;
using Avalonia.Styling;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>One entry in the left navigation.</summary>
public sealed record NavigationItem(string Key, string LabelKey, FluentIcons.Common.Symbol Icon)
{
    public string Label => Loc.Current[LabelKey];
}

/// <summary>The application shell: navigation, daemon status, configuration and settings.</summary>
public sealed partial class ShellViewModel : ObservableObject
{
    private readonly IDaemonClient _daemon;
    private readonly ISecretStore _secrets;
    private readonly ConfigStore _config;
    private readonly DispatcherTimer _saveDebounce;

    /// <summary>
    /// Suppresses saving while the loaded configuration is being applied, so restoring a
    /// setting cannot immediately rewrite the file it came from.
    /// </summary>
    private bool _applyingLoadedConfig;

    public ShellViewModel(
        IDaemonClient? daemon = null,
        ISecretStore? secrets = null,
        ConfigStore? config = null)
    {
        _daemon = daemon ?? new DisconnectedDaemonClient();
        _secrets = secrets ?? new SecretToolSecretStore();
        _config = config ?? new ConfigStore();

        Rules = new RuleStore();
        var source = new ProcProcessSource();

        Processes = new ProcessesPageViewModel(source, _daemon, Rules);
        Games = new GamesPageViewModel(Rules, _daemon);
        Proxies = new ProxiesPageViewModel(Rules, _daemon, _secrets);

        SelectedPage = Pages[0];

        // Coalesced: a burst of edits produces one write, and the file is never rewritten
        // in the middle of the user still typing.
        _saveDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(600) };
        _saveDebounce.Tick += async (_, _) =>
        {
            _saveDebounce.Stop();
            await SaveConfigurationAsync().ConfigureAwait(true);
        };

        var existedBefore = File.Exists(_config.FilePath);
        LoadConfiguration();

        // Create the file on first run. A config you cannot find until you have changed
        // something is a config people assume does not exist.
        if (!existedBefore)
        {
            ScheduleSave();
        }

        Rules.Changed += (_, _) => ScheduleSave();
        Rules.Proxies.CollectionChanged += (_, _) => ScheduleSave();
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

    // -- configuration -------------------------------------------------------

    /// <summary>Where the configuration lives, shown in Settings and in diagnostics.</summary>
    public string ConfigPath => _config.FilePath;

    /// <summary>Where proxy passwords are kept. Stated plainly rather than assumed.</summary>
    public string SecretStoreDescription => _secrets.Description;

    /// <summary>
    /// A problem with loading or saving settings. Persistent, not a toast: it stays true
    /// until the user does something about it.
    /// </summary>
    [ObservableProperty]
    public partial string? ConfigWarning { get; set; }

    private void LoadConfiguration()
    {
        var (document, warning) = _config.Load();
        ConfigWarning = warning;

        _applyingLoadedConfig = true;
        try
        {
            IsDarkTheme = !string.Equals(document.Settings.Theme, "light", StringComparison.OrdinalIgnoreCase);
            IsChinese = document.Settings.Language.StartsWith("zh", StringComparison.OrdinalIgnoreCase);
            ReducedMotion = document.Settings.ReducedMotion;

            Rules.Proxies.Clear();
            foreach (var proxy in document.Proxies)
            {
                Rules.Proxies.Add(proxy.ToEndpoint());
            }

            // Rules arrive unapplied. They describe what the user wants, not what the kernel
            // currently does, and only a daemon reply may promote them to active.
            var restored = new List<RoutingRule>();
            foreach (var dto in document.Rules)
            {
                try
                {
                    restored.Add(dto.ToRule());
                }
                catch (InvalidDataException e)
                {
                    ConfigWarning = $"A saved rule could not be restored and was dropped: {e.Message}";
                }
            }

            Rules.LoadPersisted(restored);
        }
        finally
        {
            _applyingLoadedConfig = false;
        }
    }

    private void ScheduleSave()
    {
        if (_applyingLoadedConfig)
        {
            return;
        }

        _saveDebounce.Stop();
        _saveDebounce.Start();
    }

    /// <summary>Writes the configuration now, bypassing the debounce. Used on shutdown.</summary>
    public async Task SaveConfigurationAsync()
    {
        var settings = new PersistedSettings
        {
            Theme = IsDarkTheme ? "dark" : "light",
            Language = IsChinese ? "zh-Hans" : "en",
            ReducedMotion = ReducedMotion,
        };

        var error = await _config.SaveAsync(settings, Rules.Proxies, Rules.Rules).ConfigureAwait(true);
        if (error is not null)
        {
            ConfigWarning = error;
        }
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

    [RelayCommand]
    private Task ReconnectAsync() => RefreshDaemonStateAsync();

    /// <summary>
    /// Asks the daemon whether it is there and, if so, hands it everything it needs.
    /// </summary>
    /// <remarks>
    /// The daemon keeps nothing across a restart, so the app is the source of truth and
    /// re-sends its proxies and persistent rules on every connection. That is what makes a
    /// persistent rule survive a restart of either process.
    /// </remarks>
    public async Task RefreshDaemonStateAsync()
    {
        await _daemon.ConnectAsync().ConfigureAwait(true);

        if (IsDaemonConnected)
        {
            await PushConfigurationToDaemonAsync().ConfigureAwait(true);
        }

        OnPropertyChanged(nameof(IsDaemonConnected));
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        OnPropertyChanged(nameof(DaemonDiagnostics));
        Processes.NotifyDaemonStateChanged();
    }

    private async Task PushConfigurationToDaemonAsync()
    {
        if (_daemon is not UnixSocketDaemonClient socketClient)
        {
            return;
        }

        if (Rules.Proxies.Count > 0)
        {
            // Secrets are read here, in the unprivileged app, and handed over the local
            // socket. The daemon never reads the user's keyring and stores nothing at rest.
            var withSecrets = new List<(ProxyEndpoint, string?)>(Rules.Proxies.Count);
            foreach (var proxy in Rules.Proxies)
            {
                var password = proxy.PasswordRef is null
                    ? null
                    : await _secrets.GetAsync(proxy.PasswordRef).ConfigureAwait(true);
                withSecrets.Add((proxy, password));
            }

            await socketClient.SetProxiesAsync(withSecrets).ConfigureAwait(true);
        }

        foreach (var rule in Rules.Rules.Where(r => r.Lifetime == RuleLifetime.Persistent && r.Enabled))
        {
            var result = await socketClient.ApplyRuleAsync(rule).ConfigureAwait(true);
            if (result.Succeeded)
            {
                Rules.MarkApplied(rule.Id, result.ConfirmedAtUtc);
            }
            else
            {
                ConfigWarning = $"Saved rule “{rule.Name}” could not be reapplied: {result.FailureReason}";
            }
        }
    }

    // -- appearance ----------------------------------------------------------

    [ObservableProperty]
    public partial bool IsDarkTheme { get; set; } = true;

    partial void OnIsDarkThemeChanged(bool value)
    {
        if (Application.Current is { } app)
        {
            app.RequestedThemeVariant = value ? ThemeVariant.Dark : ThemeVariant.Light;
        }

        ScheduleSave();
    }

    [ObservableProperty]
    public partial bool IsChinese { get; set; }

    partial void OnIsChineseChanged(bool value)
    {
        Loc.Current.Language = value ? "zh-Hans" : "en";
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        OnPropertyChanged(nameof(PlaceholderTitle));
        ScheduleSave();
    }

    /// <summary>
    /// Honours the user's reduced-motion preference. When set, transitions are removed
    /// entirely rather than merely shortened.
    /// </summary>
    [ObservableProperty]
    public partial bool ReducedMotion { get; set; }

    partial void OnReducedMotionChanged(bool value)
    {
        if (Application.Current?.Resources is { } resources)
        {
            resources["YuraDurationFast"] = value ? TimeSpan.Zero : TimeSpan.FromMilliseconds(120);
            resources["YuraDurationNormal"] = value ? TimeSpan.Zero : TimeSpan.FromMilliseconds(180);
            resources["YuraDurationSlow"] = value ? TimeSpan.Zero : TimeSpan.FromMilliseconds(280);
        }

        ScheduleSave();
    }
}
