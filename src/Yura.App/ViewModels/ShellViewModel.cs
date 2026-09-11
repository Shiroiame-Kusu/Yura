using Avalonia;
using Avalonia.Styling;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Games;
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
public sealed partial class ShellViewModel : ObservableObject, IDisposable
{
    private readonly IDaemonClient _daemon;
    private readonly ISecretStore _secrets;
    private readonly ConfigStore _config;
    private readonly DispatcherTimer _saveDebounce;
    private readonly DispatcherTimer _pushDebounce;

    /// <summary>True while the banner shows a tunnel warning, so it can be cleared when the exit comes up.</summary>
    private bool _tunnelWarningShown;

    /// <summary>
    /// Suppresses saving while the loaded configuration is being applied, so restoring a
    /// setting cannot immediately rewrite the file it came from.
    /// </summary>
    private bool _applyingLoadedConfig;

    public ShellViewModel(
        IDaemonClient? daemon = null,
        ISecretStore? secrets = null,
        ConfigStore? config = null,
        IServiceManager? services = null)
    {
        _daemon = daemon ?? new DisconnectedDaemonClient();
        _secrets = secrets ?? new SecretToolSecretStore();
        _config = config ?? new ConfigStore();

        Rules = new RuleStore();
        var source = new ProcProcessSource();

        Processes = new ProcessesPageViewModel(source, _daemon, Rules);
        Games = new GamesPageViewModel(Rules, _daemon, source);
        Connections = new ConnectionsPageViewModel(_daemon, Rules);
        Proxies = new ProxiesPageViewModel(Rules, _daemon, _secrets);
        RulesPage = new RulesPageViewModel(Rules, _daemon);
        Diagnostics = new DiagnosticsPageViewModel(_daemon, _config, _secrets);
        Settings = new SettingsPageViewModel(this, _daemon, services);

        SelectedPage = Pages[0];

        // The Processes page hands work to two other pages: inspecting connections, and
        // turning a selected process into a game profile.
        Processes.InspectConnectionsRequested += (_, process) =>
        {
            Connections.FilterTo(process.Identity.Pid, process.DisplayName);
            SelectedPage = Pages.First(p => p.Key == "connections");
        };
        Processes.AddAsGameRequested += (_, process) =>
        {
            Games.AddFromProcess(process);
            SelectedPage = Pages.First(p => p.Key == "games");
        };

        // A rule drafted from a connection is finished on the Rules page: it needs an action.
        Connections.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ConnectionsPageViewModel.RuleDraft) &&
                Connections.RuleDraft is { } draft)
            {
                RulesPage.EditDraft(draft);
                SelectedPage = Pages.First(p => p.Key == "rules");
                Connections.RuleDraft = null;
            }
        };

        Games.ProfilesChanged += (_, _) => ScheduleSave();

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
        Rules.Proxies.CollectionChanged += (_, _) => { ScheduleSave(); SchedulePush(); };
        Rules.Chains.CollectionChanged += (_, _) => { ScheduleSave(); SchedulePush(); };

        // The daemon must learn about a new or edited exit as soon as it is saved, or the
        // next rule that names it is refused as referring to a proxy it does not know.
        _pushDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _pushDebounce.Tick += async (_, _) =>
        {
            _pushDebounce.Stop();
            if (IsDaemonConnected)
            {
                await PushProxiesToDaemonAsync().ConfigureAwait(true);
            }
        };
    }

    private void SchedulePush()
    {
        if (_applyingLoadedConfig)
        {
            return;
        }

        _pushDebounce.Stop();
        _pushDebounce.Start();
    }

    public RuleStore Rules { get; }

    public ProcessesPageViewModel Processes { get; }

    public GamesPageViewModel Games { get; }

    public ConnectionsPageViewModel Connections { get; }

    public ProxiesPageViewModel Proxies { get; }

    public RulesPageViewModel RulesPage { get; }

    public DiagnosticsPageViewModel Diagnostics { get; }

    public SettingsPageViewModel Settings { get; }

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

    public bool IsConnectionsSelected => SelectedPage.Key == "connections";

    public bool IsProxiesSelected => SelectedPage.Key == "proxies";

    public bool IsRulesSelected => SelectedPage.Key == "rules";

    public bool IsDiagnosticsSelected => SelectedPage.Key == "diagnostics";

    public bool IsSettingsSelected => SelectedPage.Key == "settings";

    /// <summary>
    /// Starts and stops the pages that poll, so a page nobody is looking at costs nothing.
    /// </summary>
    partial void OnSelectedPageChanged(NavigationItem value)
    {
        OnPropertyChanged(nameof(IsProcessesSelected));
        OnPropertyChanged(nameof(IsGamesSelected));
        OnPropertyChanged(nameof(IsConnectionsSelected));
        OnPropertyChanged(nameof(IsProxiesSelected));
        OnPropertyChanged(nameof(IsRulesSelected));
        OnPropertyChanged(nameof(IsDiagnosticsSelected));
        OnPropertyChanged(nameof(IsSettingsSelected));

        if (IsConnectionsSelected)
        {
            Connections.Activate();
        }
        else
        {
            Connections.Deactivate();
        }

        if (IsDiagnosticsSelected)
        {
            Diagnostics.Activate();
        }
        else
        {
            Diagnostics.Deactivate();
        }

        if (IsGamesSelected)
        {
            Games.Activate();
        }
        else
        {
            Games.Deactivate();
        }

        if (IsProxiesSelected)
        {
            Proxies.Activate();
        }
        else
        {
            Proxies.Deactivate();
        }

        if (IsSettingsSelected)
        {
            Settings.Activate();
        }
        else
        {
            Settings.Deactivate();
        }

        Processes.SetActive(IsProcessesSelected);
    }

    // -- configuration -------------------------------------------------------

    /// <summary>Where the configuration lives, shown in Settings and in diagnostics.</summary>
    public string ConfigPath => _config.FilePath;

    public string ConfigDirectory => _config.Directory;

    /// <summary>Where proxy passwords are kept. Stated plainly rather than assumed.</summary>
    public string SecretStoreDescription => _secrets.Description;

    /// <summary>False when there is no secret service, so passwords last only this session.</summary>
    public bool HasSecretStore => _secrets.IsAvailable;

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
            DnsPolicy = document.Settings.DnsPolicy;
            Processes.FilterScope = document.Settings.ShowAllProcesses
                ? ProcessFilterScope.AllProcesses
                : ProcessFilterScope.MyProcesses;

            Rules.Proxies.Clear();
            foreach (var proxy in document.Proxies)
            {
                Rules.Proxies.Add(proxy.ToEndpoint());
            }

            Rules.Chains.Clear();
            foreach (var chain in document.Chains)
            {
                Rules.Chains.Add(chain.ToChain());
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
            Games.LoadProfiles(document.Games.Select(g => g.ToProfile()));
            Settings.NotifyShellChanged();
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

    /// <summary>Lets a page ask for its change to be persisted, on the same debounce.</summary>
    public void RequestSave() => ScheduleSave();

    /// <summary>Writes the configuration now, bypassing the debounce. Used on shutdown.</summary>
    public async Task SaveConfigurationAsync()
    {
        var snapshot = new ConfigSnapshot
        {
            Settings = new PersistedSettings
            {
                Theme = IsDarkTheme ? "dark" : "light",
                Language = IsChinese ? "zh-Hans" : "en",
                ReducedMotion = ReducedMotion,
                DnsPolicy = DnsPolicy,
                ShowAllProcesses = Processes.FilterScope == ProcessFilterScope.AllProcesses,
            },
            Proxies = Rules.Proxies,
            Chains = Rules.Chains,
            Games = Games.Profiles,
            Rules = Rules.Rules,
        };

        var error = await _config.SaveAsync(snapshot).ConfigureAwait(true);
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
    /// re-sends its proxies, chains, options and persistent rules on every connection. That is
    /// what makes a persistent rule survive a restart of either process.
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
        Games.NotifyDaemonStateChanged();
    }

    private async Task PushConfigurationToDaemonAsync()
    {
        await PushProxiesToDaemonAsync().ConfigureAwait(true);
        await _daemon.SetDnsPolicyAsync(DnsPolicy).ConfigureAwait(true);

        // Every enabled rule, not only the saved ones. A daemon that has just started holds
        // nothing, and a rule bound to a process that is still running is still wanted — the
        // alternative is a list that says "Proxied" about a rule no longer in any kernel.
        foreach (var rule in Rules.Rules.Where(r => r.Enabled))
        {
            var result = await _daemon.ApplyRuleAsync(rule).ConfigureAwait(true);
            if (result.Succeeded)
            {
                Rules.MarkApplied(rule.Id, result.ConfirmedAtUtc);
                continue;
            }

            if (rule.Lifetime == RuleLifetime.Persistent)
            {
                ConfigWarning = $"Saved rule “{rule.Name}” could not be reapplied: {result.FailureReason}";
            }
            else
            {
                // A temporary rule the daemon will not take is a rule whose process is gone.
                // Dropping it is the honest outcome; keeping it would show a policy that
                // nothing is enforcing.
                Rules.Remove(rule.Id);
            }
        }

        await PruneStrayDaemonRulesAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// Takes out rules the daemon holds that this app does not.
    /// </summary>
    /// <remarks>
    /// The app is the source of truth for what should be installed, and anything else the
    /// daemon is holding decides routes from a position no page shows. That happens when a
    /// previous app run exited between installing a rule and replacing it, and it happened
    /// systematically until superseded rules were removed at the point they are replaced.
    /// </remarks>
    private async Task PruneStrayDaemonRulesAsync()
    {
        var installed = await _daemon.GetInstalledRulesAsync().ConfigureAwait(true);
        var known = Rules.Rules.Select(r => r.Id).ToHashSet();
        var strays = installed.Where(r => !known.Contains(r.Id)).ToList();

        foreach (var stray in strays)
        {
            await _daemon.RemoveRuleAsync(stray.Id).ConfigureAwait(true);
        }

        if (strays.Count > 0)
        {
            ConfigWarning = strays.Count == 1
                ? $"Removed a rule the daemon still held from an earlier session: “{strays[0].Name}”."
                : $"Removed {strays.Count} rules the daemon still held from an earlier session.";
        }
    }

    /// <summary>Hands the daemon the current exits and chains, secrets included.</summary>
    /// <remarks>
    /// Secrets are read here, in the unprivileged app, and handed over the local socket.
    /// The daemon never reads the user's keyring and stores nothing at rest. A tunnel that
    /// could not come up is not a failed push: the proxies are in place, the reason is shown
    /// where the exit is listed, and once in the banner until the exit comes up.
    /// </remarks>
    private async Task PushProxiesToDaemonAsync()
    {
        var withSecrets = new List<(ProxyEndpoint, ProxySecrets)>(Rules.Proxies.Count);
        foreach (var proxy in Rules.Proxies)
        {
            var password = proxy.PasswordRef is null
                ? null
                : await _secrets.GetAsync(proxy.PasswordRef).ConfigureAwait(true);
            var preshared = proxy.WireGuard?.PresharedKeyRef is { } pskRef
                ? await _secrets.GetAsync(pskRef).ConfigureAwait(true)
                : null;
            withSecrets.Add((proxy, new ProxySecrets(password, preshared)));
        }

        var result = await _daemon.SetProxiesAsync(withSecrets, Rules.Chains).ConfigureAwait(true);
        if (result.Warnings.Count > 0)
        {
            ConfigWarning = string.Join(" ", result.Warnings);
            _tunnelWarningShown = true;
        }
        else if (_tunnelWarningShown)
        {
            ConfigWarning = null;
            _tunnelWarningShown = false;
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

        Settings.NotifyShellChanged();
        ScheduleSave();
    }

    [ObservableProperty]
    public partial bool IsChinese { get; set; }

    partial void OnIsChineseChanged(bool value)
    {
        Loc.Current.Language = value ? "zh-Hans" : "en";
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        Settings.NotifyShellChanged();
        Proxies.NotifyLanguageChanged();
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

        Settings.NotifyShellChanged();
        ScheduleSave();
    }

    /// <summary>
    /// Whether DNS from proxied processes goes through the proxy. Global rather than per rule,
    /// because it changes the shape of the installed ruleset.
    /// </summary>
    [ObservableProperty]
    public partial DnsPolicy DnsPolicy { get; set; } = DnsPolicy.ThroughProxy;

    public void Dispose()
    {
        _saveDebounce.Stop();
        _pushDebounce.Stop();
        Processes.Dispose();
        Games.Dispose();
        Connections.Dispose();
        Proxies.Dispose();
        Diagnostics.Dispose();
    }
}
