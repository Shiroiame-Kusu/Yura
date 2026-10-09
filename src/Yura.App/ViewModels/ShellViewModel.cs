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
/// <remarks>
/// Observable because its label is. As a record read once, the navigation kept the language it
/// started in until the app was restarted.
/// </remarks>
public sealed class NavigationItem : ObservableObject
{
    public NavigationItem(string key, string labelKey, FluentIcons.Common.Symbol icon)
    {
        Key = key;
        LabelKey = labelKey;
        Icon = icon;

        // The items live as long as the shell, which lives as long as the application and
        // Loc.Current, so the subscription never needs undoing.
        Loc.Current.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(Loc.Language))
            {
                OnPropertyChanged(nameof(Label));
            }
        };
    }

    public string Key { get; }

    public string LabelKey { get; }

    public FluentIcons.Common.Symbol Icon { get; }

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
    private readonly DispatcherTimer _heartbeat;

    /// <summary>The push to the daemon under way, if one is. See <see cref="SyncAsync"/>.</summary>
    private Task? _sync;

    /// <summary>Set when the push under way went out of date before it finished.</summary>
    private bool _syncAgain;

    /// <summary>The daemon state the shell last acted on, to tell a connection from a repeat.</summary>
    private DaemonState _daemonState;

    private bool _heartbeatInFlight;

    /// <summary>The thread the shell was built on, which is the UI thread. See <see cref="OnUiThread"/>.</summary>
    private readonly int _uiThread = Environment.CurrentManagedThreadId;

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

        // A secret the secret service would not take lasts only as long as the app. The editor
        // closes on save, so the warning goes where configuration problems are shown.
        Proxies.Editor.SecretNotStored += (_, message) => ConfigWarning = message;

        // The daemon comes and goes on its own — started after the app, restarted by an
        // upgrade, or by systemd after a crash — and holds nothing across a restart. Each time
        // it appears it has to be handed everything again, and only the app can do that.
        _daemonState = _daemon.State;
        _daemon.StateChanged += OnDaemonStateChangedOnAnyThread;
        _daemon.InstanceChanged += OnDaemonRestartedOnAnyThread;

        // Pages ask the daemon things only while they are showing, and some never do. Without
        // a request of its own the shell could sit on such a page while the daemon restarted
        // behind it, and go on calling rules active that no kernel held.
        _heartbeat = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _heartbeat.Tick += async (_, _) => await HeartbeatAsync().ConfigureAwait(true);
        _heartbeat.Start();
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
            UseSystemTitleBar = document.Settings.UseSystemTitleBar;
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

    /// <summary>Writes the configuration now, bypassing the debounce.</summary>
    public async Task SaveConfigurationAsync()
    {
        var error = await _config.SaveAsync(Snapshot()).ConfigureAwait(true);
        if (error is not null)
        {
            ConfigWarning = error;
        }
    }

    /// <summary>Writes the configuration as the app exits, and returns once it is written.</summary>
    /// <remarks>
    /// For the shutdown handler, which runs on the UI thread and cannot await. Waiting there on
    /// <see cref="SaveConfigurationAsync"/> hung every exit: it resumes on the UI thread, which
    /// the handler is holding, so closing the window left it on screen and the process running.
    /// The store never comes back to the calling thread, so waiting on it is safe, and a failure
    /// has nowhere left to be shown.
    /// </remarks>
    public void SaveConfigurationBeforeExit() => _config.SaveAsync(Snapshot()).GetAwaiter().GetResult();

    private ConfigSnapshot Snapshot() => new()
    {
        Settings = new PersistedSettings
        {
            Theme = IsDarkTheme ? "dark" : "light",
            Language = IsChinese ? "zh-Hans" : "en",
            ReducedMotion = ReducedMotion,
            UseSystemTitleBar = UseSystemTitleBar,
            DnsPolicy = DnsPolicy,
            ShowAllProcesses = Processes.FilterScope == ProcessFilterScope.AllProcesses,
        },
        Proxies = Rules.Proxies,
        Chains = Rules.Chains,
        Games = Games.Profiles,
        Rules = Rules.Rules,
    };

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
        RaiseDaemonState();

        if (IsDaemonConnected)
        {
            await SyncAsync().ConfigureAwait(true);
        }
    }

    /// <summary>Re-reads everything the shell and the pages show about the daemon.</summary>
    private void RaiseDaemonState()
    {
        OnPropertyChanged(nameof(IsDaemonConnected));
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        OnPropertyChanged(nameof(DaemonDiagnostics));
        Processes.NotifyDaemonStateChanged();
        Games.NotifyDaemonStateChanged();
    }

    private void OnDaemonStateChangedOnAnyThread(object? sender, DaemonState state) =>
        OnUiThread(() => OnDaemonStateChanged(state));

    private void OnDaemonRestartedOnAnyThread(object? sender, EventArgs e) => OnUiThread(OnDaemonRestarted);

    /// <summary>What the daemon appearing or going away means for the rest of the app.</summary>
    /// <remarks>
    /// Nothing listened to this before. A daemon that restarted, or came up after the app, was
    /// handed no proxies and no rules until someone pressed Reconnect, while every page went on
    /// showing the rules as active and the banner went on saying whatever it said last.
    /// </remarks>
    private void OnDaemonStateChanged(DaemonState state)
    {
        var previous = _daemonState;
        _daemonState = state;
        RaiseDaemonState();

        if (state == DaemonState.Connected && previous != DaemonState.Connected)
        {
            // Restarted or only out of reach for a moment, pushing everything is right either
            // way: a rule the daemon still holds is replaced by itself.
            _ = SyncAsync();
        }
        else if (state == DaemonState.Disconnected && previous != DaemonState.Disconnected)
        {
            // Nothing is confirmed while no daemon answers; rules read as pending until one
            // confirms them again.
            Rules.MarkAllPending();
        }
    }

    /// <summary>An answer came from a new run of the daemon, which holds nothing it was given.</summary>
    private void OnDaemonRestarted()
    {
        Rules.MarkAllPending();

        // Again even when a push is under way: it may have started before the restart, and
        // what it pushed so far went to the process that has gone.
        _ = SyncAsync(again: true);
    }

    /// <summary>
    /// Hands the daemon everything it should hold, one push at a time.
    /// </summary>
    /// <remarks>
    /// A request while a push is under way waits for that push rather than starting a second
    /// one beside it. <paramref name="again"/> asks for one more push after it, for when the
    /// one under way has gone out of date.
    /// </remarks>
    private Task SyncAsync(bool again = false)
    {
        if (_sync is { IsCompleted: false } running)
        {
            _syncAgain |= again;
            return running;
        }

        _sync = RunSyncAsync();
        return _sync;
    }

    private async Task RunSyncAsync()
    {
        do
        {
            _syncAgain = false;
            if (!IsDaemonConnected)
            {
                // The next connection pushes it all.
                return;
            }

            await PushConfigurationToDaemonAsync().ConfigureAwait(true);
        }
        while (_syncAgain);
    }

    /// <summary>One cheap request every few seconds, for what its answer says about the daemon.</summary>
    private async Task HeartbeatAsync()
    {
        if (_heartbeatInFlight)
        {
            return;
        }

        _heartbeatInFlight = true;
        try
        {
            await _daemon.PingAsync().ConfigureAwait(true);
        }
        finally
        {
            _heartbeatInFlight = false;
        }
    }

    /// <summary>Runs on the UI thread. The daemon client raises its events on whichever thread got the answer.</summary>
    /// <remarks>
    /// Compared with the thread that built the shell rather than asked of the dispatcher: the
    /// two agree in the app, and only the first is still true where no Avalonia loop runs, as in
    /// a test, where the dispatcher belongs to whichever thread touched it first.
    /// </remarks>
    private void OnUiThread(Action action)
    {
        if (Environment.CurrentManagedThreadId == _uiThread)
        {
            action();
        }
        else
        {
            Dispatcher.UIThread.Post(action);
        }
    }

    private async Task PushConfigurationToDaemonAsync()
    {
        // Listed before anything is pushed and pruned after. A rule a page installs while this
        // runs is in the daemon a moment before it is in the app's list, and pruned from a
        // listing taken in that moment it would leave the kernel while the page showed it active.
        var installed = await _daemon.GetInstalledRulesAsync().ConfigureAwait(true);

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

            if (!result.Answered)
            {
                // The daemon went away part-way through. A rule it never saw is not a rule it
                // refused, and the next connection pushes everything again.
                return;
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

        await PruneStrayDaemonRulesAsync(installed).ConfigureAwait(true);
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
    private async Task PruneStrayDaemonRulesAsync(IReadOnlyList<(Guid Id, string Name)> installed)
    {
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

        // Strings bound with {loc:Tr} follow on their own. Everything a view model puts
        // together has to be read again, on every page — only the Proxies page used to be told,
        // and the rest kept the previous language until something else changed them.
        OnPropertyChanged(nameof(DaemonStatusText));
        OnPropertyChanged(nameof(DaemonBannerDetail));
        Settings.NotifyShellChanged();
        Settings.NotifyLanguageChanged();
        Processes.NotifyLanguageChanged();
        Games.NotifyLanguageChanged();
        Connections.NotifyLanguageChanged();
        Proxies.NotifyLanguageChanged();
        RulesPage.NotifyLanguageChanged();
        Diagnostics.NotifyLanguageChanged();
        ScheduleSave();
    }

    /// <summary>
    /// Applies what the command line asked for over what the configuration says, without
    /// saving it.
    /// </summary>
    /// <remarks>
    /// Null leaves the saved choice alone. These used to be set by an object initializer, which
    /// runs after the constructor has loaded the configuration: the command line's defaults —
    /// dark, English — replaced the user's saved theme and language on every launch, and were
    /// then saved over them.
    /// </remarks>
    public void ApplyStartupOverrides(bool? dark, bool? chinese)
    {
        _applyingLoadedConfig = true;
        try
        {
            if (dark is { } isDark)
            {
                IsDarkTheme = isDark;
            }

            if (chinese is { } isChinese)
            {
                IsChinese = isChinese;
            }
        }
        finally
        {
            _applyingLoadedConfig = false;
        }
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
    /// Lets the desktop draw the title bar and frame, for anyone who prefers them, or whose window
    /// manager draws its own whatever the window asks for, such as a tiling one.
    /// </summary>
    [ObservableProperty]
    public partial bool UseSystemTitleBar { get; set; }

    partial void OnUseSystemTitleBarChanged(bool value)
    {
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
        _daemon.StateChanged -= OnDaemonStateChangedOnAnyThread;
        _daemon.InstanceChanged -= OnDaemonRestartedOnAnyThread;
        _heartbeat.Stop();
        _saveDebounce.Stop();
        _pushDebounce.Stop();
        Processes.Dispose();
        Games.Dispose();
        Connections.Dispose();
        Proxies.Dispose();
        Diagnostics.Dispose();
    }
}
