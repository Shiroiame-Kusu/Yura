using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Ipc;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>A language the interface can be shown in.</summary>
public sealed record LanguageOption(string Tag, string Display);

/// <summary>
/// The Settings page: the daemon service, the one global routing policy, appearance and
/// language, and where things are kept.
/// </summary>
/// <remarks>
/// Appearance settings live on the view model that owns them (the shell) and are surfaced
/// here rather than duplicated, so there is one source of truth for the theme. DNS policy is
/// pushed to the daemon when it changes, because it changes the installed ruleset.
///
/// The service section is the only place the app asks for privilege, and it does so through
/// polkit with the exact script shown first. It never edits sudoers and never stores a
/// password of its own.
/// </remarks>
public sealed partial class SettingsPageViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;
    private readonly IDaemonClient _daemon;
    private readonly IServiceManager _services;
    private bool _serviceQueryInFlight;

    public SettingsPageViewModel(ShellViewModel shell, IDaemonClient daemon, IServiceManager? services = null)
    {
        _shell = shell;
        _daemon = daemon;
        _services = services ?? new ServiceManager();
        Daemon = DaemonLocator.Find();
    }

    // -- appearance ----------------------------------------------------------

    public bool IsDarkTheme
    {
        get => _shell.IsDarkTheme;
        set => _shell.IsDarkTheme = value;
    }

    public IReadOnlyList<LanguageOption> Languages { get; } =
    [
        new("en", "English"),
        new("zh-Hans", "简体中文"),
    ];

    public LanguageOption SelectedLanguage
    {
        get => _shell.IsChinese ? Languages[1] : Languages[0];
        set
        {
            if (value is not null)
            {
                _shell.IsChinese = value.Tag.StartsWith("zh", StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    public bool ReducedMotion
    {
        get => _shell.ReducedMotion;
        set => _shell.ReducedMotion = value;
    }

    public bool UseSystemTitleBar
    {
        get => _shell.UseSystemTitleBar;
        set => _shell.UseSystemTitleBar = value;
    }

    public bool ShowAllProcesses
    {
        get => _shell.Processes.FilterScope == ProcessFilterScope.AllProcesses;
        set
        {
            _shell.Processes.FilterScope = value ? ProcessFilterScope.AllProcesses : ProcessFilterScope.MyProcesses;
            OnPropertyChanged();
            _shell.RequestSave();
        }
    }

    // -- routing -------------------------------------------------------------

    public IReadOnlyList<DnsPolicy> DnsPolicies { get; } = [DnsPolicy.ThroughProxy, DnsPolicy.Direct];

    public DnsPolicy DnsPolicy
    {
        get => _shell.DnsPolicy;
        set
        {
            if (_shell.DnsPolicy == value)
            {
                return;
            }

            _shell.DnsPolicy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(DnsPolicyHint));
            _ = PushDnsPolicyAsync(value);
        }
    }

    /// <summary>What the choice actually does, stated next to it rather than in a manual.</summary>
    public string DnsPolicyHint => DnsPolicy == DnsPolicy.ThroughProxy
        ? Loc.Current["Settings.Dns.ThroughProxyHint"]
        : Loc.Current["Settings.Dns.DirectHint"];

    [ObservableProperty]
    public partial string? StatusMessage { get; set; }

    [ObservableProperty]
    public partial string? ErrorMessage { get; set; }

    private async Task PushDnsPolicyAsync(DnsPolicy policy)
    {
        _shell.RequestSave();

        if (_daemon.State != DaemonState.Connected)
        {
            // Saved either way; it takes effect when the daemon next connects.
            StatusMessage = Loc.Current["Settings.SavedNotApplied"];
            return;
        }

        var result = await _daemon.SetDnsPolicyAsync(policy).ConfigureAwait(true);
        if (result.Succeeded)
        {
            StatusMessage = Loc.Current["Settings.Applied"];
            ErrorMessage = null;
        }
        else
        {
            ErrorMessage = result.FailureReason;
        }
    }

    // -- storage -------------------------------------------------------------

    public string ConfigPath => _shell.ConfigPath;

    /// <summary>
    /// Where passwords and keys go. When there is no secret service the sentence says what
    /// that means for the user, rather than naming the fallback as if it were a place.
    /// </summary>
    public string SecretStoreDescription => _shell.HasSecretStore
        ? _shell.SecretStoreDescription
        : Loc.Current["Diagnostics.SecretsInMemory"];

    public string AppVersion => typeof(SettingsPageViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    [RelayCommand]
    private void OpenConfigDirectory()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "xdg-open",
                ArgumentList = { _shell.ConfigDirectory },
                UseShellExecute = false,
            });
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            ErrorMessage = Loc.Current["Settings.OpenFailed"];
        }
    }

    // -- the daemon service --------------------------------------------------

    public bool HasSystemd => _services.HasSystemd;

    public bool HasPolkit => _services.HasPolkit;

    [ObservableProperty]
    public partial ServiceStatus? Service { get; set; }

    [ObservableProperty]
    public partial DaemonLocation? Daemon { get; set; }

    /// <summary>An explicit daemon path, when detection is not what the user wants.</summary>
    [ObservableProperty]
    public partial string DaemonPathOverride { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool IsServiceBusy { get; set; }

    [ObservableProperty]
    public partial string? ServiceMessage { get; set; }

    [ObservableProperty]
    public partial string? ServiceError { get; set; }

    [ObservableProperty]
    public partial string JournalTail { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool ShowUnit { get; set; }

    [ObservableProperty]
    public partial bool ShowScript { get; set; }

    public bool IsServiceInstalled => Service is { State: not (ServiceState.NotInstalled or ServiceState.Unsupported) };

    public bool IsServiceRunning => Service?.State == ServiceState.Running;

    public bool IsServiceFailed => Service?.State == ServiceState.Failed;

    public bool IsServiceStopped => Service is { State: ServiceState.Stopped };

    public bool IsServiceEnabled => Service?.Enabled == true;

    public bool HasJournal => JournalTail.Length > 0;

    /// <summary>
    /// Start is offered only for a service that exists and is not running. Before it is
    /// installed there is nothing to start, and a disabled button beside "Install and start"
    /// is noise rather than information.
    /// </summary>
    public bool CanShowStart => IsServiceInstalled && !IsServiceRunning;

    public string ServiceStateText => Service?.State switch
    {
        ServiceState.Running => Loc.Current["Settings.Service.Running"],
        ServiceState.Stopped => Loc.Current["Settings.Service.Stopped"],
        ServiceState.Failed => Loc.Current["Settings.Service.Failed"],
        ServiceState.Unsupported => Loc.Current["Settings.Service.Unsupported"],
        ServiceState.NotInstalled => Loc.Current["Settings.Service.NotInstalled"],
        _ => Loc.Current["Common.Loading"],
    };

    public string ServiceEnabledText => Service is null || !IsServiceInstalled
        ? string.Empty
        : Loc.Current[Service.Enabled ? "Settings.Service.Enabled" : "Settings.Service.Disabled"];

    public string? ServiceDetailText => Service?.State == ServiceState.Failed ? Service.Detail : null;

    public string ServiceExecStartText => Service?.ExecStart ?? string.Empty;

    public bool HasDaemon => Daemon is not null;

    public string DaemonText => Daemon is { } daemon
        ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Settings.Service.DaemonFound"],
            Loc.Current[daemon.Source switch
            {
                DaemonSource.Explicit => "Settings.Service.Source.Explicit",
                DaemonSource.Environment => "Settings.Service.Source.Environment",
                DaemonSource.Sibling => "Settings.Service.Source.Sibling",
                DaemonSource.Installed => "Settings.Service.Source.Installed",
                _ => "Settings.Service.Source.Development",
            }], daemon.Directory)
        : Loc.Current["Settings.Service.DaemonNotFound"];

    public string SocketPath => IpcProtocol.DefaultSocketPath;

    public string InstallHint => string.Format(CultureInfo.CurrentCulture, Loc.Current["Settings.Service.InstallHint"],
        DaemonLocator.InstallDirectory, SystemdUnit.UnitPath);

    /// <summary>The unit as it will be installed, for review before anything runs.</summary>
    public string UnitPreview => Daemon is { } daemon
        ? ServiceManager.InstalledUnitText(daemon, GenerateUnit(daemon))
        : string.Empty;

    public string InstallScriptPreview => Daemon is { } daemon
        ? ServiceManager.BuildInstallScript(daemon, GenerateUnit(daemon))
        : string.Empty;

    public string UninstallScriptPreview => ServiceManager.BuildUninstallScript();

    public bool CanInstall => HasSystemd && HasDaemon && !IsServiceBusy;

    public bool CanControl => HasSystemd && IsServiceInstalled && !IsServiceBusy;

    private static string GenerateUnit(DaemonLocation daemon) =>
        SystemdUnit.Generate(daemon.ExecStart, CurrentUid(), IpcProtocol.DefaultSocketPath, daemon.InHome);

    private static uint CurrentUid()
    {
        // The desktop user running the app is the one the daemon must accept.
        try
        {
            return (uint)geteuid();
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return 1000;
        }
    }

    [System.Runtime.InteropServices.DllImport("libc")]
    private static extern uint geteuid();

    public void Activate() => _ = RefreshServiceAsync();

    public void Deactivate()
    {
    }

    [RelayCommand]
    public async Task RefreshServiceAsync()
    {
        if (_serviceQueryInFlight)
        {
            return;
        }

        _serviceQueryInFlight = true;
        try
        {
            // Where the daemon is, as well as what the service is doing: an install or an
            // uninstall changes both, and a path from two minutes ago is not a fact.
            Daemon = DaemonLocator.Find(DaemonPathOverride);
            Service = await _services.QueryAsync().ConfigureAwait(true);
            JournalTail = Service.State == ServiceState.Failed
                ? await _services.JournalTailAsync(20).ConfigureAwait(true)
                : string.Empty;
            RaiseService();
        }
        finally
        {
            _serviceQueryInFlight = false;
        }
    }

    [RelayCommand]
    private async Task InstallServiceAsync()
    {
        if (!HasSystemd)
        {
            return;
        }

        // Located again now, not reused from when the page was last refreshed. The displayed
        // location can be minutes old, and an uninstall in between deletes the very directory
        // it names — which is how an install came to copy a directory that was no longer there.
        Daemon = DaemonLocator.Find(DaemonPathOverride);
        RaiseService();
        if (Daemon is not { } daemon)
        {
            ServiceError = Loc.Current["Settings.Service.NoDaemon"];
            RaiseService();
            return;
        }

        await RunPrivilegedAsync(ServiceManager.BuildInstallScript(daemon, GenerateUnit(daemon)),
            Loc.Current["Settings.Service.Installed"]).ConfigureAwait(true);
    }

    [RelayCommand]
    private async Task UninstallServiceAsync()
    {
        await RunPrivilegedAsync(ServiceManager.BuildUninstallScript(), Loc.Current["Settings.Service.Uninstalled"])
            .ConfigureAwait(true);

        // The directory the location pointed at has just been removed; saying where the daemon
        // is now — the build it would install next — is more use than a stale path.
        Daemon = DaemonLocator.Find(DaemonPathOverride);
        RaiseService();
    }

    [RelayCommand]
    private Task StartServiceAsync() => ControlAsync("start");

    [RelayCommand]
    private Task StopServiceAsync() => ControlAsync("stop");

    [RelayCommand]
    private Task RestartServiceAsync() => ControlAsync("restart");

    private async Task RunPrivilegedAsync(string script, string successMessage)
    {
        IsServiceBusy = true;
        ServiceMessage = null;
        ServiceError = null;
        RaiseService();
        try
        {
            var (ok, output) = await _services.RunAsRootAsync(script).ConfigureAwait(true);
            if (ok)
            {
                ServiceMessage = successMessage;
            }
            else
            {
                ServiceError = output;
            }
        }
        finally
        {
            IsServiceBusy = false;
            await RefreshServiceAsync().ConfigureAwait(true);
            await _shell.RefreshDaemonStateAsync().ConfigureAwait(true);
            RaiseService();
        }
    }

    private async Task ControlAsync(string verb)
    {
        IsServiceBusy = true;
        ServiceMessage = null;
        ServiceError = null;
        RaiseService();
        try
        {
            var (ok, output) = await _services.ControlAsync(verb).ConfigureAwait(true);
            if (!ok)
            {
                ServiceError = output.Length > 0 ? output : Loc.Current["Settings.Service.ControlFailed"];
            }
        }
        finally
        {
            IsServiceBusy = false;
            // The daemon takes a moment to open its socket after systemd reports it active.
            await Task.Delay(600).ConfigureAwait(true);
            await RefreshServiceAsync().ConfigureAwait(true);
            await _shell.RefreshDaemonStateAsync().ConfigureAwait(true);
            RaiseService();
        }
    }

    partial void OnDaemonPathOverrideChanged(string value)
    {
        Daemon = DaemonLocator.Find(value);
        RaiseService();
    }

    private void RaiseService()
    {
        foreach (var name in new[]
                 {
                     nameof(IsServiceInstalled), nameof(IsServiceRunning), nameof(IsServiceFailed), nameof(IsServiceStopped),
                     nameof(IsServiceEnabled), nameof(CanShowStart), nameof(ServiceStateText), nameof(ServiceEnabledText), nameof(ServiceDetailText),
                     nameof(ServiceExecStartText), nameof(HasDaemon), nameof(DaemonText), nameof(UnitPreview),
                     nameof(InstallScriptPreview), nameof(CanInstall), nameof(CanControl), nameof(HasJournal), nameof(InstallHint),
                     nameof(HasSystemd), nameof(HasPolkit),
                 })
        {
            OnPropertyChanged(name);
        }
    }

    /// <summary>Re-renders every localised string after a language change.</summary>
    public void NotifyLanguageChanged() => OnPropertyChanged(string.Empty);

    /// <summary>Re-raises everything the shell owns, after the shell changes it.</summary>
    public void NotifyShellChanged()
    {
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(SelectedLanguage));
        OnPropertyChanged(nameof(ReducedMotion));
        OnPropertyChanged(nameof(UseSystemTitleBar));
        OnPropertyChanged(nameof(DnsPolicy));
        OnPropertyChanged(nameof(DnsPolicyHint));
        OnPropertyChanged(nameof(ShowAllProcesses));
        OnPropertyChanged(nameof(SecretStoreDescription));
        RaiseService();
    }
}
