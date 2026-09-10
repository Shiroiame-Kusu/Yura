using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>
/// The Settings page: appearance, language, accessibility, and the one networking policy
/// that is global rather than per rule.
/// </summary>
/// <remarks>
/// Appearance settings live on the view model that owns them (the shell) and are surfaced
/// here rather than duplicated, so there is one source of truth for the theme. DNS policy is
/// pushed to the daemon when it changes, because it changes the installed ruleset.
/// </remarks>
public sealed partial class SettingsPageViewModel : ObservableObject
{
    private readonly ShellViewModel _shell;
    private readonly IDaemonClient _daemon;

    public SettingsPageViewModel(ShellViewModel shell, IDaemonClient daemon)
    {
        _shell = shell;
        _daemon = daemon;
    }

    public bool IsDarkTheme
    {
        get => _shell.IsDarkTheme;
        set => _shell.IsDarkTheme = value;
    }

    public bool IsChinese
    {
        get => _shell.IsChinese;
        set => _shell.IsChinese = value;
    }

    public bool ReducedMotion
    {
        get => _shell.ReducedMotion;
        set => _shell.ReducedMotion = value;
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

    public string ConfigPath => _shell.ConfigPath;

    /// <summary>
    /// Where passwords go. When there is no secret service the sentence says what that means
    /// for the user, rather than naming the fallback as if it were a place.
    /// </summary>
    public string SecretStoreDescription => _shell.HasSecretStore
        ? _shell.SecretStoreDescription
        : Loc.Current["Diagnostics.SecretsInMemory"];

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

    /// <summary>Re-raises everything the shell owns, after the shell changes it.</summary>
    public void NotifyShellChanged()
    {
        OnPropertyChanged(nameof(IsDarkTheme));
        OnPropertyChanged(nameof(IsChinese));
        OnPropertyChanged(nameof(ReducedMotion));
        OnPropertyChanged(nameof(DnsPolicy));
        OnPropertyChanged(nameof(DnsPolicyHint));
        OnPropertyChanged(nameof(ShowAllProcesses));
    }
}
