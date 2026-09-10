using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Proxies;

namespace Yura.App.ViewModels;

/// <summary>The Proxies page and the editor it hosts.</summary>
public sealed partial class ProxiesPageViewModel : ObservableObject
{
    private readonly RuleStore _rules;
    private readonly IDaemonClient _daemon;

    public ProxiesPageViewModel(RuleStore rules, IDaemonClient daemon, ISecretStore secrets)
    {
        _rules = rules;
        _daemon = daemon;
        Editor = new ProxyEditorViewModel(rules, daemon, secrets);
    }

    public ObservableCollection<ProxyEndpoint> Proxies => _rules.Proxies;

    public ProxyEditorViewModel Editor { get; }

    [RelayCommand]
    private void AddProxy() => Editor.BeginAdd();

    [RelayCommand]
    private void EditProxy(ProxyEndpoint endpoint) => Editor.BeginEdit(endpoint);
}

/// <summary>
/// The Add/Edit proxy form.
/// </summary>
/// <remarks>
/// Validation is per field and runs as the user types, but only after that field has been
/// touched — flagging an empty form the instant it opens is noise. Entered values survive a
/// failed save or a failed test; nothing is cleared behind the user's back.
/// </remarks>
public sealed partial class ProxyEditorViewModel : ObservableObject
{
    private readonly RuleStore _rules;
    private readonly IDaemonClient _daemon;
    private readonly ISecretStore _secrets;
    private readonly HashSet<string> _touched = [];
    private Guid _editingId = Guid.NewGuid();
    private bool _isNew = true;
    private CancellationTokenSource? _testCts;
    private bool _passwordAlreadyStored;

    public ProxyEditorViewModel(RuleStore rules, IDaemonClient daemon, ISecretStore secrets)
    {
        _rules = rules;
        _daemon = daemon;
        _secrets = secrets;
    }

    /// <summary>
    /// Where passwords are kept, stated in the UI rather than assumed. A missing secret
    /// service is a different sentence, not the same sentence with an awkward clause
    /// wedged into it.
    /// </summary>
    public string SecretStoreDescription => _secrets.IsAvailable
        ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.SecretHint"],
            Loc.Current.Language.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
                ? Loc.Current["Proxy.SecretStore"]
                : _secrets.Description)
        : Loc.Current["Proxy.SecretHintUnavailable"];

    /// <summary>Shown when a saved password exists but is not displayed back.</summary>
    public string PasswordPlaceholder => _passwordAlreadyStored
        ? "Saved — leave blank to keep"
        : Loc.Current["Proxy.Optional"];

    public IReadOnlyList<ProxyProtocol> Protocols { get; } =
        [ProxyProtocol.Socks5, ProxyProtocol.Http, ProxyProtocol.Https];

    [ObservableProperty]
    public partial bool IsOpen { get; set; }

    public string Title => _isNew
        ? Loc.Current["Proxy.Editor.TitleNew"]
        : Loc.Current["Proxy.Editor.TitleEdit"];

    [ObservableProperty]
    public partial string Name { get; set; } = string.Empty;

    [ObservableProperty]
    public partial ProxyProtocol Protocol { get; set; } = ProxyProtocol.Socks5;

    [ObservableProperty]
    public partial string Host { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Port { get; set; } = "1080";

    [ObservableProperty]
    public partial string Username { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool ShowAdvanced { get; set; }

    // -- validation ------------------------------------------------------------

    public string? NameError
    {
        get
        {
            if (!_touched.Contains(nameof(Name)))
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(Name))
            {
                return Loc.Current["Proxy.Validation.NameRequired"];
            }

            var clash = _rules.Proxies.Any(p =>
                p.Id != _editingId && string.Equals(p.Name, Name.Trim(), StringComparison.OrdinalIgnoreCase));

            return clash ? Loc.Current["Proxy.Validation.NameDuplicate"] : null;
        }
    }

    public string? HostError
    {
        get
        {
            if (!_touched.Contains(nameof(Host)))
            {
                return null;
            }

            var value = Host.Trim();
            if (value.Length == 0)
            {
                return Loc.Current["Proxy.Validation.HostRequired"];
            }

            if (IPAddress.TryParse(value, out _))
            {
                return null;
            }

            // Accept anything Uri considers a valid DNS name; reject spaces, schemes and
            // stray punctuation with one specific message rather than a generic "invalid".
            return Uri.CheckHostName(value) == UriHostNameType.Unknown
                ? Loc.Current["Proxy.Validation.HostInvalid"]
                : null;
        }
    }

    public string? PortError
    {
        get
        {
            if (!_touched.Contains(nameof(Port)))
            {
                return null;
            }

            return ushort.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p > 0
                ? null
                : Loc.Current["Proxy.Validation.PortRange"];
        }
    }

    public bool HasNameError => NameError is not null;

    public bool HasHostError => HostError is not null;

    public bool HasPortError => PortError is not null;

    /// <summary>True only when every field is valid, evaluated regardless of touch state.</summary>
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(Name) &&
        !_rules.Proxies.Any(p => p.Id != _editingId &&
                                 string.Equals(p.Name, Name.Trim(), StringComparison.OrdinalIgnoreCase)) &&
        Host.Trim().Length > 0 &&
        (IPAddress.TryParse(Host.Trim(), out _) || Uri.CheckHostName(Host.Trim()) != UriHostNameType.Unknown) &&
        ushort.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port > 0;

    public bool CanSave => IsValid && !IsBusy;

    // -- test ------------------------------------------------------------------

    [ObservableProperty]
    public partial bool IsTesting { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string? TestResultText { get; set; }

    [ObservableProperty]
    public partial bool TestSucceeded { get; set; }

    [ObservableProperty]
    public partial string? TestDiagnostics { get; set; }

    public bool CanTest => IsValid && !IsTesting;

    // -- lifecycle -------------------------------------------------------------

    public void BeginAdd()
    {
        // Allocated now, not at save time, so the password can be stored against the same
        // id the endpoint will carry.
        _editingId = Guid.NewGuid();
        _isNew = true;
        _touched.Clear();
        Name = string.Empty;
        Protocol = ProxyProtocol.Socks5;
        Host = string.Empty;
        Port = "1080";
        Username = string.Empty;
        Password = string.Empty;
        _passwordAlreadyStored = false;
        ShowAdvanced = false;
        ClearTest();
        IsOpen = true;
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(PasswordPlaceholder));
    }

    public void BeginEdit(ProxyEndpoint endpoint)
    {
        _editingId = endpoint.Id;
        _isNew = false;
        _touched.Clear();
        Name = endpoint.Name;
        Protocol = endpoint.Protocol;
        Host = endpoint.Host;
        Port = endpoint.Port.ToString(CultureInfo.InvariantCulture);
        Username = endpoint.Username ?? string.Empty;
        Password = string.Empty; // Never round-trips through the UI.
        _passwordAlreadyStored = endpoint.PasswordRef is not null;
        OnPropertyChanged(nameof(PasswordPlaceholder));
        ShowAdvanced = false;
        ClearTest();
        IsOpen = true;
        OnPropertyChanged(nameof(Title));
    }

    [RelayCommand]
    private async Task TestAsync()
    {
        if (!CanTest)
        {
            return;
        }

        // Guards against a double-click starting two probes; the second cancels the first
        // rather than racing it.
        _testCts?.Cancel();
        _testCts = new CancellationTokenSource();
        var token = _testCts.Token;

        IsTesting = true;
        TestResultText = Loc.Current["Proxy.Testing"];
        TestDiagnostics = null;
        OnPropertyChanged(nameof(CanTest));

        try
        {
            var endpoint = Build();
            var password = !string.IsNullOrEmpty(Password)
                ? Password
                : await _secrets.GetAsync(endpoint.Id.ToString(), token).ConfigureAwait(true);
            var result = await _daemon.ProbeProxyAsync(endpoint, password, token).ConfigureAwait(true);
            if (token.IsCancellationRequested)
            {
                return;
            }

            TestSucceeded = result.Reachable;
            TestResultText = result.Reachable
                ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.TestPassed"],
                    result.HandshakeLatency?.TotalMilliseconds.ToString("0", CultureInfo.CurrentCulture) ?? "?")
                : result.FailureReason ?? Loc.Current["Proxy.TestFailed"];
            TestDiagnostics = result.Diagnostics;
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer test; leave the newer one to report.
        }
        finally
        {
            IsTesting = false;
            OnPropertyChanged(nameof(CanTest));
        }
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        // Mark everything touched so a click on a disabled-looking form surfaces every
        // problem at once rather than one at a time.
        MarkAllTouched();
        if (!IsValid)
        {
            return;
        }

        var endpoint = Build();

        // The password goes to the secret store, never into the configuration file. An
        // empty box on an existing proxy means "keep what is saved", not "clear it".
        if (!string.IsNullOrEmpty(Password))
        {
            await _secrets.SetAsync(endpoint.Id.ToString(), Password).ConfigureAwait(true);
        }

        var existing = _rules.Proxies.FirstOrDefault(p => p.Id == endpoint.Id);
        if (existing is not null)
        {
            _rules.Proxies[_rules.Proxies.IndexOf(existing)] = endpoint;
        }
        else
        {
            _rules.Proxies.Add(endpoint);
        }

        IsOpen = false;
    }

    [RelayCommand]
    private void Cancel()
    {
        _testCts?.Cancel();
        IsOpen = false;
    }

    private ProxyEndpoint Build() => new()
    {
        Id = _editingId,
        Name = Name.Trim(),
        Protocol = Protocol,
        Host = Host.Trim(),
        Port = ushort.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : (ushort)0,
        Username = string.IsNullOrWhiteSpace(Username) ? null : Username.Trim(),
        // Keyed on the id, not the name: renaming a proxy must not orphan its password.
        PasswordRef = string.IsNullOrEmpty(Password) && !_passwordAlreadyStored
            ? null
            : _editingId.ToString(),
    };

    private void ClearTest()
    {
        TestResultText = null;
        TestDiagnostics = null;
        TestSucceeded = false;
    }

    private void MarkAllTouched()
    {
        _touched.Add(nameof(Name));
        _touched.Add(nameof(Host));
        _touched.Add(nameof(Port));
        RaiseValidation();
    }

    private void Touch(string field)
    {
        _touched.Add(field);
        RaiseValidation();
    }

    private void RaiseValidation()
    {
        OnPropertyChanged(nameof(NameError));
        OnPropertyChanged(nameof(HostError));
        OnPropertyChanged(nameof(PortError));
        OnPropertyChanged(nameof(HasNameError));
        OnPropertyChanged(nameof(HasHostError));
        OnPropertyChanged(nameof(HasPortError));
        OnPropertyChanged(nameof(IsValid));
        OnPropertyChanged(nameof(CanSave));
        OnPropertyChanged(nameof(CanTest));
    }

    partial void OnNameChanged(string value) => Touch(nameof(Name));

    partial void OnHostChanged(string value) => Touch(nameof(Host));

    partial void OnPortChanged(string value) => Touch(nameof(Port));

    partial void OnProtocolChanged(ProxyProtocol value)
    {
        // Default ports follow the protocol until the user overrides them.
        if (!_touched.Contains(nameof(Port)) || Port is "1080" or "8080" or "3128")
        {
            Port = value == ProxyProtocol.Socks5 ? "1080" : "8080";
        }

        RaiseValidation();
    }

    partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(CanSave));
}
