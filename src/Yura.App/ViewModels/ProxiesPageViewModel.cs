using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Globalization;
using System.Net;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Agent;
using Yura.Core.Proxies;

namespace Yura.App.ViewModels;

/// <summary>
/// One proxy in the list, with the live state of the exit when Yura runs one.
/// </summary>
/// <remarks>
/// A WireGuard exit and a Yura agent are the two kinds Yura is on both ends of, so they are
/// the two that can say more than "configured": whether the peer has answered, whether the
/// session is up. An ordinary proxy has nothing to report until a flow uses it.
/// </remarks>
public sealed partial class ProxyRowViewModel : ObservableObject
{
    public ProxyRowViewModel(ProxyEndpoint endpoint) => Endpoint = endpoint;

    [ObservableProperty]
    public partial ProxyEndpoint Endpoint { get; set; }

    /// <summary>Null until the daemon has answered; a WireGuard row then says what it knows.</summary>
    [ObservableProperty]
    public partial TunnelStatus? Tunnel { get; set; }

    /// <summary>Null until the daemon has answered; an agent row then says what it knows.</summary>
    [ObservableProperty]
    public partial AgentStatus? Agent { get; set; }

    public Guid Id => Endpoint.Id;

    public string Name => Endpoint.Name;

    public string Authority => Endpoint.Authority;

    public string ProtocolDisplay => Endpoint.ProtocolDisplay;

    public bool IsWireGuard => Endpoint.IsWireGuard;

    public bool IsAgent => Endpoint.IsAgent;

    /// <summary>True for the exits that have a live state worth a line of their own.</summary>
    public bool ShowState => IsWireGuard || IsAgent;

    public bool IsExitUp => IsAgent
        ? Agent is { Connected: true }
        : Tunnel?.Up == true && Tunnel.LatestHandshakeUtc is not null;

    public bool IsExitDown => IsAgent ? Agent is { Connected: false } : Tunnel is { Up: false };

    /// <summary>The exit in one line: what it last did, or why it cannot.</summary>
    public string StateText => IsAgent ? AgentText : TunnelText;

    /// <summary>The agent session in one line.</summary>
    private string AgentText
    {
        get
        {
            if (Agent is null)
            {
                return Loc.Current["Proxy.Agent.Unknown"];
            }

            if (!Agent.Connected)
            {
                return string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Agent.Down"], Agent.Failure);
            }

            var round = Agent.RoundTripMilliseconds is { } ms
                ? string.Create(CultureInfo.CurrentCulture, $"{ms:0.#} ms")
                : Loc.Current["Common.NotMeasured"];
            return string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Agent.Up"],
                Agent.AgentName ?? Agent.Name, round,
                Loc.Current[Agent.Udp
                    ? Agent.FullCone ? "Proxy.Agent.UdpCone" : "Proxy.Agent.UdpYes"
                    : "Proxy.Agent.UdpNo"]);
        }
    }

    /// <summary>The tunnel in one line: when the peer last answered, or why it cannot.</summary>
    private string TunnelText
    {
        get
        {
            if (!IsWireGuard)
            {
                return string.Empty;
            }

            if (Tunnel is null)
            {
                return Loc.Current["Proxy.Tunnel.Unknown"];
            }

            if (!Tunnel.Up)
            {
                return string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Tunnel.Down"], Tunnel.Failure);
            }

            if (Tunnel.LatestHandshakeUtc is not { } handshake)
            {
                return Loc.Current["Proxy.Tunnel.NoHandshake"];
            }

            var age = DateTimeOffset.UtcNow - handshake;
            var when = age.TotalSeconds < 90
                ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Tunnel.SecondsAgo"], (int)Math.Max(0, age.TotalSeconds))
                : age.TotalMinutes < 90
                    ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Tunnel.MinutesAgo"], (int)age.TotalMinutes)
                    : string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Tunnel.HoursAgo"], (int)age.TotalHours);
            return string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Tunnel.Up"], when,
                FormatBytes(Tunnel.TxBytes), FormatBytes(Tunnel.RxBytes));
        }
    }

    public void Update(ProxyEndpoint endpoint)
    {
        Endpoint = endpoint;
        RaiseAll();
    }

    public void UpdateTunnel(TunnelStatus? status)
    {
        Tunnel = status;
        RaiseState();
    }

    public void UpdateAgent(AgentStatus? status)
    {
        Agent = status;
        RaiseState();
    }

    private void RaiseState()
    {
        OnPropertyChanged(nameof(IsExitUp));
        OnPropertyChanged(nameof(IsExitDown));
        OnPropertyChanged(nameof(StateText));
    }

    public void RaiseAll()
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Authority));
        OnPropertyChanged(nameof(ProtocolDisplay));
        OnPropertyChanged(nameof(IsWireGuard));
        OnPropertyChanged(nameof(IsAgent));
        OnPropertyChanged(nameof(ShowState));
        RaiseState();
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => string.Create(CultureInfo.CurrentCulture, $"{bytes} B"),
        < 1024 * 1024 => string.Create(CultureInfo.CurrentCulture, $"{bytes / 1024.0:0.#} KB"),
        < 1024L * 1024 * 1024 => string.Create(CultureInfo.CurrentCulture, $"{bytes / (1024.0 * 1024):0.#} MB"),
        _ => string.Create(CultureInfo.CurrentCulture, $"{bytes / (1024.0 * 1024 * 1024):0.##} GB"),
    };
}

/// <summary>One chain in the list.</summary>
public sealed partial class ChainRowViewModel : ObservableObject
{
    private readonly RuleStore _rules;

    public ChainRowViewModel(ProxyChain chain, RuleStore rules)
    {
        _rules = rules;
        Chain = chain;
    }

    [ObservableProperty]
    public partial ProxyChain Chain { get; set; }

    public Guid Id => Chain.Id;

    public string Name => Chain.Name;

    public string HopsDisplay => RouteOption.DescribeHops(Chain, _rules.Proxies);

    public string HopCount => string.Format(CultureInfo.CurrentCulture, Loc.Current["Chain.HopCount"], Chain.Hops.Count);

    /// <summary>Why the daemon would refuse this chain, when it would.</summary>
    public string? Problem
    {
        get
        {
            var hops = Chain.Hops.Select(id => _rules.Proxies.FirstOrDefault(p => p.Id == id)).ToList();
            if (hops.Any(h => h is null))
            {
                return Loc.Current["Chain.Validation.MissingHop"];
            }

            return ProxyChain.Validate(hops!) is { } invalid ? Localise(invalid, hops!) : null;
        }
    }

    public bool HasProblem => Problem is not null;

    public void Update(ProxyChain chain)
    {
        Chain = chain;
        RaiseAll();
    }

    public void RaiseAll()
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(HopsDisplay));
        OnPropertyChanged(nameof(HopCount));
        OnPropertyChanged(nameof(Problem));
        OnPropertyChanged(nameof(HasProblem));
    }

    /// <summary>The domain's English reasons, rendered in the user's language.</summary>
    internal static string Localise(string reason, IReadOnlyList<ProxyEndpoint> hops)
    {
        var exit = hops.Skip(1).FirstOrDefault(h => h.Protocol == ProxyProtocol.WireGuard);
        return exit is not null
            ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Chain.Validation.WireGuardFirst"], exit.Name)
            : reason;
    }
}

/// <summary>The Proxies page: the exits Yura can send traffic to, and the editors for them.</summary>
public sealed partial class ProxiesPageViewModel : ObservableObject, IDisposable
{
    private readonly RuleStore _rules;
    private readonly IDaemonClient _daemon;
    private readonly DispatcherTimer _tunnelTimer;
    private bool _tunnelRefreshInFlight;

    public ProxiesPageViewModel(RuleStore rules, IDaemonClient daemon, ISecretStore secrets)
    {
        _rules = rules;
        _daemon = daemon;
        Editor = new ProxyEditorViewModel(rules, daemon, secrets);
        ChainEditor = new ChainEditorViewModel(rules);

        Editor.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ProxyEditorViewModel.IsOpen))
            {
                if (Editor.IsOpen)
                {
                    ChainEditor.IsOpen = false;
                }
                else if (!_syncingSelection)
                {
                    ClearSelection();
                }

                OnPropertyChanged(nameof(IsAnyEditorOpen));
            }
        };
        ChainEditor.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ChainEditorViewModel.IsOpen))
            {
                if (ChainEditor.IsOpen)
                {
                    Editor.IsOpen = false;
                }
                else if (!_syncingSelection)
                {
                    ClearSelection();
                }

                OnPropertyChanged(nameof(IsAnyEditorOpen));
            }
        };

        Editor.Saved += (_, _) => _ = RefreshTunnelsAsync();

        _rules.Proxies.CollectionChanged += OnProxiesChanged;
        _rules.Chains.CollectionChanged += OnChainsChanged;
        RebuildProxies();
        RebuildChains();

        _tunnelTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _tunnelTimer.Tick += (_, _) => _ = RefreshTunnelsAsync();
    }

    public ObservableCollection<ProxyRowViewModel> Proxies { get; } = [];

    public ObservableCollection<ChainRowViewModel> Chains { get; } = [];

    /// <summary>
    /// The row the editor is showing.
    /// </summary>
    /// <remarks>
    /// Bound to the list rather than opened by a click, so the highlighted row and the editor
    /// can never disagree about what is being edited, and arrow keys move through the list the
    /// way they do everywhere else. Selecting in one list clears the other, because there is
    /// one editor panel.
    /// </remarks>
    [ObservableProperty]
    public partial ProxyRowViewModel? SelectedProxy { get; set; }

    [ObservableProperty]
    public partial ChainRowViewModel? SelectedChain { get; set; }

    /// <summary>
    /// True while a selection change is being carried out, including the editor call it makes.
    /// </summary>
    /// <remarks>
    /// It has to cover the editor call, not just the paired assignment. Opening one editor
    /// closes the other, and an editor that closes drops the selection — so without this the
    /// act of selecting a chain would clear the chain it just selected.
    /// </remarks>
    private bool _syncingSelection;

    partial void OnSelectedProxyChanged(ProxyRowViewModel? value)
    {
        if (_syncingSelection || value is null)
        {
            return;
        }

        _syncingSelection = true;
        try
        {
            SelectedChain = null;
            Editor.BeginEdit(value.Endpoint);
        }
        finally
        {
            _syncingSelection = false;
        }
    }

    partial void OnSelectedChainChanged(ChainRowViewModel? value)
    {
        if (_syncingSelection || value is null)
        {
            return;
        }

        _syncingSelection = true;
        try
        {
            SelectedProxy = null;
            ChainEditor.BeginEdit(value.Chain);
        }
        finally
        {
            _syncingSelection = false;
        }
    }

    /// <summary>Drops both selections, so an editor opened for something new owns the panel.</summary>
    private void ClearSelection()
    {
        _syncingSelection = true;
        SelectedProxy = null;
        SelectedChain = null;
        _syncingSelection = false;
    }

    public ProxyEditorViewModel Editor { get; }

    public ChainEditorViewModel ChainEditor { get; }

    public bool IsAnyEditorOpen => Editor.IsOpen || ChainEditor.IsOpen;

    /// <summary>
    /// True when the window is too narrow to dock the editor beside the lists.
    /// </summary>
    /// <remarks>
    /// Set by the view from its own width, because the threshold is a property of this layout
    /// and nothing else in the application needs to know it.
    /// </remarks>
    [ObservableProperty]
    public partial bool IsCompact { get; set; }

    public bool HasProxies => Proxies.Count > 0;

    public bool HasChains => Chains.Count > 0;

    /// <summary>A chain needs proxies to be made of.</summary>
    public bool CanAddChain => _rules.Proxies.Count > 0;

    [RelayCommand]
    private void AddProxy()
    {
        ClearSelection();
        Editor.BeginAdd();
    }

    [RelayCommand]
    private void AddWireGuard()
    {
        ClearSelection();
        Editor.BeginAddWireGuard();
    }

    [RelayCommand]
    private void AddAgent()
    {
        ClearSelection();
        Editor.BeginAddAgent();
    }

    [RelayCommand]
    private void AddChain()
    {
        ClearSelection();
        ChainEditor.BeginAdd();
    }

    // -- lifecycle -------------------------------------------------------------

    /// <summary>Called by the shell when the page becomes visible: tunnel state is only polled while it is.</summary>
    public void Activate()
    {
        _tunnelTimer.Start();
        _ = RefreshTunnelsAsync();
    }

    public void Deactivate() => _tunnelTimer.Stop();

    private async Task RefreshTunnelsAsync()
    {
        if (_tunnelRefreshInFlight || !Proxies.Any(p => p.ShowState))
        {
            return;
        }

        _tunnelRefreshInFlight = true;
        try
        {
            if (_daemon.State != DaemonState.Connected)
            {
                // Nothing is known rather than everything being down: the difference is what
                // the row says, and guessing would be a claim about the exit.
                foreach (var row in Proxies)
                {
                    row.UpdateTunnel(null);
                    row.UpdateAgent(null);
                }

                return;
            }

            var status = await _daemon.GetStatusAsync().ConfigureAwait(true);
            var tunnels = (status?.Tunnels ?? []).ToDictionary(t => t.ProxyId);
            var agents = (status?.Agents ?? []).ToDictionary(a => a.ProxyId);
            foreach (var row in Proxies.Where(r => r.IsWireGuard))
            {
                row.UpdateTunnel(tunnels.GetValueOrDefault(row.Id));
            }

            foreach (var row in Proxies.Where(r => r.IsAgent))
            {
                row.UpdateAgent(agents.GetValueOrDefault(row.Id));
            }
        }
        finally
        {
            _tunnelRefreshInFlight = false;
        }
    }

    private void OnProxiesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RebuildProxies();
        foreach (var chain in Chains)
        {
            chain.RaiseAll(); // A renamed or removed hop changes how every chain reads.
        }

        OnPropertyChanged(nameof(CanAddChain));
        _ = RefreshTunnelsAsync();
    }

    private void OnChainsChanged(object? sender, NotifyCollectionChangedEventArgs e) => RebuildChains();

    private void RebuildProxies()
    {
        var desired = _rules.Proxies.ToList();
        for (var i = Proxies.Count - 1; i >= 0; i--)
        {
            if (desired.All(p => p.Id != Proxies[i].Id))
            {
                Proxies.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            var existing = Proxies.FirstOrDefault(r => r.Id == desired[i].Id);
            if (existing is null)
            {
                Proxies.Insert(Math.Min(i, Proxies.Count), new ProxyRowViewModel(desired[i]));
            }
            else if (!ReferenceEquals(existing.Endpoint, desired[i]))
            {
                existing.Update(desired[i]);
            }
        }

        // A row that has gone takes the selection with it rather than leaving the editor
        // open on something that no longer exists.
        if (SelectedProxy is { } selected && !Proxies.Contains(selected))
        {
            ClearSelection();
        }

        OnPropertyChanged(nameof(HasProxies));
    }

    private void RebuildChains()
    {
        var desired = _rules.Chains.ToList();
        for (var i = Chains.Count - 1; i >= 0; i--)
        {
            if (desired.All(c => c.Id != Chains[i].Id))
            {
                Chains.RemoveAt(i);
            }
        }

        for (var i = 0; i < desired.Count; i++)
        {
            var existing = Chains.FirstOrDefault(r => r.Id == desired[i].Id);
            if (existing is null)
            {
                Chains.Insert(Math.Min(i, Chains.Count), new ChainRowViewModel(desired[i], _rules));
            }
            else if (!ReferenceEquals(existing.Chain, desired[i]))
            {
                existing.Update(desired[i]);
            }
        }

        if (SelectedChain is { } selected && !Chains.Contains(selected))
        {
            ClearSelection();
        }

        OnPropertyChanged(nameof(HasChains));
    }

    /// <summary>Re-renders every localised string after a language change.</summary>
    public void NotifyLanguageChanged()
    {
        foreach (var row in Proxies)
        {
            row.RaiseAll();
        }

        foreach (var row in Chains)
        {
            row.RaiseAll();
        }

        Editor.NotifyLanguageChanged();
    }

    public void Dispose() => _tunnelTimer.Stop();
}

/// <summary>
/// The Add/Edit proxy form, for every protocol including WireGuard exits.
/// </summary>
/// <remarks>
/// Validation is per field and runs as the user types, but only after that field has been
/// touched — flagging an empty form the instant it opens is noise. Entered values survive a
/// failed save or a failed test; nothing is cleared behind the user's back. Keys and
/// passwords never round-trip through the form: a saved secret shows as a placeholder that
/// says so, and leaving the box empty keeps it.
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
    private bool _presharedAlreadyStored;

    /// <summary>
    /// The protocol the endpoint had when the form opened.
    /// </summary>
    /// <remarks>
    /// A saved secret only counts when it is the right kind of secret. Switching a SOCKS5 proxy
    /// to WireGuard would otherwise pass validation with the proxy's password standing in for a
    /// private key, and to an agent with it standing in for a token; the daemon would then
    /// refuse the exit, and a form that says valid while the daemon says no is the worst of
    /// both.
    /// </remarks>
    private ProxyProtocol _editingProtocol = ProxyProtocol.Socks5;

    public ProxyEditorViewModel(RuleStore rules, IDaemonClient daemon, ISecretStore secrets)
    {
        _rules = rules;
        _daemon = daemon;
        _secrets = secrets;
    }

    /// <summary>Raised after a proxy is saved, so the page can refresh what depends on it.</summary>
    public event EventHandler? Saved;

    /// <summary>
    /// Raised with the sentence to show when a secret service exists and still refused a
    /// secret, which then lasts only as long as the app does.
    /// </summary>
    /// <remarks>
    /// Out of the editor, because the editor closes on save. When there is no secret service at
    /// all the editor has already said the secret is kept for this session only.
    /// </remarks>
    public event EventHandler<string>? SecretNotStored;

    /// <summary>Set by the view: opens a file picker and returns the chosen file's text.</summary>
    public Func<CancellationToken, Task<string?>>? PickConfigurationFile { get; set; }

    /// <summary>
    /// Where secrets are kept, stated in the UI rather than assumed. A missing secret service
    /// is a different sentence, not the same sentence with an awkward clause wedged into it.
    /// </summary>
    public string SecretStoreDescription => _secrets.IsAvailable
        ? string.Format(CultureInfo.CurrentCulture, Loc.Current[IsWireGuard ? "Proxy.WireGuard.SecretHint" : "Proxy.SecretHint"],
            SecretStoreName)
        : Loc.Current[IsWireGuard ? "Proxy.WireGuard.SecretHintUnavailable" : "Proxy.SecretHintUnavailable"];

    /// <summary>Where secrets go, as a phrase in the current language.</summary>
    private string SecretStoreName => Loc.Current.Language.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
        ? Loc.Current["Proxy.SecretStore"]
        : _secrets.Description;

    /// <summary>Shown when a saved password exists but is not displayed back.</summary>
    public string PasswordPlaceholder => _passwordAlreadyStored
        ? Loc.Current["Proxy.SecretSaved"]
        : Loc.Current["Proxy.Optional"];

    public string PrivateKeyPlaceholder => HasStoredPrivateKey
        ? Loc.Current["Proxy.SecretSaved"]
        : Loc.Current["Proxy.PrivateKeyPlaceholder"];

    /// <summary>True when a private key is already in the secret store for this exit.</summary>
    private bool HasStoredPrivateKey => _passwordAlreadyStored && SecretKindOf(_editingProtocol) == SecretKind.PrivateKey;

    /// <summary>True when a token is already in the secret store for this exit.</summary>
    private bool HasStoredToken => _passwordAlreadyStored && SecretKindOf(_editingProtocol) == SecretKind.Token;

    /// <summary>What the one stored secret is, which is not the same thing for every protocol.</summary>
    private enum SecretKind
    {
        Password,
        PrivateKey,
        Token,
    }

    private static SecretKind SecretKindOf(ProxyProtocol protocol) => protocol switch
    {
        ProxyProtocol.WireGuard => SecretKind.PrivateKey,
        ProxyProtocol.YuraAgent => SecretKind.Token,
        _ => SecretKind.Password,
    };

    public string PresharedKeyPlaceholder => _presharedAlreadyStored
        ? Loc.Current["Proxy.SecretSaved"]
        : Loc.Current["Proxy.Optional"];

    public IReadOnlyList<ProxyProtocol> Protocols { get; } =
        [ProxyProtocol.Socks5, ProxyProtocol.Http, ProxyProtocol.Https, ProxyProtocol.WireGuard, ProxyProtocol.YuraAgent];

    [ObservableProperty]
    public partial bool IsOpen { get; set; }

    public string Title => (_isNew, Protocol) switch
    {
        (true, ProxyProtocol.WireGuard) => Loc.Current["Proxy.Editor.TitleNewWireGuard"],
        (true, ProxyProtocol.YuraAgent) => Loc.Current["Proxy.Editor.TitleNewAgent"],
        (true, _) => Loc.Current["Proxy.Editor.TitleNew"],
        (false, ProxyProtocol.WireGuard) => Loc.Current["Proxy.Editor.TitleEditWireGuard"],
        (false, ProxyProtocol.YuraAgent) => Loc.Current["Proxy.Editor.TitleEditAgent"],
        _ => Loc.Current["Proxy.Editor.TitleEdit"],
    };

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
    public partial bool AllowInvalidCertificate { get; set; }

    [ObservableProperty]
    public partial bool ShowAdvanced { get; set; }

    // -- agent -------------------------------------------------------------------

    public bool IsAgent => Protocol == ProxyProtocol.YuraAgent;

    /// <summary>The agent's pinned public key, as printed beside its connect string.</summary>
    [ObservableProperty]
    public partial string Fingerprint { get; set; } = string.Empty;

    /// <summary>The shared token. A secret: it goes to the secret store, never to the config file.</summary>
    [ObservableProperty]
    public partial string Token { get; set; } = string.Empty;

    /// <summary>What the agent called itself, kept for display when the exit is named otherwise.</summary>
    [ObservableProperty]
    public partial string AgentLabel { get; set; } = string.Empty;

    public string TokenPlaceholder => HasStoredToken
        ? Loc.Current["Proxy.SecretSaved"]
        : Loc.Current["Proxy.TokenPlaceholder"];

    // -- WireGuard ---------------------------------------------------------------

    public bool IsWireGuard => Protocol == ProxyProtocol.WireGuard;

    public bool IsHttps => Protocol == ProxyProtocol.Https;

    public bool UsesCredentials => !IsWireGuard && !IsAgent;

    public string HostLabel => Loc.Current[IsWireGuard ? "Proxy.Endpoint" : IsAgent ? "Proxy.Agent.Address" : "Proxy.Host"];

    public string HostPlaceholder =>
        Loc.Current[IsWireGuard ? "Proxy.EndpointPlaceholder" : IsAgent ? "Proxy.Agent.AddressPlaceholder" : "Proxy.HostPlaceholder"];

    [ObservableProperty]
    public partial string PrivateKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PeerPublicKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string PresharedKey { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Addresses { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string DnsServers { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string AllowedIps { get; set; } = "0.0.0.0/0, ::/0";

    [ObservableProperty]
    public partial string Mtu { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Keepalive { get; set; } = "25";

    [ObservableProperty]
    public partial string ImportText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string? ImportMessage { get; set; }

    [ObservableProperty]
    public partial bool ShowImport { get; set; }

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
                return Loc.Current[IsWireGuard ? "Proxy.Validation.EndpointRequired" : "Proxy.Validation.HostRequired"];
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

    public string? PrivateKeyError =>
        !IsWireGuard || !_touched.Contains(nameof(PrivateKey)) ? null
        : PrivateKey.Trim().Length == 0 && HasStoredPrivateKey ? null
        : WireGuardConfig.IsValidKey(PrivateKey) ? null
        : Loc.Current["Proxy.Validation.PrivateKey"];

    public string? PeerPublicKeyError =>
        !IsWireGuard || !_touched.Contains(nameof(PeerPublicKey)) ? null
        : WireGuardConfig.IsValidKey(PeerPublicKey) ? null
        : Loc.Current["Proxy.Validation.PeerKey"];

    public string? PresharedKeyError =>
        !IsWireGuard || !_touched.Contains(nameof(PresharedKey)) ? null
        : PresharedKey.Trim().Length == 0 || WireGuardConfig.IsValidKey(PresharedKey) ? null
        : Loc.Current["Proxy.Validation.PresharedKey"];

    public string? AddressesError
    {
        get
        {
            if (!IsWireGuard || !_touched.Contains(nameof(Addresses)))
            {
                return null;
            }

            var list = WireGuardConfig.SplitList(Addresses);
            if (list.Count == 0)
            {
                return Loc.Current["Proxy.Validation.Addresses"];
            }

            var bad = list.FirstOrDefault(a => !WireGuardConfig.TryParseAddress(a, out _, out _));
            return bad is null ? null : string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Validation.Address"], bad);
        }
    }

    public string? DnsError
    {
        get
        {
            if (!IsWireGuard || !_touched.Contains(nameof(DnsServers)))
            {
                return null;
            }

            var bad = WireGuardConfig.SplitList(DnsServers).FirstOrDefault(d => !IPAddress.TryParse(d, out _));
            return bad is null ? null : string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Validation.Dns"], bad);
        }
    }

    public string? AllowedIpsError
    {
        get
        {
            if (!IsWireGuard || !_touched.Contains(nameof(AllowedIps)))
            {
                return null;
            }

            var bad = WireGuardConfig.SplitList(AllowedIps).FirstOrDefault(a => !WireGuardConfig.TryParseCidr(a, out _));
            return bad is null ? null : string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Validation.AllowedIps"], bad);
        }
    }

    public string? MtuError =>
        !IsWireGuard || !_touched.Contains(nameof(Mtu)) || Mtu.Trim().Length == 0 ? null
        : int.TryParse(Mtu.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var mtu) && mtu is >= 1280 and <= 65535 ? null
        : Loc.Current["Proxy.Validation.Mtu"];

    public string? KeepaliveError =>
        !IsWireGuard || !_touched.Contains(nameof(Keepalive)) || Keepalive.Trim().Length == 0 ? null
        : int.TryParse(Keepalive.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var k) && k is >= 0 and <= 65535 ? null
        : Loc.Current["Proxy.Validation.Keepalive"];

    public string? FingerprintError =>
        !IsAgent || !_touched.Contains(nameof(Fingerprint)) ? null
        : AgentConnection.IsValidFingerprint(Fingerprint) ? null
        : Loc.Current["Proxy.Validation.Fingerprint"];

    public string? TokenError
    {
        get
        {
            if (!IsAgent || !_touched.Contains(nameof(Token)))
            {
                return null;
            }

            if (Token.Trim().Length == 0)
            {
                // An empty box on an exit that already has one means "keep it".
                return HasStoredToken ? null : Loc.Current["Proxy.Validation.TokenRequired"];
            }

            return AgentConnection.IsValidToken(Token) ? null : Loc.Current["Proxy.Validation.Token"];
        }
    }

    public bool HasFingerprintError => FingerprintError is not null;

    public bool HasTokenError => TokenError is not null;

    public bool HasNameError => NameError is not null;

    public bool HasHostError => HostError is not null;

    public bool HasPortError => PortError is not null;

    public bool HasPrivateKeyError => PrivateKeyError is not null;

    public bool HasPeerPublicKeyError => PeerPublicKeyError is not null;

    public bool HasPresharedKeyError => PresharedKeyError is not null;

    public bool HasAddressesError => AddressesError is not null;

    public bool HasDnsError => DnsError is not null;

    public bool HasAllowedIpsError => AllowedIpsError is not null;

    public bool HasMtuError => MtuError is not null;

    public bool HasKeepaliveError => KeepaliveError is not null;

    /// <summary>True only when every field is valid, evaluated regardless of touch state.</summary>
    public bool IsValid =>
        !string.IsNullOrWhiteSpace(Name) &&
        !_rules.Proxies.Any(p => p.Id != _editingId &&
                                 string.Equals(p.Name, Name.Trim(), StringComparison.OrdinalIgnoreCase)) &&
        Host.Trim().Length > 0 &&
        (IPAddress.TryParse(Host.Trim(), out _) || Uri.CheckHostName(Host.Trim()) != UriHostNameType.Unknown) &&
        ushort.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port > 0 &&
        (!IsWireGuard || IsWireGuardValid) &&
        (!IsAgent || IsAgentValid);

    private bool IsAgentValid =>
        AgentConnection.IsValidFingerprint(Fingerprint) &&
        (AgentConnection.IsValidToken(Token) || (Token.Trim().Length == 0 && HasStoredToken));

    private bool IsWireGuardValid =>
        (WireGuardConfig.IsValidKey(PrivateKey) || (PrivateKey.Trim().Length == 0 && HasStoredPrivateKey)) &&
        WireGuardConfig.IsValidKey(PeerPublicKey) &&
        (PresharedKey.Trim().Length == 0 || WireGuardConfig.IsValidKey(PresharedKey)) &&
        WireGuardConfig.SplitList(Addresses) is { Count: > 0 } addresses &&
        addresses.All(a => WireGuardConfig.TryParseAddress(a, out _, out _)) &&
        WireGuardConfig.SplitList(DnsServers).All(d => IPAddress.TryParse(d, out _)) &&
        WireGuardConfig.SplitList(AllowedIps).All(a => WireGuardConfig.TryParseCidr(a, out _)) &&
        (Mtu.Trim().Length == 0 || (int.TryParse(Mtu.Trim(), out var mtu) && mtu is >= 1280 and <= 65535)) &&
        (Keepalive.Trim().Length == 0 || (int.TryParse(Keepalive.Trim(), out var keep) && keep is >= 0 and <= 65535));

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

    // -- removal ---------------------------------------------------------------

    [ObservableProperty]
    public partial bool IsConfirmingRemove { get; set; }

    public bool CanRemove => !_isNew;

    public string RemoveConfirmText => string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.RemoveConfirm"], Name.Trim());

    public string RemoveUsageText => string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.RemoveUsage"],
        _rules.RulesUsing(_editingId).Count, _rules.ChainsUsing(_editingId).Count);

    // -- lifecycle -------------------------------------------------------------

    public void BeginAdd()
    {
        // Allocated now, not at save time, so the secrets can be stored against the same id
        // the endpoint will carry.
        _editingId = Guid.NewGuid();
        _isNew = true;
        Name = string.Empty;
        Protocol = ProxyProtocol.Socks5;
        Host = string.Empty;
        Port = "1080";
        Username = string.Empty;
        Password = string.Empty;
        AllowInvalidCertificate = false;
        _passwordAlreadyStored = false;
        _presharedAlreadyStored = false;
        _editingProtocol = ProxyProtocol.Socks5;
        ResetWireGuardFields();
        ResetAgentFields();
        ShowAdvanced = false;
        ShowImport = false;
        IsConfirmingRemove = false;
        ClearTest();
        // Cleared after the fields: resetting them counts as touching them, and a new form
        // must not open with "enter a name" already showing.
        _touched.Clear();
        IsOpen = true;
        RaiseEverything();
    }

    /// <summary>Opens the form ready for a WireGuard exit, straight to the import box.</summary>
    public void BeginAddWireGuard()
    {
        BeginAdd();
        Protocol = ProxyProtocol.WireGuard;
        ShowImport = true;
        _touched.Clear();
        RaiseEverything();
    }

    /// <summary>
    /// Opens the form ready for a Yura agent, straight to the box its connect string goes in.
    /// </summary>
    /// <remarks>
    /// Adding an agent is one paste, which is the whole point of the connect string: four
    /// fields typed by hand include a fingerprint, and a mistyped fingerprint fails in a way
    /// that looks like a network problem.
    /// </remarks>
    public void BeginAddAgent()
    {
        BeginAdd();
        Protocol = ProxyProtocol.YuraAgent;
        ShowImport = true;
        _touched.Clear();
        RaiseEverything();
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
        AllowInvalidCertificate = endpoint.AllowInvalidCertificate;
        _passwordAlreadyStored = endpoint.PasswordRef is not null;
        _editingProtocol = endpoint.Protocol;
        ResetWireGuardFields();
        ResetAgentFields();
        if (endpoint.Agent is { } agent)
        {
            Fingerprint = agent.Fingerprint;
            AgentLabel = agent.AgentLabel ?? string.Empty;
        }

        if (endpoint.WireGuard is { } wg)
        {
            PeerPublicKey = wg.PeerPublicKey;
            Addresses = string.Join(", ", wg.Addresses);
            DnsServers = string.Join(", ", wg.DnsServers);
            AllowedIps = string.Join(", ", wg.AllowedIps);
            Mtu = wg.Mtu?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
            Keepalive = wg.PersistentKeepalive.ToString(CultureInfo.InvariantCulture);
            _presharedAlreadyStored = wg.PresharedKeyRef is not null;
        }

        _touched.Clear();
        ShowAdvanced = false;
        ShowImport = false;
        IsConfirmingRemove = false;
        ClearTest();
        IsOpen = true;
        RaiseEverything();
    }

    private void ResetAgentFields()
    {
        Fingerprint = string.Empty;
        Token = string.Empty;
        AgentLabel = string.Empty;
    }

    private void ResetWireGuardFields()
    {
        PrivateKey = string.Empty;
        PeerPublicKey = string.Empty;
        PresharedKey = string.Empty;
        Addresses = string.Empty;
        DnsServers = string.Empty;
        AllowedIps = "0.0.0.0/0, ::/0";
        Mtu = string.Empty;
        Keepalive = "25";
        ImportText = string.Empty;
        ImportMessage = null;
        _presharedAlreadyStored = false;
    }

    // -- import ------------------------------------------------------------------

    [RelayCommand]
    private void ImportFromText() => ApplyImport(ImportText);

    [RelayCommand]
    private async Task ImportFromFileAsync()
    {
        if (PickConfigurationFile is null)
        {
            return;
        }

        string? text;
        try
        {
            text = await PickConfigurationFile(CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            ImportMessage = e.Message;
            return;
        }

        if (text is not null)
        {
            ApplyImport(text);
        }
    }

    /// <summary>
    /// Fills the form from what was pasted: an agent's connect string, or a wg-quick
    /// configuration. Fields the input does not set are left alone.
    /// </summary>
    /// <remarks>
    /// One box for both, because the user's action is the same one — paste what the other end
    /// gave me — and telling the two apart is a job for the code rather than for them.
    /// </remarks>
    public void ApplyImport(string text)
    {
        if (text.TrimStart().StartsWith(AgentConnection.Scheme, StringComparison.OrdinalIgnoreCase))
        {
            ApplyAgentConnectString(text);
            return;
        }

        var import = WireGuardConfig.Parse(text);
        if (!import.Recognised)
        {
            ImportMessage = Loc.Current["Proxy.WireGuard.ImportNothing"];
            return;
        }

        Protocol = ProxyProtocol.WireGuard;
        if (import.PrivateKey is not null)
        {
            PrivateKey = import.PrivateKey;
        }

        if (import.PeerPublicKey is not null)
        {
            PeerPublicKey = import.PeerPublicKey;
        }

        if (import.PresharedKey is not null)
        {
            PresharedKey = import.PresharedKey;
        }

        if (import.EndpointHost is not null)
        {
            Host = import.EndpointHost;
            Port = (import.EndpointPort ?? 51820).ToString(CultureInfo.InvariantCulture);
        }

        if (import.Addresses.Count > 0)
        {
            Addresses = string.Join(", ", import.Addresses);
        }

        if (import.DnsServers.Count > 0)
        {
            DnsServers = string.Join(", ", import.DnsServers);
        }

        if (import.AllowedIps.Count > 0)
        {
            AllowedIps = string.Join(", ", import.AllowedIps);
        }

        if (import.Mtu is { } mtu)
        {
            Mtu = mtu.ToString(CultureInfo.InvariantCulture);
        }

        if (import.PersistentKeepalive is { } keepalive)
        {
            Keepalive = keepalive.ToString(CultureInfo.InvariantCulture);
        }

        // Everything the file set is worth validating immediately: that is what the user
        // wants to know before saving.
        foreach (var field in new[] { nameof(PrivateKey), nameof(PeerPublicKey), nameof(PresharedKey), nameof(Host), nameof(Port), nameof(Addresses), nameof(DnsServers), nameof(AllowedIps), nameof(Mtu), nameof(Keepalive) })
        {
            _touched.Add(field);
        }

        var missing = new List<string>();
        if (import.PrivateKey is null)
        {
            missing.Add(Loc.Current["Proxy.PrivateKey"]);
        }

        if (import.PeerPublicKey is null)
        {
            missing.Add(Loc.Current["Proxy.PeerPublicKey"]);
        }

        if (import.EndpointHost is null)
        {
            missing.Add(Loc.Current["Proxy.Endpoint"]);
        }

        if (import.Addresses.Count == 0)
        {
            missing.Add(Loc.Current["Proxy.Addresses"]);
        }

        var message = missing.Count == 0
            ? Loc.Current["Proxy.WireGuard.ImportedComplete"]
            : string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.WireGuard.ImportedMissing"], string.Join(", ", missing));
        if (import.Ignored.Count > 0)
        {
            message += " " + string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.WireGuard.Ignored"], string.Join("; ", import.Ignored));
        }

        ImportMessage = message;
        ImportText = string.Empty; // The keys must not linger in a text box after they have been taken.
        RaiseValidation();
        RaiseEverything();
    }

    /// <summary>Fills the form from an agent's connect string, or says what is wrong with it.</summary>
    private void ApplyAgentConnectString(string text)
    {
        if (!AgentConnection.TryParse(text, out var connection, out var problem))
        {
            ImportMessage = problem;
            return;
        }

        Protocol = ProxyProtocol.YuraAgent;
        Host = connection.Host;
        Port = connection.Port.ToString(CultureInfo.InvariantCulture);
        Fingerprint = connection.Fingerprint;
        Token = connection.Token;
        AgentLabel = connection.Name ?? string.Empty;

        // The agent's own label is a sensible name, and the user can change it; an unnamed
        // exit is the one thing this form cannot save.
        if (Name.Trim().Length == 0 && connection.Name is { Length: > 0 } name)
        {
            Name = name;
        }

        foreach (var field in new[] { nameof(Name), nameof(Host), nameof(Port), nameof(Fingerprint), nameof(Token) })
        {
            _touched.Add(field);
        }

        ImportMessage = string.Format(CultureInfo.CurrentCulture, Loc.Current["Proxy.Agent.Imported"],
            connection.Authority, connection.FingerprintDisplay);
        // The token must not linger in a text box after it has been taken out of it.
        ImportText = string.Empty;
        RaiseValidation();
        RaiseEverything();
    }

    // -- actions -----------------------------------------------------------------

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
            var secrets = await CollectSecretsAsync(endpoint, token).ConfigureAwait(true);
            var result = await _daemon.ProbeProxyAsync(endpoint, secrets, token).ConfigureAwait(true);
            if (token.IsCancellationRequested)
            {
                return;
            }

            TestSucceeded = result.Reachable;
            TestResultText = result.Reachable
                ? string.Format(CultureInfo.CurrentCulture,
                    Loc.Current[IsWireGuard ? "Proxy.TestPassedTunnel" : IsAgent ? "Proxy.TestPassedAgent" : "Proxy.TestPassed"],
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

    /// <summary>What was typed, or what is saved when nothing was typed.</summary>
    private async Task<ProxySecrets> CollectSecretsAsync(ProxyEndpoint endpoint, CancellationToken ct)
    {
        var primary = PrimarySecret;
        var password = !string.IsNullOrEmpty(primary)
            ? primary.Trim()
            : await _secrets.GetAsync(endpoint.Id.ToString(), ct).ConfigureAwait(true);
        string? preshared = null;
        if (IsWireGuard)
        {
            preshared = !string.IsNullOrEmpty(PresharedKey)
                ? PresharedKey.Trim()
                : _presharedAlreadyStored && _editingProtocol == ProxyProtocol.WireGuard
                    ? await _secrets.GetAsync(PresharedReference(endpoint.Id), ct).ConfigureAwait(true)
                    : null;
        }

        return new ProxySecrets(password, preshared);
    }

    public static string PresharedReference(Guid id) => $"{id}:psk";

    /// <summary>
    /// The one secret this endpoint has, whatever it is called for its protocol.
    /// </summary>
    private string PrimarySecret => Protocol switch
    {
        ProxyProtocol.WireGuard => PrivateKey,
        ProxyProtocol.YuraAgent => Token,
        _ => Password,
    };

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

        // Secrets go to the secret store, never into the configuration file. An empty box on
        // an existing proxy means "keep what is saved", not "clear it".
        var primary = PrimarySecret;
        var stored = true;
        if (!string.IsNullOrEmpty(primary))
        {
            stored &= await _secrets.SetAsync(endpoint.Id.ToString(), primary.Trim()).ConfigureAwait(true);
        }

        if (IsWireGuard && !string.IsNullOrEmpty(PresharedKey))
        {
            stored &= await _secrets.SetAsync(PresharedReference(endpoint.Id), PresharedKey.Trim()).ConfigureAwait(true);
        }

        if (!stored && _secrets.IsAvailable)
        {
            SecretNotStored?.Invoke(this, string.Format(CultureInfo.CurrentCulture,
                Loc.Current["Proxy.SecretNotStored"], endpoint.Name, SecretStoreName));
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

        PrivateKey = string.Empty;
        PresharedKey = string.Empty;
        Password = string.Empty;
        Token = string.Empty;
        IsOpen = false;
        Saved?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void Cancel()
    {
        _testCts?.Cancel();
        IsConfirmingRemove = false;
        IsOpen = false;
    }

    [RelayCommand]
    private void BeginRemove()
    {
        OnPropertyChanged(nameof(RemoveConfirmText));
        OnPropertyChanged(nameof(RemoveUsageText));
        IsConfirmingRemove = true;
    }

    [RelayCommand]
    private void KeepProxy() => IsConfirmingRemove = false;

    [RelayCommand]
    private async Task ConfirmRemoveAsync()
    {
        if (_isNew)
        {
            return;
        }

        await _secrets.DeleteAsync(_editingId.ToString()).ConfigureAwait(true);
        await _secrets.DeleteAsync(PresharedReference(_editingId)).ConfigureAwait(true);
        _rules.RemoveProxy(_editingId);
        IsConfirmingRemove = false;
        IsOpen = false;
    }

    private ProxyEndpoint Build()
    {
        var wireGuard = IsWireGuard
            ? new WireGuardSettings
            {
                PeerPublicKey = PeerPublicKey.Trim(),
                Addresses = WireGuardConfig.SplitList(Addresses),
                DnsServers = WireGuardConfig.SplitList(DnsServers),
                AllowedIps = WireGuardConfig.SplitList(AllowedIps) is { Count: > 0 } allowed ? allowed : ["0.0.0.0/0", "::/0"],
                Mtu = int.TryParse(Mtu.Trim(), out var mtu) ? mtu : null,
                PersistentKeepalive = int.TryParse(Keepalive.Trim(), out var keep) ? keep : 0,
                PresharedKeyRef = string.IsNullOrEmpty(PresharedKey) && !_presharedAlreadyStored
                    ? null
                    : PresharedReference(_editingId),
            }
            : null;

        var agent = IsAgent
            ? new AgentSettings
            {
                Fingerprint = Fingerprint.Trim(),
                AgentLabel = AgentLabel.Trim() is { Length: > 0 } label ? label : null,
            }
            : null;

        var hasPrimarySecret = Protocol switch
        {
            ProxyProtocol.WireGuard => PrivateKey.Length > 0 || HasStoredPrivateKey,
            ProxyProtocol.YuraAgent => Token.Length > 0 || HasStoredToken,
            _ => Password.Length > 0,
        };
        return new ProxyEndpoint
        {
            Id = _editingId,
            Name = Name.Trim(),
            Protocol = Protocol,
            Host = Host.Trim(),
            Port = ushort.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : (ushort)0,
            Username = !UsesCredentials || string.IsNullOrWhiteSpace(Username) ? null : Username.Trim(),
            AllowInvalidCertificate = IsHttps && AllowInvalidCertificate,
            // Keyed on the id, not the name: renaming a proxy must not orphan its secret.
            PasswordRef = !hasPrimarySecret && !_passwordAlreadyStored ? null : _editingId.ToString(),
            WireGuard = wireGuard,
            Agent = agent,
        };
    }

    private void ClearTest()
    {
        TestResultText = null;
        TestDiagnostics = null;
        TestSucceeded = false;
    }

    private void MarkAllTouched()
    {
        foreach (var field in new[] { nameof(Name), nameof(Host), nameof(Port), nameof(PrivateKey), nameof(PeerPublicKey), nameof(PresharedKey), nameof(Addresses), nameof(DnsServers), nameof(AllowedIps), nameof(Mtu), nameof(Keepalive), nameof(Fingerprint), nameof(Token) })
        {
            _touched.Add(field);
        }

        RaiseValidation();
    }

    private void Touch(string field)
    {
        _touched.Add(field);
        RaiseValidation();
    }

    private void RaiseValidation()
    {
        foreach (var name in new[]
                 {
                     nameof(NameError), nameof(HostError), nameof(PortError), nameof(PrivateKeyError), nameof(PeerPublicKeyError),
                     nameof(PresharedKeyError), nameof(AddressesError), nameof(DnsError), nameof(AllowedIpsError), nameof(MtuError),
                     nameof(KeepaliveError), nameof(HasNameError), nameof(HasHostError), nameof(HasPortError), nameof(HasPrivateKeyError),
                     nameof(HasPeerPublicKeyError), nameof(HasPresharedKeyError), nameof(HasAddressesError), nameof(HasDnsError),
                     nameof(HasAllowedIpsError), nameof(HasMtuError), nameof(HasKeepaliveError), nameof(FingerprintError),
                     nameof(TokenError), nameof(HasFingerprintError), nameof(HasTokenError),
                     nameof(IsValid), nameof(CanSave), nameof(CanTest),
                 })
        {
            OnPropertyChanged(name);
        }
    }

    private void RaiseEverything()
    {
        foreach (var name in new[]
                 {
                     nameof(Title), nameof(IsWireGuard), nameof(IsAgent), nameof(IsHttps), nameof(UsesCredentials), nameof(HostLabel),
                     nameof(HostPlaceholder), nameof(PasswordPlaceholder), nameof(PrivateKeyPlaceholder), nameof(PresharedKeyPlaceholder),
                     nameof(TokenPlaceholder), nameof(SecretStoreDescription), nameof(CanRemove),
                 })
        {
            OnPropertyChanged(name);
        }

        RaiseValidation();
    }

    public void NotifyLanguageChanged() => RaiseEverything();

    partial void OnNameChanged(string value) => Touch(nameof(Name));

    partial void OnHostChanged(string value) => Touch(nameof(Host));

    partial void OnPortChanged(string value) => Touch(nameof(Port));

    partial void OnPrivateKeyChanged(string value) => Touch(nameof(PrivateKey));

    partial void OnPeerPublicKeyChanged(string value) => Touch(nameof(PeerPublicKey));

    partial void OnPresharedKeyChanged(string value) => Touch(nameof(PresharedKey));

    partial void OnAddressesChanged(string value) => Touch(nameof(Addresses));

    partial void OnDnsServersChanged(string value) => Touch(nameof(DnsServers));

    partial void OnAllowedIpsChanged(string value) => Touch(nameof(AllowedIps));

    partial void OnMtuChanged(string value) => Touch(nameof(Mtu));

    partial void OnKeepaliveChanged(string value) => Touch(nameof(Keepalive));

    partial void OnFingerprintChanged(string value) => Touch(nameof(Fingerprint));

    partial void OnTokenChanged(string value) => Touch(nameof(Token));

    partial void OnProtocolChanged(ProxyProtocol value)
    {
        // Default ports follow the protocol until the user overrides them.
        if (!_touched.Contains(nameof(Port)) || Port is "1080" or "8080" or "3128" or "51820" or "7311")
        {
            Port = value switch
            {
                ProxyProtocol.Socks5 => "1080",
                ProxyProtocol.WireGuard => "51820",
                ProxyProtocol.YuraAgent => "7311",
                _ => "8080",
            };
            _touched.Remove(nameof(Port));
        }

        RaiseEverything();
    }

    partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(CanSave));
}

/// <summary>One hop while a chain is being edited.</summary>
public sealed record ChainHopViewModel(ProxyEndpoint Endpoint)
{
    public string Name => Endpoint.Name;

    public string Detail => $"{Endpoint.ProtocolDisplay} · {Endpoint.Authority}";
}

/// <summary>The Add/Edit chain form: a name and an ordered list of hops.</summary>
public sealed partial class ChainEditorViewModel : ObservableObject
{
    private readonly RuleStore _rules;
    private Guid _editingId = Guid.NewGuid();
    private bool _isNew = true;
    private bool _nameTouched;

    public ChainEditorViewModel(RuleStore rules)
    {
        _rules = rules;
        Hops.CollectionChanged += (_, _) => RaiseValidation();
    }

    [ObservableProperty]
    public partial bool IsOpen { get; set; }

    [ObservableProperty]
    public partial string Name { get; set; } = string.Empty;

    public ObservableCollection<ChainHopViewModel> Hops { get; } = [];

    /// <summary>What can be added as the next hop: every proxy, since the same one may appear twice.</summary>
    public ObservableCollection<ProxyEndpoint> AvailableProxies => _rules.Proxies;

    [ObservableProperty]
    public partial ProxyEndpoint? ProxyToAdd { get; set; }

    [ObservableProperty]
    public partial ChainHopViewModel? SelectedHop { get; set; }

    [ObservableProperty]
    public partial bool IsConfirmingRemove { get; set; }

    public string Title => Loc.Current[_isNew ? "Chain.Editor.TitleNew" : "Chain.Editor.TitleEdit"];

    public bool CanRemove => !_isNew;

    public string RemoveConfirmText => string.Format(CultureInfo.CurrentCulture, Loc.Current["Chain.RemoveConfirm"], Name.Trim());

    public string RemoveUsageText => string.Format(CultureInfo.CurrentCulture, Loc.Current["Chain.RemoveUsage"], _rules.RulesUsing(_editingId).Count);

    public string? NameError
    {
        get
        {
            if (!_nameTouched)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(Name))
            {
                return Loc.Current["Chain.Validation.NameRequired"];
            }

            return _rules.Chains.Any(c => c.Id != _editingId && string.Equals(c.Name, Name.Trim(), StringComparison.OrdinalIgnoreCase))
                ? Loc.Current["Chain.Validation.NameDuplicate"]
                : null;
        }
    }

    public bool HasNameError => NameError is not null;

    /// <summary>The structural problem with the hops, if any: none, or an exit not first.</summary>
    public string? HopsError
    {
        get
        {
            if (Hops.Count == 0)
            {
                return Loc.Current["Chain.Validation.NoHops"];
            }

            var endpoints = Hops.Select(h => h.Endpoint).ToList();
            return ProxyChain.Validate(endpoints) is { } invalid ? ChainRowViewModel.Localise(invalid, endpoints) : null;
        }
    }

    public bool HasHopsError => HopsError is not null;

    public bool IsValid =>
        !string.IsNullOrWhiteSpace(Name) &&
        !_rules.Chains.Any(c => c.Id != _editingId && string.Equals(c.Name, Name.Trim(), StringComparison.OrdinalIgnoreCase)) &&
        Hops.Count > 0 && ProxyChain.Validate(Hops.Select(h => h.Endpoint).ToList()) is null;

    public bool CanAddHop => ProxyToAdd is not null;

    public bool CanMoveUp => SelectedHop is not null && Hops.IndexOf(SelectedHop) > 0;

    public bool CanMoveDown => SelectedHop is not null && Hops.IndexOf(SelectedHop) < Hops.Count - 1;

    public bool CanRemoveHop => SelectedHop is not null;

    public void BeginAdd()
    {
        _editingId = Guid.NewGuid();
        _isNew = true;
        _nameTouched = false;
        Name = string.Empty;
        Hops.Clear();
        ProxyToAdd = _rules.Proxies.FirstOrDefault();
        SelectedHop = null;
        IsConfirmingRemove = false;
        IsOpen = true;
        _nameTouched = false;
        RaiseAll();
    }

    public void BeginEdit(ProxyChain chain)
    {
        _editingId = chain.Id;
        _isNew = false;
        Name = chain.Name;
        Hops.Clear();
        foreach (var id in chain.Hops)
        {
            if (_rules.Proxies.FirstOrDefault(p => p.Id == id) is { } endpoint)
            {
                Hops.Add(new ChainHopViewModel(endpoint));
            }
        }

        ProxyToAdd = _rules.Proxies.FirstOrDefault();
        SelectedHop = null;
        IsConfirmingRemove = false;
        IsOpen = true;
        _nameTouched = false;
        RaiseAll();
    }

    [RelayCommand]
    private void AddHop()
    {
        if (ProxyToAdd is { } proxy)
        {
            Hops.Add(new ChainHopViewModel(proxy));
            SelectedHop = Hops[^1];
        }
    }

    [RelayCommand]
    private void RemoveHop()
    {
        if (SelectedHop is { } hop)
        {
            var index = Hops.IndexOf(hop);
            Hops.Remove(hop);
            SelectedHop = Hops.Count == 0 ? null : Hops[Math.Min(index, Hops.Count - 1)];
        }
    }

    [RelayCommand]
    private void MoveHopUp()
    {
        if (SelectedHop is { } hop && Hops.IndexOf(hop) is var index && index > 0)
        {
            Hops.Move(index, index - 1);
            RaiseSelection();
        }
    }

    [RelayCommand]
    private void MoveHopDown()
    {
        if (SelectedHop is { } hop && Hops.IndexOf(hop) is var index && index < Hops.Count - 1)
        {
            Hops.Move(index, index + 1);
            RaiseSelection();
        }
    }

    [RelayCommand]
    private void Save()
    {
        _nameTouched = true;
        RaiseValidation();
        if (!IsValid)
        {
            return;
        }

        _rules.PutChain(new ProxyChain
        {
            Id = _editingId,
            Name = Name.Trim(),
            Hops = Hops.Select(h => h.Endpoint.Id).ToArray(),
        });
        IsOpen = false;
    }

    [RelayCommand]
    private void Cancel()
    {
        IsConfirmingRemove = false;
        IsOpen = false;
    }

    [RelayCommand]
    private void BeginRemove()
    {
        OnPropertyChanged(nameof(RemoveConfirmText));
        OnPropertyChanged(nameof(RemoveUsageText));
        IsConfirmingRemove = true;
    }

    [RelayCommand]
    private void KeepChain() => IsConfirmingRemove = false;

    [RelayCommand]
    private void ConfirmRemove()
    {
        if (!_isNew)
        {
            _rules.RemoveChain(_editingId);
        }

        IsConfirmingRemove = false;
        IsOpen = false;
    }

    partial void OnNameChanged(string value)
    {
        _nameTouched = true;
        RaiseValidation();
    }

    partial void OnProxyToAddChanged(ProxyEndpoint? value) => OnPropertyChanged(nameof(CanAddHop));

    partial void OnSelectedHopChanged(ChainHopViewModel? value) => RaiseSelection();

    private void RaiseSelection()
    {
        OnPropertyChanged(nameof(CanMoveUp));
        OnPropertyChanged(nameof(CanMoveDown));
        OnPropertyChanged(nameof(CanRemoveHop));
    }

    private void RaiseValidation()
    {
        OnPropertyChanged(nameof(NameError));
        OnPropertyChanged(nameof(HasNameError));
        OnPropertyChanged(nameof(HopsError));
        OnPropertyChanged(nameof(HasHopsError));
        OnPropertyChanged(nameof(IsValid));
        RaiseSelection();
    }

    private void RaiseAll()
    {
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(CanRemove));
        OnPropertyChanged(nameof(CanAddHop));
        RaiseValidation();
    }
}
