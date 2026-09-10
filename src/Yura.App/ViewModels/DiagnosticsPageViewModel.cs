using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;

namespace Yura.App.ViewModels;

/// <summary>One WireGuard exit as the daemon reports it.</summary>
public sealed record TunnelRow(TunnelStatus Status)
{
    public string Name => Status.Name;

    public bool Up => Status.Up && Status.LatestHandshakeUtc is not null;

    public string StateDisplay => Status.Up
        ? Loc.Current[Status.LatestHandshakeUtc is null ? "Proxy.Tunnel.NoHandshake" : "Diagnostics.Ok"]
        : Loc.Current["Diagnostics.Failed"];

    /// <summary>Interface, peer, last handshake and transfer, in one line.</summary>
    public string Summary => Status.Up
        ? string.Create(CultureInfo.InvariantCulture,
            $"{Status.Interface} → {Status.Endpoint}; handshake {(Status.LatestHandshakeUtc is { } h ? h.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture) : "never")}; rx {Status.RxBytes} B, tx {Status.TxBytes} B")
        : Status.Failure ?? Loc.Current["Common.Unknown"];
}

/// <summary>One environment check the daemon ran, with its outcome.</summary>
public sealed record CheckRow(string Name, bool Passed, string? Detail)
{
    public string StateDisplay => Passed ? Loc.Current["Diagnostics.Ok"] : Loc.Current["Diagnostics.Failed"];
}

/// <summary>
/// The Diagnostics page: what the daemon found on this machine, and what it installed.
/// </summary>
/// <remarks>
/// Every value here comes from the daemon rather than being re-derived in the app, so the
/// page cannot disagree with reality. The point of it is recovery: when routing is not
/// working, this is where the reason is — a missing kernel module, a process watcher that
/// could not start, an nftables table that is not what you expect.
/// </remarks>
public sealed partial class DiagnosticsPageViewModel : ObservableObject, IDisposable
{
    private readonly IDaemonClient _daemon;
    private readonly ConfigStore _config;
    private readonly ISecretStore _secrets;
    private readonly DispatcherTimer _timer;
    private bool _inFlight;

    public DiagnosticsPageViewModel(IDaemonClient daemon, ConfigStore config, ISecretStore secrets)
    {
        _daemon = daemon;
        _config = config;
        _secrets = secrets;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += (_, _) => _ = RefreshAsync();
    }

    public ObservableCollection<CheckRow> Checks { get; } = [];

    public ObservableCollection<TunnelRow> Tunnels { get; } = [];

    public bool HasTunnels => Tunnels.Count > 0;

    public ObservableCollection<string> Log { get; } = [];

    [ObservableProperty]
    public partial DaemonStatus? Status { get; set; }

    [ObservableProperty]
    public partial string? Ruleset { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    public bool IsDaemonConnected => _daemon.State == DaemonState.Connected;

    public string? UnavailableReason => _daemon.UnavailableReason;

    // -- app-side facts, which are true with or without a daemon ----------------

    public string ConfigPath => _config.FilePath;

    public string SecretStore => _secrets.IsAvailable
        ? _secrets.Description
        : Loc.Current["Diagnostics.SecretsInMemory"];

    public string AppVersion => typeof(DiagnosticsPageViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.2.0";

    public string DaemonVersion => Status?.Version ?? Loc.Current["Common.Unavailable"];

    public string UptimeDisplay => Status is { } status
        ? status.Uptime.TotalHours >= 1
            ? string.Create(CultureInfo.CurrentCulture, $"{(int)status.Uptime.TotalHours}h {status.Uptime.Minutes}m")
            : string.Create(CultureInfo.CurrentCulture, $"{status.Uptime.Minutes}m {status.Uptime.Seconds}s")
        : Loc.Current["Common.Unavailable"];

    public string ProcessWatcherDisplay => Status?.ProcessWatcher ?? Loc.Current["Common.Unavailable"];

    /// <summary>
    /// True when process tracking is event-driven. When it is not, short-lived processes can
    /// keep their original route, which is a real behavioural difference and is stated.
    /// </summary>
    public bool IsWatcherEventDriven =>
        Status?.ProcessWatcher?.StartsWith("netlink", StringComparison.Ordinal) == true;

    public string KernelDisplay => Status?.KernelRelease ?? Loc.Current["Common.Unavailable"];

    public string NftDisplay => Status?.NftVersion ?? Loc.Current["Common.Unavailable"];

    public string ActiveRulesDisplay => Status?.ActiveRules.ToString(CultureInfo.CurrentCulture) ?? "—";

    public string ActiveFlowsDisplay => Status?.ActiveFlows.ToString(CultureInfo.CurrentCulture) ?? "—";

    public string ActiveGroupsDisplay => Status?.ActiveGroups.ToString(CultureInfo.CurrentCulture) ?? "—";

    public string SocketDisplay => Status?.SocketPath ?? Loc.Current["Common.Unavailable"];

    public string AllowedUidsDisplay => Status is { AllowedUids.Count: > 0 }
        ? string.Join(", ", Status.AllowedUids)
        : Loc.Current["Common.Unavailable"];

    public bool HasFailedChecks => Checks.Any(c => !c.Passed);

    public void Activate()
    {
        _timer.Start();
        _ = RefreshAsync();
    }

    public void Deactivate() => _timer.Stop();

    [RelayCommand]
    public async Task RefreshAsync()
    {
        if (_inFlight)
        {
            return;
        }

        _inFlight = true;
        IsBusy = true;
        try
        {
            Status = await _daemon.GetStatusAsync().ConfigureAwait(true);

            Checks.Clear();
            foreach (var check in Status?.Checks ?? [])
            {
                Checks.Add(new CheckRow(check.Name, check.Passed, check.Detail));
            }

            Tunnels.Clear();
            foreach (var tunnel in Status?.Tunnels ?? [])
            {
                Tunnels.Add(new TunnelRow(tunnel));
            }

            var log = await _daemon.GetLogAsync(200).ConfigureAwait(true);
            Log.Clear();
            foreach (var line in log)
            {
                Log.Add(line);
            }

            RaiseAll();
        }
        finally
        {
            _inFlight = false;
            IsBusy = false;
        }
    }

    /// <summary>Fetches the installed ruleset on demand: it is long, and rarely what you need.</summary>
    [RelayCommand]
    private async Task LoadRulesetAsync()
    {
        IsBusy = true;
        try
        {
            Ruleset = await _daemon.DumpRulesetAsync().ConfigureAwait(true)
                      ?? Loc.Current["Diagnostics.RulesetUnavailable"];
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Everything an operator would otherwise have to gather by hand, as one block of text.
    /// </summary>
    /// <remarks>
    /// Deliberately assembled here rather than in a support tool: a bug report about routing
    /// is unactionable without the kernel version, the checks and the installed ruleset, and
    /// asking a user to run four commands loses most of them.
    /// </remarks>
    public string BuildReport()
    {
        var report = new System.Text.StringBuilder();
        report.AppendLine("# Yura diagnostics");
        report.AppendLine(CultureInfo.InvariantCulture, $"app        : {AppVersion}");
        report.AppendLine(CultureInfo.InvariantCulture, $"daemon     : {DaemonVersion}");
        report.AppendLine(CultureInfo.InvariantCulture, $"kernel     : {KernelDisplay}");
        report.AppendLine(CultureInfo.InvariantCulture, $"nftables   : {NftDisplay}");
        report.AppendLine(CultureInfo.InvariantCulture, $"watcher    : {ProcessWatcherDisplay}");
        report.AppendLine(CultureInfo.InvariantCulture, $"dns policy : {Status?.DnsPolicy}");
        report.AppendLine(CultureInfo.InvariantCulture, $"config     : {ConfigPath}");
        report.AppendLine(CultureInfo.InvariantCulture, $"secrets    : {SecretStore}");
        report.AppendLine(CultureInfo.InvariantCulture, $"rules/flows/groups: {ActiveRulesDisplay}/{ActiveFlowsDisplay}/{ActiveGroupsDisplay}");
        report.AppendLine();
        report.AppendLine("## Checks");
        foreach (var check in Checks)
        {
            report.AppendLine(CultureInfo.InvariantCulture,
                $"[{(check.Passed ? "ok" : "FAILED")}] {check.Name}{(check.Detail is null ? string.Empty : ": " + check.Detail)}");
        }

        if (Tunnels.Count > 0)
        {
            report.AppendLine();
            report.AppendLine("## WireGuard exits");
            foreach (var tunnel in Tunnels)
            {
                report.AppendLine(CultureInfo.InvariantCulture, $"{tunnel.Name}: {tunnel.Summary}");
            }
        }

        if (Ruleset is { Length: > 0 })
        {
            report.AppendLine();
            report.AppendLine("## Installed ruleset");
            report.AppendLine(Ruleset);
        }

        if (Log.Count > 0)
        {
            report.AppendLine();
            report.AppendLine("## Recent daemon log");
            foreach (var line in Log)
            {
                report.AppendLine(line);
            }
        }

        return report.ToString();
    }

    private void RaiseAll()
    {
        OnPropertyChanged(nameof(IsDaemonConnected));
        OnPropertyChanged(nameof(UnavailableReason));
        OnPropertyChanged(nameof(DaemonVersion));
        OnPropertyChanged(nameof(UptimeDisplay));
        OnPropertyChanged(nameof(ProcessWatcherDisplay));
        OnPropertyChanged(nameof(IsWatcherEventDriven));
        OnPropertyChanged(nameof(KernelDisplay));
        OnPropertyChanged(nameof(NftDisplay));
        OnPropertyChanged(nameof(ActiveRulesDisplay));
        OnPropertyChanged(nameof(ActiveFlowsDisplay));
        OnPropertyChanged(nameof(ActiveGroupsDisplay));
        OnPropertyChanged(nameof(SocketDisplay));
        OnPropertyChanged(nameof(AllowedUidsDisplay));
        OnPropertyChanged(nameof(HasFailedChecks));
        OnPropertyChanged(nameof(HasTunnels));
    }

    public void Dispose() => _timer.Stop();
}
