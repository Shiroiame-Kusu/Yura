using CommunityToolkit.Mvvm.ComponentModel;
using Yura.App.Localization;
using Yura.Core.Processes;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>How a process's current routing policy should be presented.</summary>
public enum PolicyKind
{
    Direct,
    Proxied,
    Blocked,
    Pending,
}

/// <summary>One row of the Processes table.</summary>
/// <remarks>
/// Rows are long-lived and updated in place. Rebuilding them on every refresh would drop
/// the selection, move the keyboard focus and shuffle rows under the pointer, all of which
/// the specification rules out for a list that refreshes on a timer.
/// </remarks>
public sealed partial class ProcessRowViewModel : ObservableObject
{
    public ProcessRowViewModel(ProcessSnapshot snapshot)
    {
        Snapshot = snapshot;
        Key = MakeKey(snapshot.Identity);
    }

    /// <summary>Stable identity key: survives refreshes, never collides across pid reuse.</summary>
    public string Key { get; }

    public static string MakeKey(ProcessIdentity identity) => $"{identity.Pid}:{identity.StartTicks}";

    [ObservableProperty]
    public partial ProcessSnapshot Snapshot { get; set; }

    [ObservableProperty]
    public partial PolicyKind Policy { get; set; } = PolicyKind.Direct;

    /// <summary>Name of the proxy or rule driving this row's policy, when there is one.</summary>
    [ObservableProperty]
    public partial string? PolicyDetail { get; set; }

    /// <summary>True while a rule change has been sent but not yet confirmed by the daemon.</summary>
    [ObservableProperty]
    public partial bool IsPending { get; set; }

    public int Pid => Snapshot.Identity.Pid;

    public string DisplayName => Snapshot.DisplayName;

    public string UserName => Snapshot.UserName;

    public int ParentPid => Snapshot.ParentPid;

    /// <summary>
    /// The executable path, or an explanation of why it is missing. Never blank: a blank
    /// cell would be indistinguishable from a path we simply failed to render.
    /// </summary>
    public string PathDisplay => Snapshot.ExecutablePathState switch
    {
        ExecutablePathState.Resolved => Snapshot.ExecutablePath ?? string.Empty,
        ExecutablePathState.Deleted => Snapshot.ExecutablePath ?? string.Empty,
        ExecutablePathState.PermissionDenied => Loc.Current["Processes.PathDenied"],
        _ => Loc.Current["Common.Unavailable"],
    };

    public bool PathIsUnavailable => Snapshot.ExecutablePathState
        is ExecutablePathState.PermissionDenied or ExecutablePathState.None;

    public bool ExecutableWasReplaced => Snapshot.ExecutablePathState == ExecutablePathState.Deleted;

    /// <summary>Connection count, or a dash when the daemon could not supply one.</summary>
    public string ConnectionCountDisplay =>
        Snapshot.ConnectionCount is { } count ? count.ToString() : "—";

    public bool IsWine => Snapshot.Wine is not null;

    /// <summary>
    /// The icon shown beside the process name.
    /// </summary>
    /// <remarks>
    /// A category glyph, not the application's real icon: resolving that means matching the
    /// executable against installed <c>.desktop</c> entries and loading themed icons, which
    /// is a separate piece of work. A consistent category glyph is honest in the meantime;
    /// a wrong application icon would not be.
    /// </remarks>
    public FluentIcons.Common.Symbol Icon => Snapshot switch
    {
        { Wine: not null } => FluentIcons.Common.Symbol.WindowApps,
        { ExecutablePathState: ExecutablePathState.PermissionDenied } => FluentIcons.Common.Symbol.LockClosed,
        { ExecutablePathState: ExecutablePathState.Deleted } => FluentIcons.Common.Symbol.DocumentDismiss,
        _ => FluentIcons.Common.Symbol.Window,
    };

    // Avalonia cannot bind the Classes collection wholesale, so each badge variant is
    // exposed as its own boolean and bound with Classes.<Name>.
    public bool IsProxiedPolicy => Policy == PolicyKind.Proxied;

    public bool IsBlockedPolicy => Policy == PolicyKind.Blocked;

    public bool IsPendingPolicy => Policy == PolicyKind.Pending;

    public string PolicyDisplay => Policy switch
    {
        PolicyKind.Proxied => PolicyDetail ?? Loc.Current["Processes.Policy.Proxied"],
        PolicyKind.Blocked => Loc.Current["Processes.Policy.Blocked"],
        PolicyKind.Pending => Loc.Current["Processes.Policy.PendingApply"],
        _ => Loc.Current["Processes.Policy.Direct"],
    };

    /// <summary>Applies a fresh snapshot without disturbing the row's identity.</summary>
    public void Update(ProcessSnapshot snapshot)
    {
        var connectionsChanged = Snapshot.ConnectionCount != snapshot.ConnectionCount;
        var pathChanged = Snapshot.ExecutablePath != snapshot.ExecutablePath ||
                          Snapshot.ExecutablePathState != snapshot.ExecutablePathState;

        // An exec keeps the pid and the start time — the row's identity — and replaces the
        // program: the name and the Wine context change under the same row.
        var imageChanged = pathChanged || Snapshot.DisplayName != snapshot.DisplayName ||
                           Snapshot.Wine != snapshot.Wine;

        Snapshot = snapshot;

        // Only the properties that can actually change between refreshes are re-raised,
        // so a per-second refresh does not invalidate every binding on every row.
        if (connectionsChanged)
        {
            OnPropertyChanged(nameof(ConnectionCountDisplay));
        }

        if (pathChanged)
        {
            OnPropertyChanged(nameof(PathDisplay));
            OnPropertyChanged(nameof(PathIsUnavailable));
            OnPropertyChanged(nameof(ExecutableWasReplaced));
        }

        if (imageChanged)
        {
            OnPropertyChanged(nameof(DisplayName));
            OnPropertyChanged(nameof(IsWine));
            OnPropertyChanged(nameof(Icon));
        }
    }

    /// <summary>Re-renders every localised string after a language change.</summary>
    public void NotifyLanguageChanged() => OnPropertyChanged(string.Empty);

    partial void OnPolicyChanged(PolicyKind value)
    {
        OnPropertyChanged(nameof(PolicyDisplay));
        OnPropertyChanged(nameof(IsProxiedPolicy));
        OnPropertyChanged(nameof(IsBlockedPolicy));
        OnPropertyChanged(nameof(IsPendingPolicy));
    }

    partial void OnPolicyDetailChanged(string? value) => OnPropertyChanged(nameof(PolicyDisplay));

    /// <summary>True when the row matches a free-text filter across every visible column.</summary>
    public bool MatchesFilter(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return true;
        }

        return DisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               Snapshot.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               UserName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
               Pid.ToString().Contains(filter, StringComparison.Ordinal) ||
               (Snapshot.ExecutablePath?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (Snapshot.Wine?.TargetExecutable?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false);
    }
}
