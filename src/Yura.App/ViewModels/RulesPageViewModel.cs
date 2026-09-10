using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.Core.Net;
using Yura.Core.Rules;

namespace Yura.App.ViewModels;

/// <summary>One row of the ordered rule list.</summary>
public sealed partial class RuleRowViewModel : ObservableObject
{
    public RuleRowViewModel(RoutingRule rule, string? routeName)
    {
        Rule = rule;
        RouteName = routeName;
    }

    [ObservableProperty]
    public partial RoutingRule Rule { get; set; }

    [ObservableProperty]
    public partial string? RouteName { get; set; }

    public Guid Id => Rule.Id;

    public int Order => Rule.Order;

    public string Name => Rule.Name;

    public string OriginDisplay => Rule.Origin switch
    {
        RuleOrigin.ProcessSelection => Loc.Current["Rules.Origin.ProcessSelection"],
        RuleOrigin.GameProfile => Loc.Current["Rules.Origin.GameProfile"],
        RuleOrigin.System => Loc.Current["Rules.Origin.System"],
        _ => Loc.Current["Rules.Origin.Manual"],
    };

    public string LifetimeDisplay => Rule.Lifetime switch
    {
        RuleLifetime.Instance => Loc.Current["Rules.Lifetime.Instance"],
        RuleLifetime.Session => Loc.Current["Rules.Lifetime.Session"],
        _ => Loc.Current["Rules.Lifetime.Persistent"],
    };

    public string ProcessDisplay => RuleDescriber.Process(Rule.Process);

    /// <summary>
    /// Who created the rule and what it matches, in one line under the name.
    /// </summary>
    /// <remarks>
    /// Both facts belong together: the origin explains where the rule came from, and the
    /// selector explains what it does, and neither is worth its own column at the width a
    /// table with an inspector beside it actually has.
    /// </remarks>
    public string MatchSummary => $"{OriginDisplay} · {RuleDescriber.Process(Rule.Process)}";

    public string DestinationDisplay => RuleDescriber.Destination(Rule.Destination);

    public string ActionDisplay => RuleDescriber.Action(Rule.Action, RouteName);

    /// <summary>
    /// Whether the kernel is carrying out this rule, as distinct from the user having asked
    /// for it. Only a daemon reply may set it.
    /// </summary>
    public string StateDisplay => !Rule.Enabled
        ? Loc.Current["Rules.State.Disabled"]
        : Rule.AppliedAtUtc is null
            ? Loc.Current["Rules.State.Pending"]
            : Loc.Current["Rules.State.Active"];

    public bool IsActive => Rule.Enabled && Rule.AppliedAtUtc is not null;

    public bool IsPending => Rule.Enabled && Rule.AppliedAtUtc is null;

    public bool IsDisabled => !Rule.Enabled;

    public bool IsEditable => Rule.IsUserEditable;

    public bool IsProxyAction => Rule.Action is RuleAction.Proxy or RuleAction.Chain;

    public bool IsBlockAction => Rule.Action is RuleAction.Block;

    public void Update(RoutingRule rule, string? routeName)
    {
        Rule = rule;
        RouteName = routeName;
        OnPropertyChanged(nameof(Order));
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(ProcessDisplay));
        OnPropertyChanged(nameof(MatchSummary));
        OnPropertyChanged(nameof(DestinationDisplay));
        OnPropertyChanged(nameof(ActionDisplay));
        OnPropertyChanged(nameof(StateDisplay));
        OnPropertyChanged(nameof(LifetimeDisplay));
        OnPropertyChanged(nameof(OriginDisplay));
        OnPropertyChanged(nameof(IsActive));
        OnPropertyChanged(nameof(IsPending));
        OnPropertyChanged(nameof(IsDisabled));
        OnPropertyChanged(nameof(IsProxyAction));
        OnPropertyChanged(nameof(IsBlockAction));
    }
}

/// <summary>
/// The Rules page: the one ordered list both workflows share.
/// </summary>
/// <remarks>
/// Every rule in the product appears here, whatever created it, because the precedence
/// question — "why is my game profile not winning?" — can only be answered by seeing the
/// single list in evaluation order. Reordering is offered as buttons rather than drag and
/// drop so it is reachable from the keyboard.
/// </remarks>
public sealed partial class RulesPageViewModel : ObservableObject
{
    private readonly RuleStore _rules;
    private readonly IDaemonClient _daemon;

    public RulesPageViewModel(RuleStore rules, IDaemonClient daemon)
    {
        _rules = rules;
        _daemon = daemon;
        _rules.Changed += (_, _) => Reload();
        Editor = new RuleEditorViewModel(rules);
        Editor.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(RuleEditorViewModel.IsOpen))
            {
                OnPropertyChanged(nameof(ShowOverlayInspector));
            }
        };
        Reload();
    }

    public ObservableCollection<RuleRowViewModel> Rules { get; } = [];

    public RuleEditorViewModel Editor { get; }

    [ObservableProperty]
    public partial RuleRowViewModel? SelectedRule { get; set; }

    [ObservableProperty]
    public partial string? StatusMessage { get; set; }

    [ObservableProperty]
    public partial string? ErrorMessage { get; set; }

    [ObservableProperty]
    public partial string? ErrorDiagnostics { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    /// <summary>
    /// True when the window is too narrow to dock the inspector beside the table.
    /// </summary>
    /// <remarks>
    /// Set by the view from its own bounds rather than the window's, so the threshold stays
    /// correct whatever the navigation sidebar's width happens to be.
    /// </remarks>
    [ObservableProperty]
    public partial bool IsCompact { get; set; }

    /// <summary>The inspector floats only when it is needed and cannot be docked.</summary>
    public bool ShowOverlayInspector => IsCompact && (HasSelection || Editor.IsOpen);

    public bool HasSelection => SelectedRule is not null;

    public bool IsEmpty => Rules.Count == 0;

    public bool CanUndo => _rules.PendingUndo is not null;

    public string? UndoDescription => _rules.PendingUndo is { } undo
        ? string.Format(CultureInfo.CurrentCulture, Loc.Current["Rules.UndoAvailable"], undo.Description)
        : null;

    public string CountSummary => string.Format(
        CultureInfo.CurrentCulture, Loc.Current["Rules.Count"], Rules.Count);

    private void Reload()
    {
        var ordered = _rules.Rules;
        var selectedId = SelectedRule?.Id;

        for (var i = Rules.Count - 1; i >= 0; i--)
        {
            if (ordered.All(r => r.Id != Rules[i].Id))
            {
                Rules.RemoveAt(i);
            }
        }

        for (var i = 0; i < ordered.Count; i++)
        {
            var rule = ordered[i];
            var routeName = rule.Action switch
            {
                RuleAction.Proxy p => _rules.RouteName(p.EndpointId),
                RuleAction.Chain c => _rules.RouteName(c.ChainId),
                _ => null,
            };

            var existing = Rules.FirstOrDefault(r => r.Id == rule.Id);
            if (existing is null)
            {
                Rules.Insert(Math.Min(i, Rules.Count), new RuleRowViewModel(rule, routeName));
                continue;
            }

            existing.Update(rule, routeName);
            var at = Rules.IndexOf(existing);
            if (at != i)
            {
                Rules.Move(at, i);
            }
        }

        if (selectedId is { } id)
        {
            SelectedRule = Rules.FirstOrDefault(r => r.Id == id);
        }

        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(CountSummary));
        OnPropertyChanged(nameof(CanUndo));
        OnPropertyChanged(nameof(UndoDescription));
    }

    partial void OnIsCompactChanged(bool value) => OnPropertyChanged(nameof(ShowOverlayInspector));

    partial void OnSelectedRuleChanged(RuleRowViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(ShowOverlayInspector));
        StatusMessage = null;
        ErrorMessage = null;
    }

    // -- ordering --------------------------------------------------------------

    [RelayCommand]
    private Task MoveEarlierAsync() => MoveAsync(earlier: true);

    [RelayCommand]
    private Task MoveLaterAsync() => MoveAsync(earlier: false);

    private async Task MoveAsync(bool earlier)
    {
        if (SelectedRule is not { } row || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            // Both rules that swapped have to be reapplied: their order is what the kernel
            // ruleset encodes, so a reorder the daemon has not accepted is not in effect.
            var changed = _rules.Move(row.Id, earlier);
            foreach (var rule in changed)
            {
                await ApplyAsync(rule).ConfigureAwait(true);
            }

            SelectedRule = Rules.FirstOrDefault(r => r.Id == row.Id);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task ToggleEnabledAsync()
    {
        if (SelectedRule is not { } row || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var updated = _rules.SetEnabled(row.Id, !row.Rule.Enabled);
            if (updated is null)
            {
                return;
            }

            if (updated.Enabled)
            {
                await ApplyAsync(updated).ConfigureAwait(true);
            }
            else
            {
                // A disabled rule must leave the kernel, or it would still be routing.
                var result = await _daemon.RemoveRuleAsync(updated.Id).ConfigureAwait(true);
                Report(result, Loc.Current["Rules.Disabled"]);
            }
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(CanUndo));
            OnPropertyChanged(nameof(UndoDescription));
        }
    }

    [RelayCommand]
    private async Task RemoveAsync()
    {
        if (SelectedRule is not { } row || IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var result = await _daemon.RemoveRuleAsync(row.Id).ConfigureAwait(true);
            if (result.Succeeded)
            {
                _rules.Remove(row.Id);
                StatusMessage = Loc.Current["Rules.Removed"];
            }
            else
            {
                Report(result, null);
            }
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(CanUndo));
            OnPropertyChanged(nameof(UndoDescription));
        }
    }

    /// <summary>Puts back the previous version of the last edited rule, in the kernel too.</summary>
    [RelayCommand]
    private async Task UndoAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var undo = _rules.Undo();
            if (undo is null)
            {
                return;
            }

            if (undo.Current is not null && undo.Previous is null)
            {
                await _daemon.RemoveRuleAsync(undo.Current.Id).ConfigureAwait(true);
            }

            if (undo.Previous is not null)
            {
                await ApplyAsync(undo.Previous).ConfigureAwait(true);
            }

            StatusMessage = Loc.Current["Rules.UndoDone"];
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(CanUndo));
            OnPropertyChanged(nameof(UndoDescription));
        }
    }

    // -- editing ---------------------------------------------------------------

    [RelayCommand]
    private void AddRule() => Editor.BeginAdd();

    [RelayCommand]
    private void EditRule()
    {
        if (SelectedRule is { IsEditable: true } row)
        {
            Editor.BeginEdit(row.Rule);
        }
    }

    /// <summary>Opens the editor on a rule drafted elsewhere, e.g. from a connection.</summary>
    public void EditDraft(RoutingRule draft) => Editor.BeginEdit(draft, isNew: true);

    [RelayCommand]
    private async Task SaveEditAsync()
    {
        if (IsBusy)
        {
            return;
        }

        if (!Editor.TryBuild(out var rule, out var problem))
        {
            Editor.ValidationMessage = problem;
            return;
        }

        Editor.ValidationMessage = null;

        IsBusy = true;
        try
        {
            _rules.Replace(rule);
            var result = await ApplyAsync(rule).ConfigureAwait(true);
            if (result.Succeeded)
            {
                Editor.Close();
                SelectedRule = Rules.FirstOrDefault(r => r.Id == rule.Id);
            }
        }
        finally
        {
            IsBusy = false;
            OnPropertyChanged(nameof(CanUndo));
            OnPropertyChanged(nameof(UndoDescription));
        }
    }

    private async Task<RuleApplyResult> ApplyAsync(RoutingRule rule)
    {
        var result = await _daemon.ApplyRuleAsync(rule).ConfigureAwait(true);
        if (result.Succeeded)
        {
            _rules.MarkApplied(rule.Id, result.ConfirmedAtUtc);
            StatusMessage = string.Format(CultureInfo.CurrentCulture, Loc.Current["Rules.Applied"], rule.Name);
            ErrorMessage = null;
            ErrorDiagnostics = null;
        }
        else
        {
            Report(result, null);
        }

        return result;
    }

    private void Report(RuleApplyResult result, string? success)
    {
        if (result.Succeeded)
        {
            StatusMessage = success;
            ErrorMessage = null;
            ErrorDiagnostics = null;
            return;
        }

        ErrorMessage = result.FailureReason;
        ErrorDiagnostics = result.Diagnostics;
    }
}

/// <summary>
/// The rule editor: process side, destination side, action.
/// </summary>
/// <remarks>
/// Text entry for destinations rather than a builder, because the values are exactly the ones
/// people already write in firewall rules — <c>*.example.com</c>, <c>10.0.0.0/8</c>,
/// <c>27000-27100</c> — and validation explains any part it cannot read.
/// </remarks>
public sealed partial class RuleEditorViewModel : ObservableObject
{
    private readonly RuleStore _rules;
    private Guid _editingId = Guid.NewGuid();
    private RoutingRule? _original;

    public RuleEditorViewModel(RuleStore rules) => _rules = rules;

    [ObservableProperty]
    public partial bool IsOpen { get; set; }

    public string Title => _original is null ? Loc.Current["Rules.Editor.TitleNew"] : Loc.Current["Rules.Editor.TitleEdit"];

    [ObservableProperty]
    public partial string Name { get; set; } = string.Empty;

    [ObservableProperty]
    public partial ProcessSelectorKind ProcessKind { get; set; } = ProcessSelectorKind.ProcessName;

    [ObservableProperty]
    public partial string ProcessValue { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Hosts { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Networks { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Ports { get; set; } = string.Empty;

    [ObservableProperty]
    public partial TransportFilter Protocol { get; set; } = TransportFilter.Any;

    [ObservableProperty]
    public partial RuleActionChoice Action { get; set; } = RuleActionChoice.Direct;

    [ObservableProperty]
    public partial RouteOption? Route { get; set; }

    [ObservableProperty]
    public partial bool IncludeChildren { get; set; }

    [ObservableProperty]
    public partial string? ValidationMessage { get; set; }

    public IReadOnlyList<ProcessSelectorKind> ProcessKinds { get; } =
        [ProcessSelectorKind.ProcessName, ProcessSelectorKind.ExecutablePath, ProcessSelectorKind.Any];

    public IReadOnlyList<TransportFilter> Protocols { get; } =
        [TransportFilter.Any, TransportFilter.Tcp, TransportFilter.Udp];

    public IReadOnlyList<RuleActionChoice> Actions { get; } =
        [RuleActionChoice.Direct, RuleActionChoice.Block, RuleActionChoice.Proxy];

    /// <summary>Proxies and chains together: both are things a rule can route to.</summary>
    public System.Collections.ObjectModel.ObservableCollection<RouteOption> Routes => _rules.Routes;

    public bool NeedsRoute => Action == RuleActionChoice.Proxy;

    public bool NeedsProcessValue => ProcessKind != ProcessSelectorKind.Any;

    public string ProcessValueLabel => ProcessKind switch
    {
        ProcessSelectorKind.ExecutablePath => Loc.Current["Rules.Editor.ExecutablePath"],
        _ => Loc.Current["Rules.Editor.ProcessName"],
    };

    public void BeginAdd()
    {
        _editingId = Guid.NewGuid();
        _original = null;
        Name = string.Empty;
        ProcessKind = ProcessSelectorKind.ProcessName;
        ProcessValue = string.Empty;
        Hosts = Networks = Ports = string.Empty;
        Protocol = TransportFilter.Any;
        Action = RuleActionChoice.Direct;
        Route = null;
        IncludeChildren = false;
        ValidationMessage = null;
        IsOpen = true;
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Routes));
    }

    public void BeginEdit(RoutingRule rule, bool isNew = false)
    {
        _editingId = rule.Id;
        _original = isNew ? null : rule;
        Name = rule.Name;
        ProcessKind = rule.Process.Kind == ProcessSelectorKind.Instance
            ? ProcessSelectorKind.ExecutablePath
            : rule.Process.Kind;
        ProcessValue = rule.Process.Kind switch
        {
            ProcessSelectorKind.ExecutablePath => rule.Process.ExecutablePath ?? string.Empty,
            ProcessSelectorKind.ProcessName => rule.Process.ProcessName ?? string.Empty,
            _ => string.Empty,
        };
        Hosts = string.Join(", ", rule.Destination.Hosts);
        Networks = string.Join(", ", rule.Destination.Networks);
        Ports = string.Join(", ", rule.Destination.Ports);
        Protocol = rule.Destination.Protocol;
        Action = rule.Action switch
        {
            RuleAction.Block => RuleActionChoice.Block,
            RuleAction.Proxy or RuleAction.Chain => RuleActionChoice.Proxy,
            _ => RuleActionChoice.Direct,
        };
        Route = rule.Action switch
        {
            RuleAction.Proxy p => _rules.FindRoute(p.EndpointId),
            RuleAction.Chain c => _rules.FindRoute(c.ChainId),
            _ => null,
        };
        IncludeChildren = rule.Process.Descendants != DescendantPolicy.Exclude;
        ValidationMessage = null;
        IsOpen = true;
        OnPropertyChanged(nameof(Title));
        OnPropertyChanged(nameof(Routes));
    }

    [RelayCommand]
    public void Close() => IsOpen = false;

    /// <summary>
    /// Builds the rule, or explains the first thing that cannot be read.
    /// </summary>
    /// <remarks>
    /// Parsing failures name the offending value rather than saying "invalid input", because
    /// a rule list is long and the user needs to know which field to fix.
    /// </remarks>
    public bool TryBuild(out RoutingRule rule, out string? problem)
    {
        rule = null!;
        problem = null;

        if (string.IsNullOrWhiteSpace(Name))
        {
            problem = Loc.Current["Rules.Editor.NameRequired"];
            return false;
        }

        if (NeedsProcessValue && string.IsNullOrWhiteSpace(ProcessValue))
        {
            problem = Loc.Current["Rules.Editor.ProcessRequired"];
            return false;
        }

        var hosts = new List<HostPattern>();
        foreach (var value in Split(Hosts))
        {
            hosts.Add(Yura.Core.Ipc.RuleDto.ParseHost(value));
        }

        var networks = new List<System.Net.IPNetwork>();
        foreach (var value in Split(Networks))
        {
            try
            {
                networks.Add(Yura.Core.Ipc.RuleDto.ParseNetwork(value));
            }
            catch (InvalidDataException)
            {
                problem = string.Format(CultureInfo.CurrentCulture, Loc.Current["Rules.Editor.BadNetwork"], value);
                return false;
            }
        }

        var ports = new List<PortRange>();
        foreach (var value in Split(Ports))
        {
            if (!PortRange.TryParse(value, out var range))
            {
                problem = string.Format(CultureInfo.CurrentCulture, Loc.Current["Rules.Editor.BadPort"], value);
                return false;
            }

            ports.Add(range);
        }

        RuleAction action;
        switch (Action)
        {
            case RuleActionChoice.Block:
                action = RuleAction.Block.Instance;
                break;
            case RuleActionChoice.Proxy:
                if (Route is not { } chosen)
                {
                    problem = Loc.Current["Rules.Editor.RouteRequired"];
                    return false;
                }

                action = chosen.ToAction();
                break;
            default:
                action = RuleAction.Direct.Instance;
                break;
        }

        // A rule with neither a process nor a destination would capture the whole machine; the
        // daemon refuses it, so saying so here saves a round trip and explains it better.
        var unconstrainedDestination = hosts.Count == 0 && networks.Count == 0 && ports.Count == 0 &&
                                       Protocol == TransportFilter.Any;
        if (ProcessKind == ProcessSelectorKind.Any && unconstrainedDestination)
        {
            problem = Loc.Current["Rules.Editor.TooBroad"];
            return false;
        }

        if (ProcessKind == ProcessSelectorKind.Any && hosts.Count > 0)
        {
            problem = Loc.Current["Rules.Editor.HostNeedsProcess"];
            return false;
        }

        rule = new RoutingRule
        {
            Id = _editingId,
            Order = _original?.Order ?? _rules.NextOrder(RuleOrigin.Manual),
            Name = Name.Trim(),
            Enabled = _original?.Enabled ?? true,
            Origin = _original?.Origin ?? RuleOrigin.Manual,
            Lifetime = RuleLifetime.Persistent,
            CreatedAtUtc = _original?.CreatedAtUtc ?? DateTimeOffset.UtcNow,
            Process = new ProcessSelector
            {
                Kind = ProcessKind,
                ExecutablePath = ProcessKind == ProcessSelectorKind.ExecutablePath ? ProcessValue.Trim() : null,
                ProcessName = ProcessKind == ProcessSelectorKind.ProcessName ? ProcessValue.Trim() : null,
                Descendants = IncludeChildren ? DescendantPolicy.IncludeFuture : DescendantPolicy.Exclude,
            },
            Destination = new DestinationSelector
            {
                Hosts = hosts,
                Networks = networks,
                Ports = ports,
                Protocol = Protocol,
            },
            Action = action,
        };

        return true;
    }

    private static IEnumerable<string> Split(string text) =>
        text.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    partial void OnActionChanged(RuleActionChoice value) => OnPropertyChanged(nameof(NeedsRoute));

    partial void OnProcessKindChanged(ProcessSelectorKind value)
    {
        OnPropertyChanged(nameof(NeedsProcessValue));
        OnPropertyChanged(nameof(ProcessValueLabel));
    }
}

/// <summary>The actions the editor offers. Chains appear in the route list, not as a separate action.</summary>
public enum RuleActionChoice
{
    Direct,
    Block,
    Proxy,
}
