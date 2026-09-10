using System.Globalization;
using Yura.Core.Rules;

namespace Yura.App.Localization;

/// <summary>
/// Renders a rule's parts in the user's language.
/// </summary>
/// <remarks>
/// <see cref="ProcessSelector.Describe"/> and <see cref="DestinationSelector.Describe"/> live
/// in the domain and are deliberately English: they go into daemon logs, diagnostics and
/// match explanations that an operator reads. Anything shown in the interface goes through
/// here instead, which is what stops "Any destination" appearing in a Chinese table — a
/// defect only visible by actually rendering the other language.
/// </remarks>
internal static class RuleDescriber
{
    public static string Process(ProcessSelector selector)
    {
        var text = selector.Kind switch
        {
            ProcessSelectorKind.Instance => selector.Identity is null
                ? Loc.Current["Common.Unknown"]
                : Format("Describe.Instance", selector.Identity.ToShortString()),
            ProcessSelectorKind.ExecutablePath => Format("Describe.Path", selector.ExecutablePath ?? "?"),
            ProcessSelectorKind.ProcessName => Format("Describe.Name", selector.ProcessName ?? "?"),
            ProcessSelectorKind.User => Format("Describe.User", selector.Uid?.ToString(CultureInfo.CurrentCulture) ?? "?"),
            _ => Loc.Current["Describe.AnyProcess"],
        };

        // The Wine target is what distinguishes two games on one runtime, so a rule that has
        // one must say so: without it the two rules read identically.
        if (selector.WineTargetExecutable is { Length: > 0 } wine)
        {
            text += " · " + Format("Describe.WineTarget", wine);
        }

        if (selector.Descendants != DescendantPolicy.Exclude)
        {
            text += " " + Loc.Current["Describe.AndChildren"];
        }

        return text;
    }

    public static string Destination(DestinationSelector destination)
    {
        if (destination.IsUnconstrained)
        {
            return Loc.Current["Describe.AnyDestination"];
        }

        var parts = new List<string>(4);
        if (destination.Hosts.Count > 0)
        {
            parts.Add(string.Join(", ", destination.Hosts));
        }

        if (destination.Networks.Count > 0)
        {
            parts.Add(string.Join(", ", destination.Networks));
        }

        if (destination.Ports.Count > 0)
        {
            parts.Add(Format("Describe.Port", string.Join(", ", destination.Ports)));
        }

        if (destination.Protocol != TransportFilter.Any)
        {
            parts.Add(destination.Protocol.ToString().ToUpperInvariant());
        }

        return string.Join(" · ", parts);
    }

    /// <summary>The action, with the route's display name rather than its id.</summary>
    public static string Action(RuleAction action, string? routeName) => action switch
    {
        RuleAction.Block => Loc.Current["Describe.Block"],
        RuleAction.Proxy or RuleAction.Chain => routeName ?? Loc.Current["Rules.UnknownRoute"],
        _ => Loc.Current["Describe.Direct"],
    };

    /// <summary>"via Home server", or the bare action when there is no route.</summary>
    public static string Route(RuleAction action, string? routeName) => action switch
    {
        RuleAction.Proxy or RuleAction.Chain => Format("Describe.Via", routeName ?? Loc.Current["Rules.UnknownRoute"]),
        _ => Action(action, routeName),
    };

    private static string Format(string key, string value) =>
        string.Format(CultureInfo.CurrentCulture, Loc.Current[key], value);
}
