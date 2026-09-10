using System.Net;
using Yura.Core.Processes;

namespace Yura.Core.Rules;

/// <summary>Everything needed to decide one connection's route.</summary>
public sealed record RoutingRequest
{
    /// <summary>
    /// The owning process, or null when ownership could not be established (permission
    /// denied, or the socket's owner exited before we looked). A null process can only
    /// match rules whose process selector is <see cref="ProcessSelectorKind.Any"/>.
    /// </summary>
    public ProcessSnapshot? Process { get; init; }

    public required IPAddress DestinationAddress { get; init; }

    public required ushort DestinationPort { get; init; }

    public required TransportProtocol Protocol { get; init; }

    /// <summary>
    /// Destination name if one was learned from a DNS answer or from TLS SNI / HTTP Host.
    /// Null means "no name observed", not "no name exists".
    /// </summary>
    public string? DestinationHost { get; init; }

    /// <summary>
    /// Ids of rules whose process side was already decided by the kernel classifier. When
    /// present, the evaluator trusts this set for instance and tree membership instead of
    /// re-deriving it from pids, which would race with process exit.
    /// </summary>
    public IReadOnlySet<Guid>? ClassifierMatchedRuleIds { get; init; }
}

/// <summary>Why a connection is routed the way it is.</summary>
public sealed record RuleDecision
{
    public required RuleAction Action { get; init; }

    /// <summary>The winning rule, or null when nothing matched and the default applied.</summary>
    public RoutingRule? MatchedRule { get; init; }

    /// <summary>
    /// Rules that also matched but lost on order. Surfaced so the UI can answer
    /// "why isn't my game profile winning?" without the user reading the whole list.
    /// </summary>
    public IReadOnlyList<RoutingRule> ShadowedRules { get; init; } = [];

    /// <summary>Human-readable sentence for the connection inspector.</summary>
    public required string Explanation { get; init; }

    public bool IsDefault => MatchedRule is null;
}

/// <summary>
/// Ordered, first-match evaluation over the shared rule list.
/// </summary>
/// <remarks>
/// This type is pure and side-effect free so it can be unit tested against the acceptance
/// criteria, and so the daemon and the UI can never disagree about which rule wins: the UI
/// runs exactly this code to render its explanation.
/// </remarks>
public static class RuleEvaluator
{
    /// <summary>Traffic that matches nothing goes out untouched.</summary>
    public static readonly RuleAction DefaultAction = RuleAction.Direct.Instance;

    /// <summary>Sorts a rule list into evaluation order. Stable and total.</summary>
    public static IReadOnlyList<RoutingRule> Sort(IEnumerable<RoutingRule> rules) =>
        rules.OrderBy(r => r.Order)
             .ThenBy(r => r.CreatedAtUtc)
             .ThenBy(r => r.Id)
             .ToArray();

    /// <summary>
    /// Evaluates <paramref name="orderedRules"/> against <paramref name="request"/>.
    /// </summary>
    /// <param name="orderedRules">Must already be in evaluation order; use <see cref="Sort"/>.</param>
    public static RuleDecision Evaluate(IReadOnlyList<RoutingRule> orderedRules, RoutingRequest request)
    {
        ArgumentNullException.ThrowIfNull(orderedRules);
        ArgumentNullException.ThrowIfNull(request);

        RoutingRule? winner = null;
        List<RoutingRule>? shadowed = null;

        foreach (var rule in orderedRules)
        {
            if (!rule.Enabled || !Matches(rule, request))
            {
                continue;
            }

            if (winner is null)
            {
                winner = rule;
                continue;
            }

            (shadowed ??= []).Add(rule);
        }

        if (winner is null)
        {
            return new RuleDecision
            {
                Action = DefaultAction,
                Explanation = "No rule matched. Unmatched traffic defaults to Direct.",
            };
        }

        return new RuleDecision
        {
            Action = winner.Action,
            MatchedRule = winner,
            ShadowedRules = shadowed ?? (IReadOnlyList<RoutingRule>)[],
            Explanation = Explain(winner, shadowed),
        };
    }

    private static bool Matches(RoutingRule rule, RoutingRequest request)
    {
        if (!MatchesProcessSide(rule, request))
        {
            return false;
        }

        return rule.Destination.MatchesDestination(
            request.DestinationAddress,
            request.DestinationPort,
            request.Protocol,
            request.DestinationHost);
    }

    private static bool MatchesProcessSide(RoutingRule rule, RoutingRequest request)
    {
        if (rule.Process.Kind == ProcessSelectorKind.Any)
        {
            return true;
        }

        // The kernel classifier owns instance and process-tree membership. If it has spoken
        // for this connection, its answer is authoritative: re-deriving membership from the
        // current /proc state would give the wrong answer for a process that has since
        // exited, or for a child that has been re-parented.
        if (request.ClassifierMatchedRuleIds is { } classified &&
            (rule.Process.IsInstanceScoped || rule.Process.Descendants != DescendantPolicy.Exclude))
        {
            return classified.Contains(rule.Id);
        }

        return request.Process is { } process && rule.Process.MatchesProcess(process);
    }

    private static string Explain(RoutingRule winner, List<RoutingRule>? shadowed)
    {
        var origin = winner.Origin switch
        {
            RuleOrigin.ProcessSelection => "process selection",
            RuleOrigin.GameProfile => "game profile",
            RuleOrigin.System => "built-in loop prevention",
            _ => "manual rule",
        };

        var text = $"Matched {origin} “{winner.Name}” at position {winner.Order}.";

        if (shadowed is { Count: > 0 })
        {
            var names = string.Join(", ", shadowed.Take(3).Select(r => $"“{r.Name}”"));
            var more = shadowed.Count > 3 ? $" and {shadowed.Count - 3} more" : string.Empty;
            text += $" It takes precedence over {names}{more}, which also matched but sit lower in the list.";
        }

        return text;
    }
}
