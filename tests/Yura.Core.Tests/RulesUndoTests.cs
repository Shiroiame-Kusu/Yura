using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>Undo on the Rules page, which has to undo in the kernel what it undoes in the list.</summary>
public sealed class RulesUndoTests
{
    private static RoutingRule Curl(RuleAction action) => new()
    {
        Id = Guid.NewGuid(),
        Order = 100,
        Name = "curl",
        Origin = RuleOrigin.Manual,
        Lifetime = RuleLifetime.Persistent,
        Process = new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/usr/bin/curl" },
        Action = action,
        CreatedAtUtc = DateTimeOffset.UnixEpoch,
    };

    [Fact]
    public async Task Undoing_a_replacement_takes_the_new_rule_out_of_the_daemon()
    {
        // The earlier rule was put back and the one that replaced it stayed installed, deciding
        // routes from a position no page showed.
        var rules = new RuleStore();
        var daemon = new RecordingDaemonClient();
        var page = new RulesPageViewModel(rules, daemon);
        var first = Curl(RuleAction.Direct.Instance);
        rules.Add(first);
        var second = Curl(RuleAction.Block.Instance);
        rules.Add(second);
        daemon.Installed.Add((second.Id, second.Name));

        await page.UndoCommand.ExecuteAsync(null);

        Assert.Contains(second.Id, daemon.Removed);
        Assert.Equal(first.Id, Assert.Single(daemon.Installed).Id);
        Assert.Equal(first.Id, Assert.Single(rules.Rules).Id);
    }

    [Fact]
    public async Task Undoing_an_in_place_replacement_puts_the_old_rule_back_in_its_place()
    {
        var rules = new RuleStore();
        var daemon = new RecordingDaemonClient();
        var page = new RulesPageViewModel(rules, daemon);
        var first = Curl(RuleAction.Direct.Instance);
        rules.Add(first);
        rules.Add(first with { Action = RuleAction.Block.Instance });
        daemon.Installed.Add((first.Id, first.Name));

        await page.UndoCommand.ExecuteAsync(null);

        // Same id both ways: the daemon swaps it back in one step, and removing it first would
        // leave a moment with neither.
        Assert.Empty(daemon.Removed);
        Assert.Equal(RuleAction.Direct.Instance, daemon.Applied[^1].Rule.Action);
        Assert.Equal(first.Id, Assert.Single(daemon.Installed).Id);
    }
}
