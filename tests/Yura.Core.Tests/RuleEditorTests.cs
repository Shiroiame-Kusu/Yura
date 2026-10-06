using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// The Rules page editor: what a rule matches has to survive being edited.
/// </summary>
/// <remarks>
/// Saving rebuilt the match from the three fields the form shows. Everything else went: the
/// Windows executable that keeps a rule on a shared Proton runtime to one game, the running
/// instance a rule was bound to, the existing children a tree rule covers, and the lifetime.
/// Renaming a boost rule turned it into a saved rule that proxied every game on the runtime.
/// </remarks>
public sealed class RuleEditorTests
{
    private static readonly Guid Exit = Guid.Parse("eeeeeeee-0000-4000-8000-00000000000e");

    private static RuleStore Store()
    {
        var store = new RuleStore();
        store.Proxies.Add(new ProxyEndpoint
        {
            Id = Exit, Name = "Tokyo", Protocol = ProxyProtocol.Socks5, Host = "10.0.0.2", Port = 1080,
        });
        return store;
    }

    private static readonly ProcessSnapshot Curl = new()
    {
        Identity = new ProcessIdentity { Pid = 4242, StartTicks = 99, Uid = 1000, BootId = "b" },
        Name = "curl",
        ExecutablePath = "/usr/bin/curl",
        ExecutablePathState = ExecutablePathState.Resolved,
        ParentPid = 1,
        UserName = "hakuu",
    };

    [Fact]
    public void Renaming_a_Proton_game_rule_keeps_it_on_that_one_game()
    {
        var store = Store();
        var boost = new RoutingRule
        {
            Id = Guid.NewGuid(),
            Order = 300,
            Name = "Boost: Elden Ring",
            Origin = RuleOrigin.GameProfile,
            Lifetime = RuleLifetime.Session,
            Process = new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = "/home/u/.steam/steam/steamapps/common/Proton 9.0/files/bin/wine64-preloader",
                WineTargetExecutable = @"C:\Games\ELDEN RING\Game\eldenring.exe",
                WinePrefix = "/home/u/.steam/steam/steamapps/compatdata/1245620/pfx",
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            },
            Destination = DestinationSelector.Any,
            Action = new RuleAction.Proxy(Exit),
            CreatedAtUtc = DateTimeOffset.UnixEpoch,
        };
        var editor = new RuleEditorViewModel(store);
        editor.BeginEdit(boost);

        editor.Name = "Elden Ring via Tokyo";
        Assert.True(editor.TryBuild(out var saved, out var problem), problem);

        Assert.Equal(boost.Id, saved.Id);
        Assert.Equal("Elden Ring via Tokyo", saved.Name);
        Assert.Equal(boost.Process, saved.Process);
        Assert.Equal(RuleLifetime.Session, saved.Lifetime);
        Assert.Equal(RuleOrigin.GameProfile, saved.Origin);
    }

    [Fact]
    public void An_instance_rule_is_edited_as_an_instance_rule()
    {
        var store = Store();
        var rule = store.BuildRule(Curl, RuleScopeChoice.Instance, new RuleAction.Proxy(Exit), false);
        var editor = new RuleEditorViewModel(store);

        editor.BeginEdit(rule);

        // Nothing to type, and the form says what is kept instead of asking for a path.
        Assert.Equal(ProcessSelectorKind.Instance, editor.ProcessKind);
        Assert.Contains(ProcessSelectorKind.Instance, editor.ProcessKinds);
        Assert.False(editor.NeedsProcessValue);
        Assert.True(editor.HasFixedSubject);
        Assert.False(string.IsNullOrEmpty(editor.FixedSubjectDescription));

        editor.Action = RuleActionChoice.Block;
        Assert.True(editor.TryBuild(out var saved, out var problem), problem);

        Assert.Equal(rule.Process.Identity, saved.Process.Identity);
        Assert.Equal(ProcessSelectorKind.Instance, saved.Process.Kind);
        Assert.Equal(RuleLifetime.Instance, saved.Lifetime);
        Assert.Equal(RuleAction.Block.Instance, saved.Action);
    }

    [Fact]
    public void Turning_an_instance_rule_into_a_path_rule_makes_it_a_saved_one()
    {
        // A rule no longer tied to one running process cannot expire with it.
        var store = Store();
        var rule = store.BuildRule(Curl, RuleScopeChoice.Instance, new RuleAction.Proxy(Exit), false);
        var editor = new RuleEditorViewModel(store);
        editor.BeginEdit(rule);

        editor.ProcessKind = ProcessSelectorKind.ExecutablePath;
        editor.ProcessValue = "/usr/bin/curl";
        Assert.True(editor.TryBuild(out var saved, out var problem), problem);

        Assert.Equal(ProcessSelectorKind.ExecutablePath, saved.Process.Kind);
        Assert.Null(saved.Process.Identity);
        Assert.Equal(RuleLifetime.Persistent, saved.Lifetime);
    }

    [Fact]
    public void A_tree_rule_keeps_its_existing_children_unless_the_box_is_changed()
    {
        var store = Store();
        var tree = store.BuildRule(Curl, RuleScopeChoice.Tree, new RuleAction.Proxy(Exit), false);
        Assert.Equal(DescendantPolicy.IncludeExistingAndFuture, tree.Process.Descendants);
        var editor = new RuleEditorViewModel(store);

        editor.BeginEdit(tree);
        Assert.True(editor.TryBuild(out var untouched, out _));
        Assert.Equal(DescendantPolicy.IncludeExistingAndFuture, untouched.Process.Descendants);

        editor.IncludeChildren = false;
        Assert.True(editor.TryBuild(out var unticked, out _));
        Assert.Equal(DescendantPolicy.Exclude, unticked.Process.Descendants);
    }

    [Fact]
    public void A_new_rule_has_only_the_kinds_the_form_can_build()
    {
        var store = Store();
        var editor = new RuleEditorViewModel(store);
        editor.BeginEdit(store.BuildRule(Curl, RuleScopeChoice.Instance, RuleAction.Direct.Instance, false));

        editor.BeginAdd();

        Assert.DoesNotContain(ProcessSelectorKind.Instance, editor.ProcessKinds);
        Assert.False(editor.HasFixedSubject);
    }
}
