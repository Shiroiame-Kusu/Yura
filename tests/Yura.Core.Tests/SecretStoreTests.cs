using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// Where proxy passwords, WireGuard keys and agent tokens go when the secret service will not
/// take them.
/// </summary>
/// <remarks>
/// They used to go nowhere. Without <c>secret-tool</c>, or with one and no secret service behind
/// it, the store kept nothing and the app had no other copy: the proxy was saved pointing at a
/// secret nothing held, and the daemon was handed an exit with no password or key — while the
/// editor said the secret was kept for the session.
/// </remarks>
public sealed class SecretStoreTests
{
    /// <summary>A secret service that is there, or not, and takes nothing either way.</summary>
    private sealed class RefusingSecretStore(bool available) : ISecretStore
    {
        public List<string> Deleted { get; } = [];

        public bool IsAvailable => available;

        public string Description => "the desktop secret service";

        public Task<bool> SetAsync(string reference, string secret, CancellationToken ct = default) =>
            Task.FromResult(false);

        public Task<string?> GetAsync(string reference, CancellationToken ct = default) =>
            Task.FromResult<string?>(null);

        public Task DeleteAsync(string reference, CancellationToken ct = default)
        {
            Deleted.Add(reference);
            return Task.CompletedTask;
        }
    }

    private const string AgentToken = "3cCq9Yb1n5Xp7tR2uW4kZ6mJ8dL0sF1hV3gB5aN7eQ0";

    private const string AgentKey = "qS3n8uG1xK0pZ7rJ4mW2cV5bT9hY6dL8aF1eR0sX4uY";

    [Fact]
    public async Task A_secret_the_secret_service_refuses_still_lasts_the_session()
    {
        var store = new SessionBackedSecretStore(new RefusingSecretStore(available: true));
        var ct = TestContext.Current.CancellationToken;

        var persisted = await store.SetAsync("exit", "hunter2", ct);

        Assert.False(persisted);
        Assert.Equal("hunter2", await store.GetAsync("exit", ct));
    }

    [Fact]
    public async Task The_secret_set_this_session_wins_over_the_one_saved_before()
    {
        var persistent = new FakeSecretStore();
        persistent.Secrets["exit"] = "old";
        var store = new SessionBackedSecretStore(persistent);
        var ct = TestContext.Current.CancellationToken;

        Assert.Equal("old", await store.GetAsync("exit", ct));

        await store.SetAsync("exit", "new", ct);

        Assert.Equal("new", await store.GetAsync("exit", ct));
        Assert.Equal("new", persistent.Secrets["exit"]);
    }

    [Fact]
    public async Task Deleting_a_secret_removes_both_copies()
    {
        var persistent = new RefusingSecretStore(available: true);
        var store = new SessionBackedSecretStore(persistent);
        var ct = TestContext.Current.CancellationToken;
        await store.SetAsync("exit", "hunter2", ct);

        await store.DeleteAsync("exit", ct);

        Assert.Null(await store.GetAsync("exit", ct));
        Assert.Contains("exit", persistent.Deleted);
    }

    private static ProxyEditorViewModel AgentEditor(ISecretStore secrets, RuleStore rules)
    {
        var editor = new ProxyEditorViewModel(rules, new RecordingDaemonClient(), secrets);
        editor.BeginAddAgent();
        editor.Name = "Frankfurt";
        editor.Host = "203.0.113.9";
        editor.Fingerprint = AgentKey;
        editor.Token = AgentToken;
        return editor;
    }

    [Fact]
    public async Task Saving_says_so_when_the_secret_service_did_not_keep_the_secret()
    {
        var rules = new RuleStore();
        var secrets = new SessionBackedSecretStore(new RefusingSecretStore(available: true));
        var editor = AgentEditor(secrets, rules);
        string? warning = null;
        editor.SecretNotStored += (_, message) => warning = message;

        await editor.SaveCommand.ExecuteAsync(null);

        // Saved, usable now, and the user told it will not survive a restart.
        var saved = Assert.Single(rules.Proxies);
        Assert.Equal(AgentToken, await secrets.GetAsync(saved.Id.ToString(), TestContext.Current.CancellationToken));
        Assert.NotNull(warning);
        Assert.Contains("Frankfurt", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task With_no_secret_service_at_all_the_editor_has_already_said_so()
    {
        var rules = new RuleStore();
        var editor = AgentEditor(new SessionBackedSecretStore(new RefusingSecretStore(available: false)), rules);
        string? warning = null;
        editor.SecretNotStored += (_, message) => warning = message;

        await editor.SaveCommand.ExecuteAsync(null);

        Assert.Single(rules.Proxies);
        Assert.Null(warning);
        Assert.Contains("session", editor.SecretStoreDescription, StringComparison.OrdinalIgnoreCase);
    }
}
