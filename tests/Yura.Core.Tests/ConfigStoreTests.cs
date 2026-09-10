using Yura.App.Services;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// Covers what the configuration file must and must not contain, and how it behaves when
/// the file on disk is not what we left there.
/// </summary>
public sealed class ConfigStoreTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "yura-config-tests-" + Guid.NewGuid().ToString("N"));

    private ConfigStore NewStore() => new(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    private static ProxyEndpoint Proxy(string name = "Home", string? passwordRef = null) => new()
    {
        Id = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000001"),
        Name = name,
        Protocol = ProxyProtocol.Socks5,
        Host = "127.0.0.1",
        Port = 1080,
        Username = "hakuu",
        PasswordRef = passwordRef,
    };

    private static RoutingRule Rule(RuleLifetime lifetime, string name) => new()
    {
        Id = Guid.NewGuid(),
        Order = 100,
        Name = name,
        Origin = RuleOrigin.ProcessSelection,
        Lifetime = lifetime,
        Process = lifetime == RuleLifetime.Persistent
            ? new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/usr/bin/curl" }
            : new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = new ProcessIdentity { Pid = 42, StartTicks = 7, Uid = 1000, BootId = "b" },
            },
        Action = new RuleAction.Proxy(Guid.Parse("aaaaaaaa-0000-4000-8000-000000000001")),
        CreatedAtUtc = DateTimeOffset.UnixEpoch,
    };

    [Fact]
    public void Defaults_to_the_xdg_location()
    {
        Assert.EndsWith("/Yura", ConfigStore.DefaultDirectory(), StringComparison.Ordinal);
        Assert.Contains(".config", ConfigStore.DefaultDirectory(), StringComparison.Ordinal);
    }

    [Fact]
    public void Honours_XDG_CONFIG_HOME_when_it_is_set()
    {
        var previous = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        try
        {
            Environment.SetEnvironmentVariable("XDG_CONFIG_HOME", "/tmp/xdg-probe");
            Assert.Equal("/tmp/xdg-probe/Yura", ConfigStore.DefaultDirectory());
        }
        finally
        {
            Environment.SetEnvironmentVariable("XDG_CONFIG_HOME", previous);
        }
    }

    [Fact]
    public void A_missing_file_loads_as_empty_rather_than_failing()
    {
        var (document, warning) = NewStore().Load();

        Assert.Null(warning);
        Assert.Empty(document.Proxies);
        Assert.Empty(document.Rules);
    }

    [Fact]
    public async Task Proxies_and_persistent_rules_round_trip()
    {
        var store = NewStore();
        var rule = Rule(RuleLifetime.Persistent, "curl always");

        Assert.Null(await store.SaveAsync(new PersistedSettings(), [Proxy()], [rule]));

        var (document, warning) = store.Load();
        Assert.Null(warning);

        var proxy = Assert.Single(document.Proxies).ToEndpoint();
        Assert.Equal("Home", proxy.Name);
        Assert.Equal(ProxyProtocol.Socks5, proxy.Protocol);
        Assert.Equal(1080, proxy.Port);
        Assert.Equal("hakuu", proxy.Username);

        var restored = Assert.Single(document.Rules).ToRule();
        Assert.Equal(ProcessSelectorKind.ExecutablePath, restored.Process.Kind);
        Assert.Equal("/usr/bin/curl", restored.Process.ExecutablePath);
        Assert.Equal(rule.Action, restored.Action);
    }

    [Fact]
    public async Task Instance_and_session_rules_are_never_written()
    {
        var store = NewStore();

        await store.SaveAsync(new PersistedSettings(), [],
        [
            Rule(RuleLifetime.Persistent, "keep"),
            Rule(RuleLifetime.Instance, "drop-instance"),
            Rule(RuleLifetime.Session, "drop-session"),
        ]);

        // A pid and a start time mean nothing after a reboot; persisting them would let a
        // reused pid inherit a policy, which is the one thing the design forbids.
        var (document, _) = store.Load();
        var kept = Assert.Single(document.Rules);
        Assert.Equal("keep", kept.Name);
    }

    [Fact]
    public async Task A_password_is_never_written_to_the_file()
    {
        var store = NewStore();
        await store.SaveAsync(new PersistedSettings(), [Proxy(passwordRef: "aaaaaaaa-0000-4000-8000-000000000001")], []);

        var text = await File.ReadAllTextAsync(store.FilePath);

        Assert.Contains("passwordRef", text, StringComparison.Ordinal);
        Assert.DoesNotContain("password\"", text, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Settings_round_trip()
    {
        var store = NewStore();
        await store.SaveAsync(
            new PersistedSettings { Theme = "light", Language = "zh-Hans", ReducedMotion = true }, [], []);

        var (document, _) = store.Load();

        Assert.Equal("light", document.Settings.Theme);
        Assert.Equal("zh-Hans", document.Settings.Language);
        Assert.True(document.Settings.ReducedMotion);
    }

    [Fact]
    public async Task The_config_file_is_not_readable_by_other_users()
    {
        var store = NewStore();
        await store.SaveAsync(new PersistedSettings(), [Proxy()], []);

        var mode = File.GetUnixFileMode(store.FilePath);

        Assert.Equal(UnixFileMode.None, mode & (UnixFileMode.GroupRead | UnixFileMode.OtherRead));
    }

    [Fact]
    public async Task A_corrupt_file_is_preserved_rather_than_overwritten()
    {
        var store = NewStore();
        await store.SaveAsync(new PersistedSettings(), [Proxy()], []);
        await File.WriteAllTextAsync(store.FilePath, "{ this is not json");

        var (document, warning) = store.Load();

        Assert.NotNull(warning);
        Assert.Empty(document.Proxies);
        // Losing someone's proxy list to a parse error is not an acceptable outcome.
        Assert.True(File.Exists(store.FilePath + ".corrupt"), "the unreadable file must be kept");
    }

    [Fact]
    public async Task A_file_from_a_newer_version_is_left_alone()
    {
        var store = NewStore();
        await File.WriteAllTextAsync(
            Path.Combine(Directory.CreateDirectory(_directory).FullName, "config.json"),
            """{"version": 99, "proxies": [], "rules": []}""");

        var (document, warning) = store.Load();

        Assert.NotNull(warning);
        Assert.Contains("newer version", warning, StringComparison.Ordinal);
        Assert.Empty(document.Proxies);
        Assert.False(File.Exists(store.FilePath + ".corrupt"), "a newer file is not corrupt and must not be moved");
    }

    [Fact]
    public async Task Saving_leaves_no_temporary_file_behind()
    {
        var store = NewStore();
        await store.SaveAsync(new PersistedSettings(), [Proxy()], []);

        Assert.False(File.Exists(store.FilePath + ".tmp"));
    }
}
