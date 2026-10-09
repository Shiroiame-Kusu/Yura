using Yura.App.Services;
using Yura.Core.Games;
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

    private static ConfigSnapshot Snapshot(
        PersistedSettings? settings = null,
        IEnumerable<ProxyEndpoint>? proxies = null,
        IEnumerable<RoutingRule>? rules = null,
        IEnumerable<ProxyChain>? chains = null,
        IEnumerable<GameProfile>? games = null) => new()
        {
            Settings = settings ?? new PersistedSettings(),
            Proxies = proxies ?? [],
            Rules = rules ?? [],
            Chains = chains ?? [],
            Games = games ?? [],
        };

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

        Assert.Null(await store.SaveAsync(Snapshot(proxies: [Proxy()], rules: [rule])));

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

        await store.SaveAsync(Snapshot(rules:
        [
            Rule(RuleLifetime.Persistent, "keep"),
            Rule(RuleLifetime.Instance, "drop-instance"),
            Rule(RuleLifetime.Session, "drop-session"),
        ]));

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
        await store.SaveAsync(Snapshot(proxies: [Proxy(passwordRef: "aaaaaaaa-0000-4000-8000-000000000001")]));

        var text = await File.ReadAllTextAsync(store.FilePath);

        Assert.Contains("passwordRef", text, StringComparison.Ordinal);
        Assert.DoesNotContain("password\"", text, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Settings_round_trip()
    {
        var store = NewStore();
        await store.SaveAsync(Snapshot(
            new PersistedSettings
            {
                Theme = "light",
                Language = "zh-Hans",
                ReducedMotion = true,
                DnsPolicy = DnsPolicy.Direct,
                ShowAllProcesses = true,
            }));

        var (document, _) = store.Load();

        Assert.Equal("light", document.Settings.Theme);
        Assert.Equal("zh-Hans", document.Settings.Language);
        Assert.True(document.Settings.ReducedMotion);
        Assert.Equal(DnsPolicy.Direct, document.Settings.DnsPolicy);
        Assert.True(document.Settings.ShowAllProcesses);
    }

    /// <summary>A synchronization context whose thread never gets round to anything posted to it.</summary>
    private sealed class HeldThread : SynchronizationContext
    {
        public override void Post(SendOrPostCallback d, object? state)
        {
        }

        public override void Send(SendOrPostCallback d, object? state)
        {
        }
    }

    [Fact]
    public void Saving_never_waits_for_the_thread_that_asked()
    {
        // The app saves on exit from the UI thread, which waits for the save and so runs nothing
        // else. A save that came back to that thread to finish hung every exit, the window left
        // on screen and the process running.
        var previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new HeldThread());
        try
        {
            var save = NewStore().SaveAsync(Snapshot(proxies: [Proxy()]));

            Assert.True(save.Wait(TimeSpan.FromSeconds(10)), "the save waited for the thread that is waiting for it");
            Assert.Null(save.Result);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }
    }

    [Fact]
    public async Task The_config_file_is_not_readable_by_other_users()
    {
        var store = NewStore();
        await store.SaveAsync(Snapshot(proxies: [Proxy()]));

        var mode = File.GetUnixFileMode(store.FilePath);

        Assert.Equal(UnixFileMode.None, mode & (UnixFileMode.GroupRead | UnixFileMode.OtherRead));
    }

    [Fact]
    public async Task A_corrupt_file_is_preserved_rather_than_overwritten()
    {
        var store = NewStore();
        await store.SaveAsync(Snapshot(proxies: [Proxy()]));
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
    public async Task Chains_round_trip_and_keep_their_hop_order()
    {
        var store = NewStore();
        var first = Guid.Parse("aaaaaaaa-0000-4000-8000-00000000000a");
        var second = Guid.Parse("aaaaaaaa-0000-4000-8000-00000000000b");

        await store.SaveAsync(Snapshot(chains:
        [
            new ProxyChain { Id = Guid.NewGuid(), Name = "A then B", Hops = [first, second] },
        ]));

        var chain = Assert.Single(store.Load().Document.Chains).ToChain();
        Assert.Equal("A then B", chain.Name);
        // Order is the whole meaning of a chain: element 0 is dialled first.
        Assert.Equal([first, second], chain.Hops);
    }

    [Fact]
    public async Task Only_games_the_user_has_told_us_something_about_are_saved()
    {
        var store = NewStore();
        var route = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000001");

        await store.SaveAsync(Snapshot(games:
        [
            // Nothing known beyond what rediscovery would find again: not worth a line.
            new GameProfile { Id = Guid.NewGuid(), Name = "Untouched", SteamAppId = "1", Source = GameSource.Steam },
            new GameProfile { Id = Guid.NewGuid(), Name = "Routed", SteamAppId = "2", Source = GameSource.Steam, RouteId = route },
            new GameProfile { Id = Guid.NewGuid(), Name = "Added by hand", Source = GameSource.Manual, ExecutablePath = "/usr/bin/game" },
        ]));

        var names = store.Load().Document.Games.Select(g => g.Name).ToList();
        Assert.Equal(2, names.Count);
        Assert.Contains("Routed", names);
        Assert.Contains("Added by hand", names);
    }

    [Fact]
    public async Task A_games_route_and_measurement_target_survive_a_restart()
    {
        var store = NewStore();
        var chainId = Guid.NewGuid();

        await store.SaveAsync(Snapshot(games:
        [
            new GameProfile
            {
                Id = Guid.NewGuid(),
                Name = "FFXIV",
                WineTargetExecutable = "Z:\\games\\ffxiv_dx11.exe",
                Source = GameSource.Steam,
                RouteId = chainId,
                RouteIsChain = true,
                MeasurementHost = "204.2.229.85",
                MeasurementPort = 54994,
            },
        ]));

        var game = Assert.Single(store.Load().Document.Games).ToProfile();
        Assert.Equal(chainId, game.RouteId);
        Assert.True(game.RouteIsChain);
        Assert.Equal("204.2.229.85", game.MeasurementHost);
        Assert.Equal(54994, game.MeasurementPort);
        Assert.True(game.IsMeasurable);
        Assert.True(game.IsRoutable);
    }

    [Fact]
    public async Task Saving_leaves_no_temporary_file_behind()
    {
        var store = NewStore();
        await store.SaveAsync(Snapshot(proxies: [Proxy()]));

        Assert.False(File.Exists(store.FilePath + ".tmp"));
    }
    [Fact]
    public async Task A_wireguard_exit_round_trips_its_settings_and_never_its_keys()
    {
        var exit = new ProxyEndpoint
        {
            Id = Guid.NewGuid(),
            Name = "Frankfurt exit",
            Protocol = ProxyProtocol.WireGuard,
            Host = "wg.example.net",
            Port = 51820,
            PasswordRef = "ref-private",
            WireGuard = new WireGuardSettings
            {
                PeerPublicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                Addresses = ["10.8.0.7/32", "fd42::7/128"],
                DnsServers = ["10.8.0.1"],
                AllowedIps = ["0.0.0.0/0"],
                Mtu = 1380,
                PersistentKeepalive = 25,
                PresharedKeyRef = "ref-psk",
            },
        };

        var store = NewStore();
        Assert.Null(await store.SaveAsync(Snapshot(proxies: [exit])));

        var text = await File.ReadAllTextAsync(store.FilePath);
        Assert.DoesNotContain("PrivateKey", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("presharedKey\"", text, StringComparison.Ordinal);
        Assert.Contains("\"wireGuard\"", text, StringComparison.Ordinal);

        var restored = store.Load().Document.Proxies.Single().ToEndpoint();
        Assert.Equal(ProxyProtocol.WireGuard, restored.Protocol);
        Assert.Equal("ref-private", restored.PasswordRef);
        Assert.NotNull(restored.WireGuard);
        Assert.Equal(exit.WireGuard.PeerPublicKey, restored.WireGuard!.PeerPublicKey);
        Assert.Equal(exit.WireGuard.Addresses, restored.WireGuard.Addresses);
        Assert.Equal(exit.WireGuard.DnsServers, restored.WireGuard.DnsServers);
        Assert.Equal(exit.WireGuard.AllowedIps, restored.WireGuard.AllowedIps);
        Assert.Equal(1380, restored.WireGuard.Mtu);
        Assert.Equal(25, restored.WireGuard.PersistentKeepalive);
        Assert.Equal("ref-psk", restored.WireGuard.PresharedKeyRef);
    }
}
