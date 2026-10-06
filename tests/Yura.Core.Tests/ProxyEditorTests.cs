using System.Net;
using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.Core.Connections;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>Records what was stored, so a test can assert a secret went to the store and not the file.</summary>
internal sealed class FakeSecretStore : ISecretStore
{
    public Dictionary<string, string> Secrets { get; } = [];

    public bool IsAvailable => true;

    public string Description => "the test store";

    public Task<bool> SetAsync(string reference, string secret, CancellationToken ct = default)
    {
        Secrets[reference] = secret;
        return Task.FromResult(true);
    }

    public Task<string?> GetAsync(string reference, CancellationToken ct = default) =>
        Task.FromResult(Secrets.GetValueOrDefault(reference));

    public Task DeleteAsync(string reference, CancellationToken ct = default)
    {
        Secrets.Remove(reference);
        return Task.CompletedTask;
    }
}

/// <summary>Captures what the app asked the daemon to do: probes, applies and removals.</summary>
internal sealed class RecordingDaemonClient : IDaemonClient
{
    public List<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> Probes { get; } = [];

    /// <summary>Every rule the app installed, in order, with the reset flag it asked for.</summary>
    public List<(RoutingRule Rule, bool ResetExisting)> Applied { get; } = [];

    /// <summary>Every rule id the app asked the daemon to take out.</summary>
    public List<Guid> Removed { get; } = [];

    /// <summary>What the next apply reports back. Lets a test drive the failure path.</summary>
    public RuleApplyResult NextApplyResult { get; set; } = new() { Succeeded = true };

    /// <summary>Makes removals fail, the way a daemon that went away mid-edit would.</summary>
    public bool FailRemovals { get; set; }

    public DaemonState State { get; set; } = DaemonState.Connected;

    public event EventHandler<DaemonState>? StateChanged;

    public event EventHandler? InstanceChanged;

    /// <summary>Raises <see cref="StateChanged"/>, the way the socket client does when the daemon comes or goes.</summary>
    public void RaiseStateChanged(DaemonState state)
    {
        State = state;
        StateChanged?.Invoke(this, state);
    }

    /// <summary>Raises <see cref="InstanceChanged"/>, as if the daemon had restarted between two requests.</summary>
    public void RaiseInstanceChanged() => InstanceChanged?.Invoke(this, EventArgs.Empty);

    public string? UnavailableReason => State == DaemonState.Connected ? null : "the test daemon is not connected";

    public Task ConnectAsync(CancellationToken ct = default) => Task.CompletedTask;

    public Task<bool> PingAsync(CancellationToken ct = default) => Task.FromResult(State == DaemonState.Connected);

    public Task<DaemonStatus?> GetStatusAsync(CancellationToken ct = default) => Task.FromResult<DaemonStatus?>(null);

    public Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyDictionary<int, int>>(new Dictionary<int, int>());

    public Task<IReadOnlyList<Connections.ConnectionRecord>> GetConnectionsAsync(int? pid = null, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<Connections.ConnectionRecord>>([]);

    public Task<RuleApplyResult> ApplyRuleAsync(
        RoutingRule rule, bool resetExisting = false, CancellationToken ct = default)
    {
        Applied.Add((rule, resetExisting));
        if (NextApplyResult.Succeeded)
        {
            Installed.RemoveAll(r => r.Id == rule.Id);
            Installed.Add((rule.Id, rule.Name));
        }

        return Task.FromResult(NextApplyResult.Succeeded
            ? NextApplyResult with { ConfirmedAtUtc = DateTimeOffset.UtcNow }
            : NextApplyResult);
    }

    public Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken ct = default)
    {
        Removed.Add(ruleId);
        if (FailRemovals)
        {
            return Task.FromResult(new RuleApplyResult
            {
                Succeeded = false, FailureReason = "the test daemon refused",
            });
        }

        Installed.RemoveAll(r => r.Id == ruleId);
        return Task.FromResult(new RuleApplyResult { Succeeded = true });
    }

    /// <summary>What the daemon is holding, as it would answer list-rules.</summary>
    public List<(Guid Id, string Name)> Installed { get; } = [];

    public Task<IReadOnlyList<(Guid Id, string Name)>> GetInstalledRulesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<(Guid, string)>>(Installed.ToArray());

    public Task<RuleApplyResult> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> proxies,
        IReadOnlyList<ProxyChain> chains, CancellationToken ct = default) =>
        Task.FromResult(new RuleApplyResult { Succeeded = true });

    public Task<RuleApplyResult> SetDnsPolicyAsync(DnsPolicy policy, CancellationToken ct = default) =>
        Task.FromResult(new RuleApplyResult { Succeeded = true });

    public Task<ProxyProbeResult> ProbeProxyAsync(ProxyEndpoint endpoint, ProxySecrets secrets, CancellationToken ct = default)
    {
        Probes.Add((endpoint, secrets));
        return Task.FromResult(new ProxyProbeResult { TimestampUtc = DateTimeOffset.UtcNow, Reachable = true });
    }

    /// <summary>Holds every measurement until completed, so a test can look at the page meanwhile.</summary>
    public TaskCompletionSource? HoldMeasurements { get; set; }

    public async Task<MeasurementDto?> MeasureAsync(string host, ushort port, Guid? proxyId, Guid? chainId, int samples, CancellationToken ct = default)
    {
        if (HoldMeasurements is { } hold)
        {
            await hold.Task.WaitAsync(ct);
        }

        return null;
    }

    /// <summary>What the next NAT test reports, so a test can drive the comparison.</summary>
    public NatTestResultDto? NextNatResult { get; set; }

    public List<(Guid? ProxyId, Guid? ChainId)> NatTests { get; } = [];

    public Task<NatTestResultDto?> TestNatAsync(Guid? proxyId, Guid? chainId, CancellationToken ct = default)
    {
        NatTests.Add((proxyId, chainId));
        return Task.FromResult(NextNatResult);
    }

    public Task<string?> DumpRulesetAsync(CancellationToken ct = default) => Task.FromResult<string?>(null);

    public Task<IReadOnlyList<string>> GetLogAsync(int lines = 200, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<string>>([]);
}

/// <summary>
/// The proxy and chain editors driven the way the interface drives them.
/// </summary>
/// <remarks>
/// These are the paths where a WireGuard exit is actually created, so they are where a
/// mistake would reach a user: validation that disagrees with the daemon, a secret written
/// to the wrong place, or a saved key silently replaced by an empty box.
/// </remarks>
public sealed class ProxyEditorTests
{
    private const string PrivateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    private const string PeerKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    private const string Psk = "FpCyhws9cxwWoV4xbtR2+vNmdyUAgIkfBOozrfp2HbE=";

    private static (ProxyEditorViewModel Editor, RuleStore Rules, FakeSecretStore Secrets, RecordingDaemonClient Daemon) New()
    {
        var rules = new RuleStore();
        var secrets = new FakeSecretStore();
        var daemon = new RecordingDaemonClient();
        return (new ProxyEditorViewModel(rules, daemon, secrets), rules, secrets, daemon);
    }

    // -- Yura agents -------------------------------------------------------------

    private const string AgentToken = "3cCq9Yb1n5Xp7tR2uW4kZ6mJ8dL0sF1hV3gB5aN7eQ0";

    private const string AgentKey = "qS3n8uG1xK0pZ7rJ4mW2cV5bT9hY6dL8aF1eR0sX4uY";

    [Fact]
    public async Task One_paste_of_a_connect_string_is_a_complete_agent_exit()
    {
        // The whole setup experience: the agent prints one line, the user pastes it. Four
        // fields typed by hand include a fingerprint, and a mistyped fingerprint fails in a way
        // that looks like a network problem.
        var (editor, rules, secrets, _) = New();
        editor.BeginAddAgent();

        editor.ImportText = $"yura://{AgentToken}@203.0.113.9:7311?fp={AgentKey}&name=frankfurt-1";
        editor.ImportFromTextCommand.Execute(null);

        Assert.Equal(ProxyProtocol.YuraAgent, editor.Protocol);
        Assert.Equal("203.0.113.9", editor.Host);
        Assert.Equal("7311", editor.Port);
        Assert.Equal(AgentKey, editor.Fingerprint);
        // The agent's own label names the exit, so there is nothing left to fill in.
        Assert.Equal("frankfurt-1", editor.Name);
        Assert.True(editor.IsValid);
        // And the token is out of the box it was pasted into.
        Assert.Equal(string.Empty, editor.ImportText);

        await editor.SaveCommand.ExecuteAsync(null);

        var saved = Assert.Single(rules.Proxies);
        Assert.Equal(ProxyProtocol.YuraAgent, saved.Protocol);
        Assert.Equal(AgentKey, saved.Agent?.Fingerprint);
        Assert.Equal("frankfurt-1", saved.Agent?.AgentLabel);
        // The token is a secret: it goes to the store, keyed by id, and not into the endpoint.
        Assert.Equal(AgentToken, secrets.Secrets[saved.Id.ToString()]);
        Assert.Equal(saved.Id.ToString(), saved.PasswordRef);
    }

    [Fact]
    public void A_connect_string_that_will_not_parse_says_why_and_changes_nothing()
    {
        var (editor, _, _, _) = New();
        editor.BeginAddAgent();

        editor.ImportText = "yura://deadbeef@203.0.113.9:7311";
        editor.ImportFromTextCommand.Execute(null);

        Assert.NotNull(editor.ImportMessage);
        Assert.Equal(string.Empty, editor.Host);
        Assert.False(editor.IsValid);
    }

    [Fact]
    public void An_agent_without_a_key_fingerprint_cannot_be_saved()
    {
        // Without it there is nothing to identify the agent by, and an exit that trusts
        // whatever answers is not an exit worth having.
        var (editor, _, _, _) = New();
        editor.BeginAddAgent();
        editor.Name = "Frankfurt";
        editor.Host = "203.0.113.9";
        editor.Port = "7311";
        editor.Token = AgentToken;

        Assert.False(editor.IsValid);
        editor.Fingerprint = AgentKey;
        Assert.True(editor.IsValid);
    }

    [Fact]
    public async Task An_agent_without_a_token_cannot_be_saved()
    {
        var (editor, rules, _, _) = New();
        editor.BeginAddAgent();
        editor.Name = "Frankfurt";
        editor.Host = "203.0.113.9";
        editor.Fingerprint = AgentKey;

        Assert.False(editor.IsValid);
        // Nothing is said about the token until it has been touched or a save attempted;
        // flagging an untouched box is noise.
        Assert.Null(editor.TokenError);

        await editor.SaveCommand.ExecuteAsync(null);

        Assert.Empty(rules.Proxies);
        Assert.NotNull(editor.TokenError);
        Assert.True(editor.IsOpen);

        editor.Token = AgentToken;
        Assert.True(editor.IsValid);
        Assert.Null(editor.TokenError);
    }

    [Fact]
    public void A_stored_token_counts_for_an_agent_that_already_has_one()
    {
        var (editor, rules, _, _) = New();
        var id = Guid.NewGuid();
        rules.Proxies.Add(new ProxyEndpoint
        {
            Id = id,
            Name = "Frankfurt",
            Protocol = ProxyProtocol.YuraAgent,
            Host = "203.0.113.9",
            Port = 7311,
            PasswordRef = id.ToString(),
            Agent = new AgentSettings { Fingerprint = AgentKey },
        });

        editor.BeginEdit(rules.Proxies[0]);

        // The token is not shown back, and leaving the box empty keeps it.
        Assert.Equal(string.Empty, editor.Token);
        Assert.True(editor.IsValid);
        Assert.Null(editor.TokenError);
    }

    [Fact]
    public void A_proxys_saved_password_does_not_count_as_an_agent_token()
    {
        // The same trap as a password standing in for a WireGuard private key: the form would
        // say valid and the daemon would refuse the exit.
        var (editor, rules, _, _) = New();
        var id = Guid.NewGuid();
        rules.Proxies.Add(new ProxyEndpoint
        {
            Id = id,
            Name = "Home",
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = 1080,
            PasswordRef = id.ToString(),
        });

        editor.BeginEdit(rules.Proxies[0]);
        editor.Protocol = ProxyProtocol.YuraAgent;
        editor.Fingerprint = AgentKey;

        Assert.False(editor.IsValid);
        editor.Token = AgentToken;
        Assert.True(editor.IsValid);
    }

    [Fact]
    public async Task Testing_an_agent_sends_the_token_as_its_secret()
    {
        var (editor, _, _, daemon) = New();
        editor.BeginAddAgent();
        editor.Name = "Frankfurt";
        editor.Host = "203.0.113.9";
        editor.Fingerprint = AgentKey;
        editor.Token = AgentToken;

        await editor.TestCommand.ExecuteAsync(null);

        var (endpoint, secrets) = Assert.Single(daemon.Probes);
        Assert.Equal(ProxyProtocol.YuraAgent, endpoint.Protocol);
        Assert.Equal(AgentKey, endpoint.Agent?.Fingerprint);
        Assert.Equal(AgentToken, secrets.Password);
    }

    [Fact]
    public void An_agent_exit_has_no_username_or_password_fields()
    {
        var (editor, _, _, _) = New();
        editor.BeginAddAgent();

        Assert.False(editor.UsesCredentials);
        Assert.True(editor.IsAgent);
        // And the default port is the agent's.
        Assert.Equal("7311", editor.Port);
    }

    [Fact]
    public void A_wg_configuration_pasted_into_the_same_box_still_makes_a_WireGuard_exit()
    {
        // One box, two kinds of paste: telling them apart is the code's job, not the user's.
        var (editor, _, _, _) = New();
        editor.BeginAddAgent();

        editor.ImportText = $"""
            [Interface]
            PrivateKey = {PrivateKey}
            Address = 10.8.0.7/32

            [Peer]
            PublicKey = {PeerKey}
            Endpoint = wg.example.net:51820
            """;
        editor.ImportFromTextCommand.Execute(null);

        Assert.Equal(ProxyProtocol.WireGuard, editor.Protocol);
        Assert.Equal("wg.example.net", editor.Host);
    }

    [Fact]
    public void A_new_form_shows_no_errors_until_something_is_touched()
    {
        var (editor, _, _, _) = New();

        editor.BeginAdd();

        Assert.Null(editor.NameError);
        Assert.Null(editor.HostError);
        Assert.Null(editor.PortError);
        Assert.False(editor.IsValid);
        Assert.False(editor.CanSave);
    }

    [Fact]
    public void Opening_the_form_again_after_abandoning_it_still_shows_no_errors()
    {
        // Clearing the fields for a new form counts as touching them, so a second Add would
        // otherwise open with "enter a name" already showing against an empty box.
        var (editor, _, _, _) = New();
        editor.BeginAdd();
        editor.Name = "half typed";
        editor.Host = "127.0.0.1";
        editor.CancelCommand.Execute(null);

        editor.BeginAdd();

        Assert.Null(editor.NameError);
        Assert.Null(editor.HostError);
        Assert.Equal(string.Empty, editor.Name);
    }

    [Fact]
    public void Opening_an_exit_for_editing_after_a_new_form_shows_no_errors_either()
    {
        var (editor, rules, _, _) = New();
        var proxy = new ProxyEndpoint { Id = Guid.NewGuid(), Name = "Home", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 1080 };
        rules.Proxies.Add(proxy);
        editor.BeginAddWireGuard();
        editor.Name = "abandoned";

        editor.BeginEdit(proxy);

        Assert.Null(editor.NameError);
        Assert.Null(editor.PrivateKeyError);
        Assert.Equal("Home", editor.Name);
        Assert.False(editor.IsWireGuard);
        Assert.True(editor.IsValid);
    }

    [Fact]
    public void Adding_a_wireguard_exit_opens_on_the_import_box_with_its_default_port()
    {
        var (editor, _, _, _) = New();

        editor.BeginAddWireGuard();

        Assert.Equal(ProxyProtocol.WireGuard, editor.Protocol);
        Assert.True(editor.ShowImport);
        Assert.True(editor.IsWireGuard);
        Assert.False(editor.UsesCredentials);
        Assert.Equal("51820", editor.Port);
        Assert.Null(editor.PrivateKeyError);
    }

    [Fact]
    public async Task Importing_a_configuration_fills_the_form_and_saves_the_keys_to_the_store()
    {
        var (editor, rules, secrets, _) = New();
        editor.BeginAddWireGuard();

        editor.ApplyImport($"""
            [Interface]
            PrivateKey = {PrivateKey}
            Address = 10.8.0.7/32
            DNS = 10.8.0.1
            MTU = 1380
            [Peer]
            PublicKey = {PeerKey}
            PresharedKey = {Psk}
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.net:51820
            PersistentKeepalive = 25
            """);

        Assert.Equal("vpn.example.net", editor.Host);
        Assert.Equal("51820", editor.Port);
        Assert.Equal("10.8.0.7/32", editor.Addresses);
        Assert.Equal("10.8.0.1", editor.DnsServers);
        Assert.Equal("1380", editor.Mtu);
        Assert.Equal("25", editor.Keepalive);
        // The keys must not be left sitting in the paste box after being taken from it.
        Assert.Equal(string.Empty, editor.ImportText);
        Assert.NotNull(editor.ImportMessage);

        editor.Name = "Frankfurt exit";
        Assert.True(editor.IsValid);
        await editor.SaveCommand.ExecuteAsync(null);

        var saved = Assert.Single(rules.Proxies);
        Assert.Equal(ProxyProtocol.WireGuard, saved.Protocol);
        Assert.Equal(PeerKey, saved.WireGuard!.PeerPublicKey);
        Assert.Equal(["10.8.0.7/32"], saved.WireGuard.Addresses);
        Assert.Equal(PrivateKey, secrets.Secrets[saved.Id.ToString()]);
        Assert.Equal(Psk, secrets.Secrets[$"{saved.Id}:psk"]);
        // Only references are on the endpoint; the keys themselves are in the store.
        Assert.Equal(saved.Id.ToString(), saved.PasswordRef);
        Assert.Equal($"{saved.Id}:psk", saved.WireGuard.PresharedKeyRef);
        Assert.False(editor.IsOpen);
    }

    [Fact]
    public void An_import_that_is_missing_fields_says_which_and_stays_invalid()
    {
        var (editor, _, _, _) = New();
        editor.BeginAddWireGuard();

        editor.ApplyImport($"[Interface]\nAddress = 10.8.0.7/32\n[Peer]\nPublicKey = {PeerKey}\n");

        Assert.Contains("still needed", editor.ImportMessage);
        Assert.NotNull(editor.PrivateKeyError);
        Assert.False(editor.IsValid);
    }

    [Fact]
    public void Text_that_is_not_a_configuration_changes_nothing_and_says_so()
    {
        var (editor, _, _, _) = New();
        editor.BeginAddWireGuard();
        editor.PeerPublicKey = PeerKey;

        editor.ApplyImport("just some text");

        Assert.Contains("does not look like", editor.ImportMessage);
        Assert.Equal(PeerKey, editor.PeerPublicKey);
    }

    [Fact]
    public void Ignored_directives_are_named_rather_than_dropped_silently()
    {
        var (editor, _, _, _) = New();
        editor.BeginAddWireGuard();

        editor.ApplyImport($"[Interface]\nPrivateKey = {PrivateKey}\nAddress = 10.0.0.2/32\nPostUp = rm -rf /\n[Peer]\nPublicKey = {PeerKey}\nEndpoint = h:1\n");

        Assert.Contains("Ignored", editor.ImportMessage);
        Assert.Contains("PostUp", editor.ImportMessage);
    }

    [Fact]
    public async Task Editing_an_exit_keeps_its_saved_key_when_the_box_is_left_blank()
    {
        var (editor, rules, secrets, _) = New();
        var id = Guid.NewGuid();
        await secrets.SetAsync(id.ToString(), PrivateKey);
        var exit = new ProxyEndpoint
        {
            Id = id, Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "h", Port = 51820,
            PasswordRef = id.ToString(),
            WireGuard = new WireGuardSettings { PeerPublicKey = PeerKey, Addresses = ["10.0.0.2/32"] },
        };
        rules.Proxies.Add(exit);

        editor.BeginEdit(exit);

        Assert.Equal(string.Empty, editor.PrivateKey);
        Assert.Contains("Saved", editor.PrivateKeyPlaceholder);
        Assert.True(editor.IsValid);

        editor.Name = "renamed";
        await editor.SaveCommand.ExecuteAsync(null);

        Assert.Equal(PrivateKey, secrets.Secrets[id.ToString()]);
        Assert.Equal(id.ToString(), Assert.Single(rules.Proxies).PasswordRef);
    }

    [Fact]
    public void Turning_a_proxy_into_an_exit_does_not_accept_its_password_as_a_private_key()
    {
        var (editor, rules, _, _) = New();
        var proxy = new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "socks", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 1080,
            PasswordRef = Guid.NewGuid().ToString(),
        };
        rules.Proxies.Add(proxy);

        editor.BeginEdit(proxy);
        editor.Protocol = ProxyProtocol.WireGuard;
        editor.PeerPublicKey = PeerKey;
        editor.Addresses = "10.0.0.2/32";

        // A stored proxy password is not a WireGuard key, and the daemon would refuse it.
        Assert.False(editor.IsValid);
        Assert.DoesNotContain("Saved", editor.PrivateKeyPlaceholder);

        editor.PrivateKey = PrivateKey;
        Assert.True(editor.IsValid);
    }

    [Fact]
    public async Task Testing_an_exit_hands_the_daemon_the_stored_keys_when_the_boxes_are_blank()
    {
        var (editor, rules, secrets, daemon) = New();
        var id = Guid.NewGuid();
        await secrets.SetAsync(id.ToString(), PrivateKey);
        await secrets.SetAsync($"{id}:psk", Psk);
        var exit = new ProxyEndpoint
        {
            Id = id, Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "h", Port = 51820,
            PasswordRef = id.ToString(),
            WireGuard = new WireGuardSettings
            {
                PeerPublicKey = PeerKey, Addresses = ["10.0.0.2/32"], PresharedKeyRef = $"{id}:psk",
            },
        };
        rules.Proxies.Add(exit);
        editor.BeginEdit(exit);

        await editor.TestCommand.ExecuteAsync(null);

        var (probed, probedSecrets) = Assert.Single(daemon.Probes);
        Assert.Equal(ProxyProtocol.WireGuard, probed.Protocol);
        Assert.Equal(PrivateKey, probedSecrets.Password);
        Assert.Equal(Psk, probedSecrets.PresharedKey);
    }

    [Fact]
    public void Every_wireguard_field_is_validated_with_its_own_message()
    {
        var (editor, _, _, _) = New();
        editor.BeginAddWireGuard();
        editor.Name = "exit";
        editor.Host = "h";
        editor.PrivateKey = PrivateKey;
        editor.PeerPublicKey = PeerKey;
        editor.Addresses = "10.0.0.2/32";
        Assert.True(editor.IsValid);

        editor.Addresses = "not-an-address";
        Assert.NotNull(editor.AddressesError);
        editor.Addresses = "10.0.0.2/32";

        editor.DnsServers = "resolver.local";
        Assert.NotNull(editor.DnsError);
        editor.DnsServers = string.Empty;

        editor.AllowedIps = "everything";
        Assert.NotNull(editor.AllowedIpsError);
        editor.AllowedIps = "0.0.0.0/0";

        editor.Mtu = "100";
        Assert.NotNull(editor.MtuError);
        editor.Mtu = string.Empty;

        editor.Keepalive = "-1";
        Assert.NotNull(editor.KeepaliveError);
        editor.Keepalive = "25";

        editor.PresharedKey = "short";
        Assert.NotNull(editor.PresharedKeyError);
        editor.PresharedKey = string.Empty;

        Assert.True(editor.IsValid);
    }

    [Fact]
    public void Switching_protocol_moves_the_default_port_but_never_one_the_user_set()
    {
        var (editor, _, _, _) = New();
        editor.BeginAdd();
        Assert.Equal("1080", editor.Port);

        editor.Protocol = ProxyProtocol.WireGuard;
        Assert.Equal("51820", editor.Port);

        editor.Port = "9999";
        editor.Protocol = ProxyProtocol.Socks5;
        Assert.Equal("9999", editor.Port);
    }

    [Fact]
    public async Task Removing_a_proxy_deletes_both_of_its_secrets()
    {
        var (editor, rules, secrets, _) = New();
        var id = Guid.NewGuid();
        await secrets.SetAsync(id.ToString(), PrivateKey);
        await secrets.SetAsync($"{id}:psk", Psk);
        var exit = new ProxyEndpoint
        {
            Id = id, Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "h", Port = 51820,
            PasswordRef = id.ToString(),
            WireGuard = new WireGuardSettings { PeerPublicKey = PeerKey, Addresses = ["10.0.0.2/32"], PresharedKeyRef = $"{id}:psk" },
        };
        rules.Proxies.Add(exit);
        editor.BeginEdit(exit);

        await editor.ConfirmRemoveCommand.ExecuteAsync(null);

        Assert.Empty(rules.Proxies);
        Assert.Empty(secrets.Secrets);
        Assert.False(editor.IsOpen);
    }

    [Fact]
    public void A_duplicate_name_is_refused_but_keeping_a_name_on_the_same_endpoint_is_not()
    {
        var (editor, rules, _, _) = New();
        var first = new ProxyEndpoint { Id = Guid.NewGuid(), Name = "Home", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 1 };
        rules.Proxies.Add(first);

        editor.BeginAdd();
        editor.Name = "home";
        editor.Host = "h2";
        Assert.NotNull(editor.NameError);
        Assert.False(editor.IsValid);

        editor.BeginEdit(first);
        editor.Name = "Home";
        Assert.Null(editor.NameError);
    }
}

/// <summary>The chain editor: hop order is the whole meaning of a chain, so it is what these check.</summary>
public sealed class ChainEditorTests
{
    private static (ChainEditorViewModel Editor, RuleStore Rules, ProxyEndpoint Exit, ProxyEndpoint Socks) New()
    {
        var rules = new RuleStore();
        var exit = new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "h", Port = 51820,
            WireGuard = new WireGuardSettings { PeerPublicKey = "k", Addresses = ["10.0.0.2/32"] },
        };
        var socks = new ProxyEndpoint { Id = Guid.NewGuid(), Name = "socks", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 1080 };
        rules.Proxies.Add(exit);
        rules.Proxies.Add(socks);
        return (new ChainEditorViewModel(rules), rules, exit, socks);
    }

    [Fact]
    public void A_chain_saves_its_hops_in_the_order_they_are_listed()
    {
        var (editor, rules, exit, socks) = New();
        editor.BeginAdd();
        editor.Name = "exit then socks";

        editor.ProxyToAdd = exit;
        editor.AddHopCommand.Execute(null);
        editor.ProxyToAdd = socks;
        editor.AddHopCommand.Execute(null);

        Assert.True(editor.IsValid);
        editor.SaveCommand.Execute(null);

        var chain = Assert.Single(rules.Chains);
        Assert.Equal([exit.Id, socks.Id], chain.Hops);
        Assert.False(editor.IsOpen);
    }

    [Fact]
    public void An_exit_below_the_first_hop_is_refused_with_the_reason()
    {
        var (editor, _, exit, socks) = New();
        editor.BeginAdd();
        editor.Name = "socks then exit";

        editor.ProxyToAdd = socks;
        editor.AddHopCommand.Execute(null);
        editor.ProxyToAdd = exit;
        editor.AddHopCommand.Execute(null);

        Assert.False(editor.IsValid);
        Assert.Contains("first hop", editor.HopsError);
        Assert.Contains("exit", editor.HopsError);

        // Moving it up makes the same two hops valid.
        editor.SelectedHop = editor.Hops[1];
        editor.MoveHopUpCommand.Execute(null);
        Assert.Null(editor.HopsError);
        Assert.True(editor.IsValid);
    }

    [Fact]
    public void Reordering_and_removing_hops_keeps_the_selection_usable()
    {
        var (editor, _, exit, socks) = New();
        editor.BeginAdd();
        editor.Name = "c";
        editor.ProxyToAdd = exit;
        editor.AddHopCommand.Execute(null);
        editor.ProxyToAdd = socks;
        editor.AddHopCommand.Execute(null);

        // The last added hop is selected, and it is the bottom one.
        Assert.Equal(socks.Id, editor.SelectedHop!.Endpoint.Id);
        Assert.False(editor.CanMoveDown);
        Assert.True(editor.CanMoveUp);

        editor.MoveHopUpCommand.Execute(null);
        Assert.Equal(socks.Id, editor.Hops[0].Endpoint.Id);
        Assert.False(editor.CanMoveUp);

        editor.RemoveHopCommand.Execute(null);
        Assert.Single(editor.Hops);
        Assert.NotNull(editor.SelectedHop);
        Assert.Equal(exit.Id, editor.SelectedHop!.Endpoint.Id);

        editor.RemoveHopCommand.Execute(null);
        Assert.Empty(editor.Hops);
        Assert.Null(editor.SelectedHop);
        Assert.False(editor.CanRemoveHop);
        Assert.NotNull(editor.HopsError);
    }

    [Fact]
    public void The_same_proxy_may_appear_twice_in_a_chain()
    {
        var (editor, rules, _, socks) = New();
        editor.BeginAdd();
        editor.Name = "twice";
        editor.ProxyToAdd = socks;
        editor.AddHopCommand.Execute(null);
        editor.AddHopCommand.Execute(null);

        editor.SaveCommand.Execute(null);

        Assert.Equal([socks.Id, socks.Id], Assert.Single(rules.Chains).Hops);
    }

    [Fact]
    public void Editing_a_chain_replaces_it_rather_than_adding_another()
    {
        var (editor, rules, exit, socks) = New();
        var chain = new ProxyChain { Id = Guid.NewGuid(), Name = "c", Hops = [exit.Id, socks.Id] };
        rules.PutChain(chain);

        editor.BeginEdit(chain);
        Assert.Equal(2, editor.Hops.Count);
        editor.Name = "renamed";
        editor.SaveCommand.Execute(null);

        var saved = Assert.Single(rules.Chains);
        Assert.Equal(chain.Id, saved.Id);
        Assert.Equal("renamed", saved.Name);
    }

    [Fact]
    public void A_saved_chain_can_be_removed_and_a_new_one_cannot()
    {
        var (editor, rules, _, socks) = New();
        var chain = new ProxyChain { Id = Guid.NewGuid(), Name = "c", Hops = [socks.Id] };
        rules.PutChain(chain);

        editor.BeginAdd();
        Assert.False(editor.CanRemove);

        editor.BeginEdit(chain);
        Assert.True(editor.CanRemove);
        editor.ConfirmRemoveCommand.Execute(null);

        Assert.Empty(rules.Chains);
        Assert.False(editor.IsOpen);
    }
}

/// <summary>
/// The page that hosts the two editors: which one is open, and which row is highlighted.
/// </summary>
/// <remarks>
/// There is one editor panel and two lists, so the selection has to be the single source of
/// truth for what is being edited. A highlighted row with a different endpoint in the editor
/// is the defect these exist to prevent.
/// </remarks>
public sealed class ProxiesPageTests
{
    private static (ProxiesPageViewModel Page, RuleStore Rules, ProxyEndpoint A, ProxyEndpoint B) New()
    {
        var rules = new RuleStore();
        var a = new ProxyEndpoint { Id = Guid.NewGuid(), Name = "A", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 1 };
        var b = new ProxyEndpoint { Id = Guid.NewGuid(), Name = "B", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 2 };
        rules.Proxies.Add(a);
        rules.Proxies.Add(b);
        return (new ProxiesPageViewModel(rules, new RecordingDaemonClient(), new FakeSecretStore()), rules, a, b);
    }

    [Fact]
    public void The_lists_mirror_the_store()
    {
        var (page, rules, _, _) = New();

        Assert.Equal(2, page.Proxies.Count);
        Assert.True(page.HasProxies);
        Assert.False(page.HasChains);
        Assert.True(page.CanAddChain);

        rules.PutChain(new ProxyChain { Id = Guid.NewGuid(), Name = "c", Hops = [rules.Proxies[0].Id] });
        Assert.True(page.HasChains);
        Assert.Single(page.Chains);
    }

    [Fact]
    public void Selecting_a_row_opens_it_and_the_selection_stays_put()
    {
        var (page, _, a, b) = New();

        page.SelectedProxy = page.Proxies[1];

        Assert.True(page.Editor.IsOpen);
        Assert.True(page.IsAnyEditorOpen);
        Assert.Equal("B", page.Editor.Name);
        // The highlighted row is still the one the editor is showing.
        Assert.Equal(b.Id, page.SelectedProxy!.Id);

        page.SelectedProxy = page.Proxies[0];
        Assert.Equal("A", page.Editor.Name);
        Assert.Equal(a.Id, page.SelectedProxy!.Id);
    }

    [Fact]
    public void Selecting_a_chain_closes_the_proxy_editor_and_clears_its_selection()
    {
        var (page, rules, _, _) = New();
        rules.PutChain(new ProxyChain { Id = Guid.NewGuid(), Name = "c", Hops = [rules.Proxies[0].Id] });
        page.SelectedProxy = page.Proxies[0];

        page.SelectedChain = page.Chains[0];

        Assert.True(page.ChainEditor.IsOpen);
        Assert.False(page.Editor.IsOpen);
        Assert.Null(page.SelectedProxy);
        Assert.NotNull(page.SelectedChain);
    }

    [Fact]
    public void Adding_something_new_takes_the_panel_from_whatever_was_selected()
    {
        var (page, _, _, _) = New();
        page.SelectedProxy = page.Proxies[0];

        page.AddWireGuardCommand.Execute(null);

        Assert.Null(page.SelectedProxy);
        Assert.True(page.Editor.IsOpen);
        Assert.True(page.Editor.IsWireGuard);

        page.AddChainCommand.Execute(null);
        Assert.True(page.ChainEditor.IsOpen);
        Assert.False(page.Editor.IsOpen);
        Assert.Null(page.SelectedChain);
    }

    [Fact]
    public void Closing_an_editor_leaves_no_row_highlighted()
    {
        var (page, _, _, _) = New();
        page.SelectedProxy = page.Proxies[0];

        page.Editor.CancelCommand.Execute(null);

        Assert.Null(page.SelectedProxy);
        Assert.False(page.IsAnyEditorOpen);
    }

    [Fact]
    public async Task Removing_the_selected_proxy_closes_the_editor_rather_than_leaving_it_on_nothing()
    {
        var (page, rules, _, _) = New();
        page.SelectedProxy = page.Proxies[1];

        await page.Editor.ConfirmRemoveCommand.ExecuteAsync(null);

        Assert.Single(rules.Proxies);
        Assert.Single(page.Proxies);
        Assert.Null(page.SelectedProxy);
        Assert.False(page.IsAnyEditorOpen);
    }

    [Fact]
    public void A_chain_row_reports_a_missing_hop_and_a_misplaced_exit()
    {
        var rules = new RuleStore();
        var exit = new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "h", Port = 51820,
            WireGuard = new WireGuardSettings { PeerPublicKey = "k", Addresses = ["10.0.0.2/32"] },
        };
        var socks = new ProxyEndpoint { Id = Guid.NewGuid(), Name = "socks", Protocol = ProxyProtocol.Socks5, Host = "h", Port = 1080 };
        rules.Proxies.Add(exit);
        rules.Proxies.Add(socks);
        var page = new ProxiesPageViewModel(rules, new RecordingDaemonClient(), new FakeSecretStore());

        rules.PutChain(new ProxyChain { Id = Guid.NewGuid(), Name = "backwards", Hops = [socks.Id, exit.Id] });
        var row = Assert.Single(page.Chains);
        Assert.True(row.HasProblem);
        Assert.Contains("first hop", row.Problem);
        Assert.Equal("socks → exit", row.HopsDisplay);

        rules.PutChain(new ProxyChain { Id = row.Id, Name = "gone", Hops = [socks.Id, Guid.NewGuid()] });
        Assert.Contains("no longer exists", page.Chains[0].Problem);
        Assert.Equal("socks → ?", page.Chains[0].HopsDisplay);

        // Removing a hop's proxy rewrites the chain rather than leaving a dangling id.
        rules.PutChain(new ProxyChain { Id = row.Id, Name = "fine", Hops = [exit.Id, socks.Id] });
        Assert.False(page.Chains[0].HasProblem);
        rules.RemoveProxy(exit.Id);
        Assert.Equal("socks", page.Chains[0].HopsDisplay);
        Assert.False(page.Chains[0].HasProblem);
    }

    [Fact]
    public void A_wireguard_row_says_the_tunnel_state_is_unknown_until_the_daemon_answers()
    {
        var rules = new RuleStore();
        rules.Proxies.Add(new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "exit", Protocol = ProxyProtocol.WireGuard, Host = "h", Port = 51820,
            WireGuard = new WireGuardSettings { PeerPublicKey = "k", Addresses = ["10.0.0.2/32"] },
        });
        var page = new ProxiesPageViewModel(rules, new RecordingDaemonClient(), new FakeSecretStore());

        var row = Assert.Single(page.Proxies);
        Assert.True(row.IsWireGuard);
        Assert.True(row.ShowState);
        Assert.False(row.IsExitUp);
        Assert.False(row.IsExitDown);
        Assert.Contains("unknown", row.StateText);

        row.UpdateTunnel(new TunnelStatus(row.Id, "exit", "yura-wg0", true, null,
            DateTimeOffset.UtcNow.AddSeconds(-20), RxBytes: 2048, TxBytes: 1024, Endpoint: "h:51820"));
        Assert.True(row.IsExitUp);
        Assert.Contains("20 s ago", row.StateText);
        Assert.Contains("1 KB", row.StateText);

        row.UpdateTunnel(new TunnelStatus(row.Id, "exit", null, false, "the key is wrong", null, 0, 0, null));
        Assert.False(row.IsExitUp);
        Assert.True(row.IsExitDown);
        Assert.Contains("the key is wrong", row.StateText);

        // Up but never handshaken is neither: the interface exists, the peer has not answered.
        row.UpdateTunnel(new TunnelStatus(row.Id, "exit", "yura-wg0", true, null, null, 0, 0, "h:51820"));
        Assert.False(row.IsExitUp);
        Assert.False(row.IsExitDown);
        Assert.Contains("not answered", row.StateText);
    }

    [Fact]
    public void An_agent_row_says_what_the_session_is_doing()
    {
        var rules = new RuleStore();
        rules.Proxies.Add(new ProxyEndpoint
        {
            Id = Guid.NewGuid(), Name = "frankfurt", Protocol = ProxyProtocol.YuraAgent, Host = "203.0.113.9",
            Port = 7311, Agent = new AgentSettings { Fingerprint = "k" },
        });
        var page = new ProxiesPageViewModel(rules, new RecordingDaemonClient(), new FakeSecretStore());

        var row = Assert.Single(page.Proxies);
        Assert.True(row.IsAgent);
        Assert.True(row.ShowState);
        Assert.False(row.IsExitUp);
        Assert.False(row.IsExitDown);
        Assert.Contains("unknown", row.StateText);

        row.UpdateAgent(new AgentStatus(row.Id, "frankfurt", Connected: true, "frankfurt-1", "0.3.0",
            RoundTripMilliseconds: 11.4, Udp: true, Resolver: "127.0.0.53", Failure: null));
        Assert.True(row.IsExitUp);
        Assert.Contains("frankfurt-1", row.StateText);
        Assert.Contains("11.4 ms", row.StateText);
        Assert.Contains("UDP carried", row.StateText);

        // An agent that offers no UDP is up, and says so rather than looking identical.
        row.UpdateAgent(new AgentStatus(row.Id, "frankfurt", Connected: true, "frankfurt-1", "0.3.0",
            RoundTripMilliseconds: 11.4, Udp: false, Resolver: null, Failure: null));
        Assert.True(row.IsExitUp);
        Assert.Contains("no UDP", row.StateText);

        row.UpdateAgent(new AgentStatus(row.Id, "frankfurt", Connected: false, null, null, null, false, null,
            "the token was not accepted"));
        Assert.False(row.IsExitUp);
        Assert.True(row.IsExitDown);
        Assert.Contains("the token was not accepted", row.StateText);
    }

    [Fact]
    public void A_row_for_an_ordinary_proxy_has_no_state_line_at_all()
    {
        var (page, _, _, _) = New();

        var row = page.Proxies[0];
        Assert.False(row.IsWireGuard);
        Assert.False(row.IsAgent);
        Assert.False(row.ShowState);
        Assert.Equal(string.Empty, row.StateText);
        Assert.Equal("SOCKS5", row.ProtocolDisplay);
    }
}

/// <summary>
/// The sentences the Games page shows about what is actually happening to a game's traffic.
/// </summary>
/// <remarks>
/// These exist because of a real report: the page said a game was routing while its traffic
/// was going straight out. The state badge only ever meant "a rule is installed and the game
/// is running", which is not the same claim, and the difference had nowhere to be said.
/// </remarks>
public sealed class RoutingEvidenceTests
{
    private static ConnectionRecord Row(RouteObservation route, string remote = "203.0.113.9:443") => new()
    {
        Id = Guid.NewGuid().ToString(),
        Local = IPEndPoint.Parse("192.168.1.24:51544"),
        Remote = IPEndPoint.Parse(remote),
        Protocol = TransportProtocol.Tcp,
        State = ConnectionState.Established,
        Route = route,
    };

    [Fact]
    public void Connections_going_through_the_route_are_reported_as_such()
    {
        var (text, warning) = GamesPageViewModel.Summarise(
            [Row(RouteObservation.ConfirmedProxied), Row(RouteObservation.ConfirmedProxied)],
            "Frankfurt agent", patient: true);

        Assert.Contains("2", text);
        Assert.Contains("Frankfurt agent", text, StringComparison.Ordinal);
        // Something is working, so this is information rather than a warning.
        Assert.False(warning);
    }

    [Fact]
    public void A_game_talking_to_a_proxy_on_this_machine_is_named_as_the_reason()
    {
        // The case that produced the report: http_proxy was set in the environment, so the
        // game never left loopback, and loopback is the one thing Yura deliberately ignores.
        var (text, warning) = GamesPageViewModel.Summarise(
            [Row(RouteObservation.ConfirmedDirect, "127.0.0.1:8080")], "Frankfurt agent", patient: true);

        Assert.Contains("proxy on this machine", text, StringComparison.Ordinal);
        Assert.Contains("http_proxy", text, StringComparison.Ordinal);
        Assert.True(warning);
    }

    [Fact]
    public void Connections_older_than_the_route_are_distinguished_from_ones_avoiding_it()
    {
        var (text, warning) = GamesPageViewModel.Summarise(
            [Row(RouteObservation.PreExistingPreviousRoute), Row(RouteObservation.ConfirmedDirect)],
            "Frankfurt agent", patient: true);

        Assert.Contains("before the route started", text, StringComparison.Ordinal);
        Assert.Contains("directly", text, StringComparison.Ordinal);
        Assert.True(warning);
    }

    [Fact]
    public void Nothing_captured_yet_is_patient_first_and_then_says_so()
    {
        var (waiting, quiet) = GamesPageViewModel.Summarise([], "Frankfurt agent", patient: false);
        Assert.Contains("Waiting", waiting, StringComparison.Ordinal);
        Assert.False(quiet);

        var (reported, warning) = GamesPageViewModel.Summarise([], "Frankfurt agent", patient: true);
        Assert.Contains("Nothing from this game has been captured", reported, StringComparison.Ordinal);
        // And it names the three things that actually cause it.
        Assert.Contains("environment", reported, StringComparison.Ordinal);
        Assert.Contains("IPv6", reported, StringComparison.Ordinal);
        Assert.True(warning);
    }

    [Fact]
    public void Some_routed_and_some_not_reports_both_without_claiming_success()
    {
        var (text, warning) = GamesPageViewModel.Summarise(
            [Row(RouteObservation.ConfirmedProxied), Row(RouteObservation.ConfirmedDirect, "127.0.0.1:8080")],
            "Frankfurt agent", patient: true);

        Assert.Contains("1 connection(s) are going through", text, StringComparison.Ordinal);
        Assert.Contains("proxy on this machine", text, StringComparison.Ordinal);
        // Something is getting through, so it is not a warning — but both halves are stated.
        Assert.False(warning);
    }
}
