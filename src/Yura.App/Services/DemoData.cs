using Yura.App.ViewModels;
using Yura.Core.Games;
using Yura.Core.Ipc;
using Yura.Core.Net;
using Yura.Core.Processes;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>
/// Seeds the view models for design review only (<c>--demo</c>).
/// </summary>
/// <remarks>
/// Deliberately includes the awkward cases that break layouts and that a happy-path mock
/// would hide: a very long executable path, an IPv6 literal endpoint, a proxy that cannot
/// carry UDP, a chain, and a metric that has not been measured.
/// </remarks>
internal static class DemoData
{
    public static void Populate(ShellViewModel shell, string editor = "socks")
    {
        var socks = new ProxyEndpoint
        {
            Id = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000001"),
            Name = "Home server",
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = 1080,
            LastProbe = new ProxyProbeResult
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Reachable = true,
                HandshakeLatency = TimeSpan.FromMilliseconds(18),
                Udp = CapabilityState.Supported,
            },
        };

        // An IPv6 literal, to check that the authority column does not wrap or clip.
        var v6 = new ProxyEndpoint
        {
            Id = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000002"),
            Name = "Tokyo relay",
            Protocol = ProxyProtocol.Socks5,
            Host = "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            Port = 1080,
        };

        // An HTTP proxy: structurally unable to relay UDP, which the Games page must warn
        // about rather than silently failing to accelerate a UDP game.
        var http = new ProxyEndpoint
        {
            Id = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000003"),
            Name = "Corporate HTTP",
            Protocol = ProxyProtocol.Http,
            Host = "proxy.corp.example.com",
            Port = 8080,
            Username = "hakuu",
        };

        // A WireGuard exit: keys live in the secret store, so the demo endpoint only carries
        // the public half, exactly as a real one does.
        var wireguard = new ProxyEndpoint
        {
            Id = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000004"),
            Name = "Frankfurt exit",
            Protocol = ProxyProtocol.WireGuard,
            Host = "wg.example.net",
            Port = 51820,
            PasswordRef = "aaaaaaaa-0000-4000-8000-000000000004",
            WireGuard = new WireGuardSettings
            {
                PeerPublicKey = "n4rHz8mE4GmR7p8Jq2xZ0lWfD6h1vY3sQ9cK5tB2aU8=",
                Addresses = ["10.8.0.7/32"],
                DnsServers = ["10.8.0.1"],
                PersistentKeepalive = 25,
            },
        };

        // A Yura agent: the token is in the secret store, so the endpoint carries only the
        // pinned public key — exactly as a real one does.
        var agent = new ProxyEndpoint
        {
            Id = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000005"),
            Name = "Frankfurt agent",
            Protocol = ProxyProtocol.YuraAgent,
            Host = "203.0.113.9",
            Port = 7311,
            PasswordRef = "aaaaaaaa-0000-4000-8000-000000000005",
            Agent = new AgentSettings
            {
                Fingerprint = "qS3n8uG1xK0pZ7rJ4mW2cV5bT9hY6dL8aF1eR0sX4uY",
                AgentLabel = "frankfurt-1",
            },
        };

        shell.Rules.Proxies.Add(socks);
        shell.Rules.Proxies.Add(v6);
        shell.Rules.Proxies.Add(http);
        shell.Rules.Proxies.Add(wireguard);
        shell.Rules.Proxies.Add(agent);

        shell.Rules.Chains.Add(new ProxyChain
        {
            Id = Guid.Parse("cccccccc-0000-4000-8000-00000000000c"),
            Name = "Home then Tokyo",
            Hops = [socks.Id, v6.Id],
        });
        shell.Rules.Chains.Add(new ProxyChain
        {
            Id = Guid.Parse("cccccccc-0000-4000-8000-00000000000d"),
            Name = "Exit then Tokyo",
            Hops = [wireguard.Id, v6.Id],
        });

        shell.Games.LoadProfiles(
        [
            new GameProfile
            {
                Id = Guid.Parse("bbbbbbbb-0000-4000-8000-000000000001"),
                Name = "Counter-Strike 2",
                ExecutablePath = "/home/hakuu/.steam/steamapps/common/Counter-Strike Global Offensive/game/bin/linuxsteamrt64/cs2",
                SteamAppId = "730",
                Source = GameSource.Steam,
                RouteId = socks.Id,
                MeasurementHost = "162.254.192.71",
                MeasurementPort = 27015,
            },
            new GameProfile
            {
                Id = Guid.Parse("bbbbbbbb-0000-4000-8000-000000000002"),
                Name = "Final Fantasy XIV",
                WineTargetExecutable = "Z:\\home\\hakuu\\.local\\share\\Steam\\steamapps\\common\\FINAL FANTASY XIV Online\\game\\ffxiv_dx11.exe",
                SteamAppId = "39210",
                Source = GameSource.Steam,
            },
            // A game with nothing known about it yet, which is what a fresh Steam scan gives.
            new GameProfile
            {
                Id = Guid.Parse("bbbbbbbb-0000-4000-8000-000000000003"),
                Name = "Deep Rock Galactic",
                SteamAppId = "548430",
                Source = GameSource.Steam,
            },
        ],
        // The demo's own libraries, not this machine's: a capture shows the same games and the same
        // folders wherever it is taken, and nothing of the machine it was taken on.
        new SteamScan
        {
            Libraries = [new ScannedLibrary("/home/hakuu/.local/share/Steam", 3)],
            Skipped = [new SkippedLibrary("/mnt/games/SteamLibrary", SkipReason.NotPresent)],
        });

        // The process inspector only exists when something is selected, so a capture of the
        // Processes page without a selection shows an empty panel and proves nothing about
        // the layout of the part that does the work.
        shell.Processes.SelectedProcess = shell.Processes.Processes.FirstOrDefault();
        shell.Processes.SelectedProxy = shell.Rules.Proxies.FirstOrDefault();

        shell.Games.SelectedGame = shell.Games.Games.FirstOrDefault(g => g.Name.StartsWith("Counter", StringComparison.Ordinal));
        shell.Games.SelectedRoute = shell.Rules.FindRoute(socks.Id);
        // A NAT result too, and the case worth laying out: a home connection behind a NAT3, which
        // cannot reach players behind a NAT4, and a route that fixes it.
        shell.Games.DirectNat = new NatReportDto
        {
            Verdict = NatVerdict.Moderate,
            Mapping = NatMapping.EndpointIndependent,
            Filtering = NatFiltering.AddressAndPortDependent,
            MappedEndpoint = "203.0.113.44:51820",
            BehindNat = true,
            Servers = ["111.206.174.3:3478", "138.201.243.186:3478"],
            Diagnostics = "The far side sees 203.0.113.44:51820. Two different servers saw the same mapping, so it " +
                          "does not depend on the destination. Hole punching can work. An answer from another port " +
                          "of a host already sent to was kept out until this route had sent to that port itself, so " +
                          "only the exact address and port sent to can answer. Filtering was tested against " +
                          "111.206.174.3:3478, which can answer from 111.206.174.2:3479.",
        };
        shell.Games.RoutedNat = new NatReportDto
        {
            Verdict = NatVerdict.Open,
            Mapping = NatMapping.EndpointIndependent,
            Filtering = NatFiltering.EndpointIndependent,
            MappedEndpoint = "198.51.100.9:41003",
            BehindNat = false,
            Servers = ["111.206.174.3:3478", "138.201.243.186:3478"],
            Diagnostics = "The far side sees the route's own address and port, so nothing is " +
                          "translating it.",
        };
        shell.Games.LastNatTestUtc = DateTimeOffset.UtcNow;

        shell.Games.MeasurementTargetInput = "162.254.192.71:27015";
        shell.Games.EnterSimulatedSession(BoostState.Routing, TimeSpan.FromMinutes(7).Add(TimeSpan.FromSeconds(24)));

        // The session's monitor so far: the route steady near 46 ms, the direct path near 84 ms and
        // noisier, one short spike on the route, a few of its probes unanswered, and a stretch
        // where the direct path got worse. Seeded, so screenshots come out the same every time.
        var random = new Random(7);
        var now = DateTimeOffset.UtcNow;
        const int samples = 148;
        shell.Games.SeedHistory(Enumerable.Range(0, samples).Select(i =>
        {
            var at = now - TimeSpan.FromSeconds(3 * (samples - 1 - i));
            double? routed = i is 71 or 72 or 118 ? null : 44 + (random.NextDouble() * 5) + (i is >= 60 and <= 63 ? 22 : 0);
            double? direct = 78 + (random.NextDouble() * 16) + (i is >= 100 and <= 108 ? 30 : 0);
            return new LatencySample(at, routed, direct);
        }));
        shell.Games.MeasurementTarget = "162.254.192.71:27015";
        shell.Games.MeasurementMethod = "TCP connect";
        shell.Games.LastMeasurementUtc = DateTimeOffset.UtcNow;
        shell.Games.DirectLatency = new Metric(84.3, "ms");
        shell.Games.DirectJitter = new Metric(11.2, "ms");
        shell.Games.DirectLoss = new Metric(1.4, "%");
        shell.Games.RoutedLatency = new Metric(46.1, "ms");
        shell.Games.RoutedJitter = new Metric(3.7, "ms");
        // Left unmeasured on purpose: the UI must show "Not measured", not 0%.
        shell.Games.RoutedLoss = Metric.NotMeasured;

        // Rules that tell the precedence story the Rules page exists to explain: a process
        // selection above a game profile on the same game, a narrow manual rule, and one
        // disabled rule so all three states are visible at once.
        var cs2Instance = new RoutingRule
        {
            Id = Guid.Parse("eeee0001-0000-4000-8000-000000000001"),
            Order = 100,
            Name = "cs2 (pid 4821)",
            Origin = RuleOrigin.ProcessSelection,
            Lifetime = RuleLifetime.Instance,
            Process = new ProcessSelector
            {
                Kind = ProcessSelectorKind.Instance,
                Identity = new ProcessIdentity { Pid = 4821, StartTicks = 918_233, Uid = 1000, BootId = "demo" },
                Descendants = DescendantPolicy.IncludeFuture,
            },
            Action = new RuleAction.Proxy(socks.Id),
            CreatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-8),
            AppliedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-8),
        };

        var cs2Profile = new RoutingRule
        {
            Id = Guid.Parse("eeee0002-0000-4000-8000-000000000002"),
            Order = 300,
            Name = "Counter-Strike 2 (game boost)",
            Origin = RuleOrigin.GameProfile,
            Lifetime = RuleLifetime.Session,
            Process = new ProcessSelector
            {
                Kind = ProcessSelectorKind.ExecutablePath,
                ExecutablePath = "/home/hakuu/.steam/steamapps/common/Counter-Strike Global Offensive/game/bin/linuxsteamrt64/cs2",
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            },
            Action = new RuleAction.Chain(Guid.Parse("cccccccc-0000-4000-8000-00000000000c")),
            CreatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-7),
            AppliedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-7),
        };

        var firefox = new RoutingRule
        {
            Id = Guid.Parse("eeee0003-0000-4000-8000-000000000003"),
            Order = 500,
            Name = "firefox → *.example.com",
            Origin = RuleOrigin.Manual,
            Lifetime = RuleLifetime.Persistent,
            Process = new ProcessSelector { Kind = ProcessSelectorKind.ProcessName, ProcessName = "firefox" },
            Destination = new DestinationSelector
            {
                Hosts = [new HostPattern(HostMatchKind.Suffix, "example.com")],
                Ports = [PortRange.Single(443)],
                Protocol = TransportFilter.Tcp,
            },
            Action = new RuleAction.Proxy(http.Id),
            CreatedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
            AppliedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
        };

        // Pending: asked for, not yet confirmed by the daemon. A distinct state on purpose.
        var telemetry = new RoutingRule
        {
            Id = Guid.Parse("eeee0004-0000-4000-8000-000000000004"),
            Order = 501,
            Name = "Block outbound SMTP",
            Origin = RuleOrigin.Manual,
            Lifetime = RuleLifetime.Session,
            Process = new ProcessSelector { Kind = ProcessSelectorKind.ProcessName, ProcessName = "thunderbird" },
            Destination = new DestinationSelector { Ports = [PortRange.Single(25)] },
            Action = RuleAction.Block.Instance,
            CreatedAtUtc = DateTimeOffset.UtcNow.AddHours(-1),
        };

        var disabled = new RoutingRule
        {
            Id = Guid.Parse("eeee0005-0000-4000-8000-000000000005"),
            Order = 502,
            Name = "steam (all instances)",
            Enabled = false,
            Origin = RuleOrigin.ProcessSelection,
            Lifetime = RuleLifetime.Persistent,
            Process = new ProcessSelector { Kind = ProcessSelectorKind.ExecutablePath, ExecutablePath = "/usr/lib/steam/steam" },
            Action = new RuleAction.Proxy(v6.Id),
            CreatedAtUtc = DateTimeOffset.UtcNow.AddDays(-3),
        };

        shell.Rules.LoadPersisted([cs2Instance, cs2Profile, firefox, telemetry, disabled]);
        // LoadPersisted deliberately clears AppliedAtUtc, which is right at startup but not
        // here: these are meant to look like rules the daemon has confirmed.
        foreach (var applied in new[] { cs2Instance.Id, cs2Profile.Id, firefox.Id })
        {
            shell.Rules.MarkApplied(applied, DateTimeOffset.UtcNow);
        }

        shell.RulesPage.SelectedRule = shell.RulesPage.Rules.FirstOrDefault(r => r.Id == cs2Profile.Id);
        // Selected rather than edited directly: the editor follows the list selection, so
        // this is also what proves the highlighted row and the open editor agree.
        shell.Proxies.SelectedProxy = editor switch
        {
            "wireguard" => shell.Proxies.Proxies.FirstOrDefault(p => p.Id == wireguard.Id),
            "chain" => null,
            _ => shell.Proxies.Proxies.FirstOrDefault(p => p.Id == socks.Id),
        };
        if (editor == "chain")
        {
            shell.Proxies.SelectedChain = shell.Proxies.Chains.LastOrDefault();
        }
    }
}
