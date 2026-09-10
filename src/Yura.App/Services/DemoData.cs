using Yura.App.ViewModels;
using Yura.Core.Proxies;

namespace Yura.App.Services;

/// <summary>
/// Seeds the view models for design review only (<c>--demo</c>).
/// </summary>
/// <remarks>
/// Deliberately includes the awkward cases that break layouts and that a happy-path mock
/// would hide: a very long executable path, an IPv6 literal endpoint, a proxy that cannot
/// carry UDP, and a metric that has not been measured.
/// </remarks>
internal static class DemoData
{
    public static void Populate(ShellViewModel shell)
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

        shell.Rules.Proxies.Add(socks);
        shell.Rules.Proxies.Add(v6);
        shell.Rules.Proxies.Add(http);

        shell.Games.Games.Add(new GameEntry(
            "cs2", "Counter-Strike 2", "/home/hakuu/.steam/steamapps/common/Counter-Strike Global Offensive/game/bin/linuxsteamrt64/cs2", "730"));
        shell.Games.Games.Add(new GameEntry(
            "ffxiv", "Final Fantasy XIV",
            "/home/hakuu/.local/share/Steam/steamapps/common/FINAL FANTASY XIV Online/game/ffxiv_dx11.exe", "39210"));
        shell.Games.Games.Add(new GameEntry("minecraft", "Minecraft", "/usr/bin/minecraft-launcher", null));

        shell.Games.SelectedGame = shell.Games.Games[0];
        shell.Games.SelectedRoute = socks;
        shell.Games.EnterSimulatedSession(BoostState.Routing, TimeSpan.FromMinutes(7).Add(TimeSpan.FromSeconds(24)));
        shell.Games.MeasurementTarget = "162.254.192.71:27015";
        shell.Games.LastMeasurementUtc = DateTimeOffset.UtcNow;
        shell.Games.DirectLatency = new Metric(84.3, "ms");
        shell.Games.DirectJitter = new Metric(11.2, "ms");
        shell.Games.DirectLoss = new Metric(1.4, "%");
        shell.Games.RoutedLatency = new Metric(46.1, "ms");
        shell.Games.RoutedJitter = new Metric(3.7, "ms");
        // Left unmeasured on purpose: the UI must show "Not measured", not 0%.
        shell.Games.RoutedLoss = Metric.NotMeasured;

        shell.Proxies.Editor.BeginEdit(socks);
    }
}
