using Yura.Core.Games;
using Yura.Core.Ipc;
using Yura.Core.Processes;
using Yura.Core.Rules;

namespace Yura.Core.Tests;

/// <summary>
/// A Steam game matched by Steam's launch of it, and a Wine program by the wineserver that makes
/// its sockets: what Helldivers 2's Easy Anti-Cheat update showed neither was.
/// </summary>
public sealed class SteamLaunchTests
{
    // Steam's launch of Helldivers 2 after the update, as /proc showed it on 2026-10-24.
    private static readonly string[] HelldiversLaunch =
    [
        "/home/hakuu/.local/share/Steam/ubuntu12_32/reaper", "SteamLaunch", "AppId=553850", "--",
        "/home/hakuu/.local/share/Steam/steamapps/common/SteamLinuxRuntime_4/_v2-entry-point", "--verb=waitforexitandrun", "--",
        "/home/hakuu/.local/share/Steam/compatibilitytools.d/GE-Proton11-9-x86_64/proton", "waitforexitandrun",
        "/mnt/Game/SteamLibrary/steamapps/common/Helldivers 2/start_protected_game.exe",
        "--bundle-dir", "data", "--release", "+connect_lobby", "000",
    ];

    private const string Preloader =
        "/home/hakuu/.local/share/Steam/compatibilitytools.d/GE-Proton11-9-x86_64/files/lib/wine/i386-unix/wine64-preloader";

    private static ProcessSnapshot Process(int pid, string path, IReadOnlyList<string> argv, string? steamAppId = "553850") => new()
    {
        Identity = new ProcessIdentity { Pid = pid, StartTicks = (ulong)pid, Uid = 1000, BootId = "b" },
        Name = Path.GetFileName(path),
        ExecutablePath = path,
        ExecutablePathState = ExecutablePathState.Resolved,
        ParentPid = 1,
        UserName = "hakuu",
        CommandLine = argv,
        SteamAppId = steamAppId,
    };

    private static readonly ProcessSnapshot Reaper = Process(95712, HelldiversLaunch[0], HelldiversLaunch);

    // The game itself, as the anti-cheat's launcher starts it: a Wine process on the library drive.
    private static readonly ProcessSnapshot Game = Process(95967, Preloader,
        [@"S:\steamapps\common\Helldivers 2\bin/helldivers2.exe", "--bundle-dir", "data", "--release", "+connect_lobby", "000"]);

    [Fact]
    public void Steams_launch_names_the_app_it_starts()
    {
        Assert.Equal("553850", SteamLaunch.AppIdOf(HelldiversLaunch));
        Assert.Equal("553850", SteamLaunch.AppIdOf(string.Join('\0', HelldiversLaunch) + "\0"));
        Assert.Equal("553850", Reaper.SteamLaunchAppId);
    }

    [Fact]
    public void Nothing_but_Steams_launch_is_taken_for_one()
    {
        // Every process of the game carries the app id in its environment; only the launch names
        // it in its arguments.
        Assert.Null(Game.SteamLaunchAppId);
        Assert.Null(SteamLaunch.AppIdOf(["/usr/bin/python3", "proton", "AppId=553850"]));
        // What follows "--" is the game's own command line, which could say anything.
        Assert.Null(SteamLaunch.AppIdOf(["reaper", "SteamLaunch", "--", "game", "AppId=553850"]));
        Assert.Null(SteamLaunch.AppIdOf(["reaper", "SteamLaunch", "AppId=", "--"]));
        Assert.Null(SteamLaunch.AppIdOf(["reaper", "SteamLaunch", "AppId=55 3850", "--"]));
        Assert.Null(SteamLaunch.AppIdOf(["reaper"]));
        Assert.Null(SteamLaunch.AppIdOf("/usr/bin/bash\0-c\0SteamLaunch\0"));
    }

    [Fact]
    public void Steams_launcher_is_known_by_its_file_name()
    {
        Assert.True(SteamLaunch.IsLauncher("/home/hakuu/.local/share/Steam/ubuntu12_32/reaper"));
        Assert.False(SteamLaunch.IsLauncher("/usr/bin/reaper2"));
        Assert.False(SteamLaunch.IsLauncher(null));
    }

    [Fact]
    public void A_steam_app_rule_matches_its_launch_and_nothing_under_it_in_its_own_right()
    {
        var selector = new ProcessSelector { Kind = ProcessSelectorKind.SteamApp, SteamAppId = "553850" };

        Assert.True(selector.MatchesProcess(Reaper));
        // The rest of the game is covered as the launch's descendants, not by carrying the app id.
        Assert.False(selector.MatchesProcess(Game));
        Assert.False(new ProcessSelector { Kind = ProcessSelectorKind.SteamApp, SteamAppId = "1245620" }.MatchesProcess(Reaper));
        Assert.False(new ProcessSelector { Kind = ProcessSelectorKind.SteamApp }.MatchesProcess(Reaper));
        Assert.Equal("Steam app 553850", selector.Describe());
    }

    [Fact]
    public void A_steam_app_rule_crosses_the_wire_and_cannot_cross_it_without_its_app_id()
    {
        var rule = new RoutingRule
        {
            Id = Guid.NewGuid(),
            Order = 400,
            Name = "HELLDIVERS 2 (game boost)",
            Origin = RuleOrigin.GameProfile,
            Lifetime = RuleLifetime.Session,
            Process = new ProcessSelector
            {
                Kind = ProcessSelectorKind.SteamApp,
                SteamAppId = "553850",
                Descendants = DescendantPolicy.IncludeExistingAndFuture,
            },
            Destination = DestinationSelector.Any,
            Action = RuleAction.Direct.Instance,
            CreatedAtUtc = DateTimeOffset.UnixEpoch,
        };

        var dto = RuleDto.From(rule);
        var json = System.Text.Json.JsonSerializer.Serialize(dto, IpcJsonContext.Default.RuleDto);
        var back = System.Text.Json.JsonSerializer.Deserialize(json, IpcJsonContext.Default.RuleDto)!.ToRule();

        Assert.Contains("\"processKind\":\"steamApp\"", json, StringComparison.Ordinal);
        Assert.Equal(rule.Process, back.Process);

        var broken = System.Text.Json.JsonSerializer.Deserialize(
            json.Replace("\"steamAppId\":\"553850\"", "\"steamAppId\":null", StringComparison.Ordinal),
            IpcJsonContext.Default.RuleDto)!;
        Assert.Throws<InvalidDataException>(broken.ToRule);
    }

    [Fact]
    public void A_steam_game_is_matched_by_its_launch_and_a_game_added_by_hand_by_its_executable()
    {
        var steam = new GameProfile { Id = Guid.NewGuid(), Name = "HELLDIVERS 2", SteamAppId = "553850", Source = GameSource.Steam };
        var byHand = steam with
        {
            Source = GameSource.Manual,
            ExecutablePath = Preloader,
            WineTargetExecutable = @"S:\steamapps\common\Helldivers 2\bin/helldivers2.exe",
        };

        Assert.Equal("553850", steam.SteamLaunchAppId);
        Assert.True(steam.IsRoutable);
        Assert.Null(byHand.SteamLaunchAppId);

        // What a profile used to remember of Steam's launch: its launcher, and the executable
        // Steam was told to start, which the update changed.
        var remembered = byHand with
        {
            ExecutablePath = HelldiversLaunch[0],
            WineTargetExecutable = "/mnt/Game/SteamLibrary/steamapps/common/Helldivers 2/bin/helldivers2.exe",
        };
        Assert.Equal("553850", remembered.SteamLaunchAppId);

        Assert.Equal("553850", (byHand with { ExecutablePath = null, WineTargetExecutable = null }).SteamLaunchAppId);
        Assert.Null((steam with { SteamAppId = null }).SteamLaunchAppId);
    }

    // -- Wine -------------------------------------------------------------------------

    [Fact]
    public void A_wine_program_is_one_of_wines_loaders_running_and_its_server_is_the_wineserver()
    {
        Assert.True(WineProcess.IsLoader(Preloader));
        Assert.True(WineProcess.IsLoader("/usr/lib/wine/x86_64-unix/wine-preloader"));
        Assert.True(WineProcess.IsLoader("/usr/bin/wine"));
        Assert.True(WineProcess.IsLoader("/opt/wine/bin/wine64"));
        // Steam's launcher and Proton's script carry the game's .exe in their arguments; neither
        // runs a Windows program.
        Assert.False(WineProcess.IsLoader(HelldiversLaunch[0]));
        Assert.False(WineProcess.IsLoader("/usr/bin/python3.13"));
        Assert.False(WineProcess.IsLoader("/usr/bin/wineserver"));
        Assert.False(WineProcess.IsLoader(null));

        Assert.True(WineProcess.IsServer("/home/hakuu/.local/share/Steam/compatibilitytools.d/GE-Proton11-9-x86_64/files/bin/wineserver"));
        Assert.False(WineProcess.IsServer(Preloader));
    }

    [Fact]
    public void A_prefix_is_found_as_wine_finds_it()
    {
        // Proton writes it with a trailing slash; Wine strips it before looking for the server.
        Assert.Equal("/home/hakuu/Steam-NTFS/compatdata/553850/pfx",
            WineProcess.PrefixFrom("/home/hakuu/Steam-NTFS/compatdata/553850/pfx/", "/home/hakuu"));
        Assert.Equal("/home/hakuu/.wine", WineProcess.PrefixFrom(null, "/home/hakuu/"));
        Assert.Equal("/home/hakuu/.wine", WineProcess.PrefixFrom(string.Empty, "/home/hakuu"));
        Assert.Null(WineProcess.PrefixFrom(null, null));

        Assert.Equal("/tmp/pfx", WineProcess.PrefixFromEnvironment("HOME=/home/hakuu\0WINEPREFIX=/tmp/pfx//\0SteamAppId=553850\0"));
        Assert.Equal("/root/.wine", WineProcess.PrefixFromEnvironment("PATH=/usr/bin\0HOME=/root\0"));
    }

    [Fact]
    public void The_prefix_of_a_running_process_is_read_from_its_environment_on_request()
    {
        var start = new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-c", "sleep 30; :"]) { UseShellExecute = false };
        start.Environment["WINEPREFIX"] = "/tmp/yura-test-prefix/";
        using var child = System.Diagnostics.Process.Start(start)!;
        try
        {
            Assert.Equal("/tmp/yura-test-prefix", ProcProcessSource.ReadWinePrefix(child.Id));
        }
        finally
        {
            child.Kill(entireProcessTree: true);
        }

        Assert.Null(ProcProcessSource.ReadWinePrefix(int.MaxValue));
    }
}
