using Yura.Core.Games;

namespace Yura.Core.Tests;

/// <summary>
/// Steam's manifests are the only way to enumerate installed games without talking to
/// Steam, so these build a library on disk in the format Steam actually writes and check
/// what comes back — including the cases that would otherwise produce useless profiles.
/// </summary>
public sealed class SteamLibraryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "yura-steam-" + Guid.NewGuid().ToString("N"));

    private string Library(string? name = null)
    {
        var path = name is null ? Path.Combine(_root, "steamapps") : Path.Combine(_root, name, "steamapps");
        Directory.CreateDirectory(path);
        return path;
    }

    private static void WriteManifest(string library, string appId, string name, string installDir = "Game")
    {
        File.WriteAllText(Path.Combine(library, $"appmanifest_{appId}.acf"), $$"""
            "AppState"
            {
            	"appid"		"{{appId}}"
            	"Universe"		"1"
            	"name"		"{{name}}"
            	"StateFlags"		"4"
            	"installdir"		"{{installDir}}"
            	"SizeOnDisk"		"32212254720"
            }
            """);
    }

    /// <summary>Writes the current libraryfolders.vdf format: one block per library.</summary>
    private static void WriteLibraryFolders(string library, params string[] paths)
    {
        var entries = paths.Select((path, index) => $$"""
            	"{{index}}"
            	{
            		"path"		"{{path}}"
            		"label"		""
            		"apps"
            		{
            			"730"		"1234"
            		}
            	}
            """);

        File.WriteAllText(Path.Combine(library, "libraryfolders.vdf"),
            "\"libraryfolders\"\n{\n" + string.Join('\n', entries) + "\n}\n");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception e) when (e is DirectoryNotFoundException or IOException)
        {
        }
    }

    [Fact]
    public void Reads_installed_games_from_a_library()
    {
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2");
        WriteManifest(library, "39210", "FINAL FANTASY XIV Online");

        var games = SteamLibrary.Discover([_root]);

        Assert.Equal(2, games.Count);
        // Sorted by name, so the list does not reshuffle between scans.
        Assert.Equal("Counter-Strike 2", games[0].Name);
        Assert.Equal("730", games[0].SteamAppId);
        Assert.Equal(GameSource.Steam, games[0].Source);
    }

    [Fact]
    public void Ignores_runtimes_and_redistributables_which_are_apps_but_not_games()
    {
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2");
        WriteManifest(library, "2805730", "Steam Linux Runtime 3.0 (sniper)");
        WriteManifest(library, "2348590", "Proton 9.0");
        WriteManifest(library, "228980", "Steamworks Common Redistributables");

        var games = SteamLibrary.Discover([_root]);

        Assert.Equal("Counter-Strike 2", Assert.Single(games).Name);
    }

    [Fact]
    public void Follows_every_library_folder_not_just_the_last_one()
    {
        // The bug this test exists for: the vdf was flattened into a dictionary, so only the
        // last "path" survived and every library between the first and the last was dropped.
        // It takes three libraries to see it, which is why two were not enough.
        var primary = Library();
        WriteManifest(primary, "730", "Counter-Strike 2");

        var names = new[] { "second", "third", "fourth" };
        foreach (var (name, index) in names.Select((n, i) => (n, i)))
        {
            WriteManifest(Library(name), (600 + index).ToString(), $"Game {name}");
        }

        WriteLibraryFolders(primary, [_root, .. names.Select(n => Path.Combine(_root, n))]);

        var scan = SteamLibrary.Scan([_root]);

        Assert.Equal(4, scan.Libraries.Count);
        Assert.Empty(scan.Skipped);
        Assert.Equal(
            ["Counter-Strike 2", "Game fourth", "Game second", "Game third"],
            scan.Games.Select(g => g.Name).ToArray());
    }

    [Fact]
    public void Follows_the_older_flat_library_folders_format()
    {
        // Steam wrote libraries as plain pairs for years, and a library added back then is
        // still in the file.
        var primary = Library();
        WriteManifest(primary, "730", "Counter-Strike 2");
        WriteManifest(Library("elsewhere"), "548430", "Deep Rock Galactic");

        File.WriteAllText(Path.Combine(primary, "libraryfolders.vdf"), $$"""
            "libraryfolders"
            {
            	"TimeNextStatsReport"		"1700000000"
            	"ContentStatsID"		"-1234567890"
            	"1"		"{{Path.Combine(_root, "elsewhere")}}"
            }
            """);

        Assert.Contains("Deep Rock Galactic", SteamLibrary.Discover([_root]).Select(g => g.Name));
    }

    [Fact]
    public void A_library_folder_in_config_is_read_as_well_as_the_one_in_steamapps()
    {
        // Steam keeps a copy in config/; whichever one exists has to be read.
        var primary = Library();
        WriteManifest(primary, "730", "Counter-Strike 2");
        WriteManifest(Library("elsewhere"), "548430", "Deep Rock Galactic");

        Directory.CreateDirectory(Path.Combine(_root, "config"));
        WriteLibraryFolders(Path.Combine(_root, "config"), Path.Combine(_root, "elsewhere"));

        Assert.Equal(2, SteamLibrary.Discover([_root]).Count);
    }

    [Fact]
    public void A_library_Steam_lists_but_cannot_be_reached_is_reported_rather_than_ignored()
    {
        // An unmounted drive is the common case, and silence about it is what made a short
        // list look like a complete one.
        var primary = Library();
        WriteManifest(primary, "730", "Counter-Strike 2");
        var absent = Path.Combine(_root, "not-mounted");
        WriteLibraryFolders(primary, _root, absent);

        var scan = SteamLibrary.Scan([_root]);

        Assert.Equal("Counter-Strike 2", Assert.Single(scan.Games).Name);
        var skipped = Assert.Single(scan.Skipped);
        Assert.Equal(absent, skipped.Path);
        Assert.Equal(SkipReason.NotPresent, skipped.Reason);
    }

    [Fact]
    public void A_library_folder_without_a_steamapps_directory_says_so()
    {
        var primary = Library();
        var empty = Path.Combine(_root, "empty");
        Directory.CreateDirectory(empty);
        WriteLibraryFolders(primary, _root, empty);

        var scan = SteamLibrary.Scan([_root]);

        Assert.Equal(SkipReason.NoSteamApps, Assert.Single(scan.Skipped).Reason);
    }

    [Fact]
    public void The_same_directory_reached_two_ways_counts_once()
    {
        // ~/.steam/steam is a symlink to ~/.local/share/Steam on most installations, and both
        // are offered as roots. Counting both would report more libraries than exist.
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2");
        var link = Path.Combine(Path.GetTempPath(), "yura-steam-link-" + Guid.NewGuid().ToString("N"));
        Directory.CreateSymbolicLink(link, _root);

        try
        {
            var scan = SteamLibrary.Scan([_root, link]);

            Assert.Single(scan.Libraries);
            Assert.Single(scan.Games);
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public void The_same_game_in_two_libraries_is_listed_once()
    {
        var primary = Library();
        var secondary = Library("elsewhere");
        WriteManifest(primary, "730", "Counter-Strike 2");
        WriteManifest(secondary, "730", "Counter-Strike 2");

        var games = SteamLibrary.Discover([_root, Path.Combine(_root, "elsewhere")]);

        Assert.Single(games);
    }

    [Fact]
    public void A_depots_own_keys_cannot_stand_in_for_the_apps()
    {
        var library = Library();
        File.WriteAllText(Path.Combine(library, "appmanifest_730.acf"), """
            "AppState"
            {
            	"appid"		"730"
            	"name"		"Counter-Strike 2"
            	"InstalledDepots"
            	{
            		"731"
            		{
            			"manifest"		"6436761910375028561"
            			"name"		"Proton 9.0"
            			"appid"		"2348590"
            		}
            	}
            }
            """);

        var game = Assert.Single(SteamLibrary.Discover([_root]));

        // Had the nested name won, this game would have been filtered out as a runtime.
        Assert.Equal("Counter-Strike 2", game.Name);
        Assert.Equal("730", game.SteamAppId);
    }

    [Fact]
    public void A_games_identity_is_stable_across_scans_so_its_saved_route_survives()
    {
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2");

        var first = SteamLibrary.Discover([_root]);
        var second = SteamLibrary.Discover([_root]);

        Assert.Equal(first[0].Id, second[0].Id);
        Assert.NotEqual(Guid.Empty, first[0].Id);
        Assert.NotEqual(SteamLibrary.DeterministicId("730"), SteamLibrary.DeterministicId("731"));
    }

    [Fact]
    public void The_install_directory_is_recorded_only_when_it_is_actually_there()
    {
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2", installDir: "Counter-Strike Global Offensive");
        WriteManifest(library, "550", "Left 4 Dead 2", installDir: "Left 4 Dead 2");
        Directory.CreateDirectory(Path.Combine(library, "common", "Counter-Strike Global Offensive"));

        var games = SteamLibrary.Discover([_root]);

        var cs = games.Single(g => g.SteamAppId == "730");
        Assert.Equal(Path.Combine(library, "common", "Counter-Strike Global Offensive"), cs.InstallDirectory);
        // The manifest named a directory that is not there — a claim, so it is not made.
        Assert.Null(games.Single(g => g.SteamAppId == "550").InstallDirectory);
    }

    [Fact]
    public void A_discovered_game_has_nothing_to_match_on_yet_and_says_so()
    {
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2");

        var game = Assert.Single(SteamLibrary.Discover([_root]));

        // A manifest names an install directory, not a binary. Guessing one would produce a
        // rule that silently covers nothing, so the profile stays unroutable until the user
        // attaches it to a running process — or until one of the game's own binaries is seen.
        Assert.Null(game.ExecutablePath);
        Assert.False(game.IsRoutable);
        Assert.False(game.IsMeasurable);
    }

    [Fact]
    public void A_binary_inside_the_install_directory_belongs_to_that_game()
    {
        var game = new GameProfile
        {
            Id = Guid.NewGuid(),
            Name = "Counter-Strike 2",
            InstallDirectory = "/mnt/Game/SteamLibrary/steamapps/common/Counter-Strike Global Offensive",
            Source = GameSource.Steam,
        };

        Assert.True(game.MatchesInstalledPath(
            "/mnt/Game/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/game/bin/cs2"));
        // Proton reports a Windows path for the same file; the whole path still has to match.
        Assert.True(game.MatchesInstalledPath(
            @"Z:\mnt\Game\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\game\bin\cs2.exe"));

        Assert.False(game.MatchesInstalledPath(
            "/mnt/Game/SteamLibrary/steamapps/common/Euro Truck Simulator 2/bin/eurotrucks2"));
        // A sibling directory whose name merely starts the same must not match.
        Assert.False(game.MatchesInstalledPath(
            "/mnt/Game/SteamLibrary/steamapps/common/Counter-Strike Global Offensive Beta/cs2"));
        Assert.False(game.MatchesInstalledPath(null));
        Assert.False(new GameProfile { Id = Guid.NewGuid(), Name = "x", Source = GameSource.Manual }
            .MatchesInstalledPath("/anything"));
    }

    [Fact]
    public void A_missing_or_unreadable_library_yields_no_games_rather_than_an_error()
    {
        Assert.Empty(SteamLibrary.Discover([Path.Combine(_root, "does-not-exist")]));

        var library = Library();
        File.WriteAllText(Path.Combine(library, "appmanifest_1.acf"), "this is not a manifest");
        Assert.Empty(SteamLibrary.Discover([_root]));
    }

    [Fact]
    public void A_root_that_is_simply_not_installed_is_not_reported_as_a_problem()
    {
        // Every packaging of Steam is offered as a root; the ones that are not there are
        // normal and must not fill the page with warnings.
        var scan = SteamLibrary.Scan([
            Path.Combine(_root, "no-steam-here"),
            Path.Combine(_root, "nor-here"),
        ]);

        Assert.Empty(scan.Skipped);
        Assert.Empty(scan.Libraries);
    }
}
