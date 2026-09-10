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

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (DirectoryNotFoundException)
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
    public void Follows_library_folders_onto_other_drives()
    {
        var primary = Library();
        var secondary = Library("elsewhere");
        WriteManifest(primary, "730", "Counter-Strike 2");
        WriteManifest(secondary, "548430", "Deep Rock Galactic");

        File.WriteAllText(Path.Combine(primary, "libraryfolders.vdf"), $$"""
            "libraryfolders"
            {
            	"0"
            	{
            		"path"		"{{_root}}"
            		"label"		""
            	}
            	"1"
            	{
            		"path"		"{{Path.Combine(_root, "elsewhere")}}"
            		"label"		""
            	}
            }
            """);

        var games = SteamLibrary.Discover([_root]);

        Assert.Equal(2, games.Count);
        Assert.Contains("Deep Rock Galactic", games.Select(g => g.Name));
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
    public void A_discovered_game_has_nothing_to_match_on_yet_and_says_so()
    {
        var library = Library();
        WriteManifest(library, "730", "Counter-Strike 2");

        var game = Assert.Single(SteamLibrary.Discover([_root]));

        // A manifest names an install directory, not a binary. Guessing one would produce a
        // rule that silently covers nothing, so the profile stays unroutable until the user
        // attaches it to a running process.
        Assert.Null(game.ExecutablePath);
        Assert.False(game.IsRoutable);
        Assert.False(game.IsMeasurable);
    }

    [Fact]
    public void A_missing_or_unreadable_library_yields_no_games_rather_than_an_error()
    {
        Assert.Empty(SteamLibrary.Discover([Path.Combine(_root, "does-not-exist")]));

        var library = Library();
        File.WriteAllText(Path.Combine(library, "appmanifest_1.acf"), "this is not a manifest");
        Assert.Empty(SteamLibrary.Discover([_root]));
    }
}
