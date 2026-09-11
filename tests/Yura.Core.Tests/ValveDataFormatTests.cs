using Yura.Core.Games;

namespace Yura.Core.Tests;

/// <summary>
/// Steam's KeyValues format is undocumented, so these pin the parts Yura depends on against
/// text in the shape Steam actually writes — including the parts a dictionary would lose.
/// </summary>
public sealed class ValveDataFormatTests
{
    [Fact]
    public void Reads_nested_blocks_and_their_values()
    {
        var document = ValveDataFormat.Parse("""
            "AppState"
            {
            	"appid"		"730"
            	"name"		"Counter-Strike 2"
            	"InstalledDepots"
            	{
            		"731"
            		{
            			"manifest"		"6436761910375028561"
            		}
            	}
            }
            """);

        var state = Assert.Single(document.Blocks);
        Assert.Equal("AppState", state.Key);
        Assert.Equal("730", state["appid"]);
        Assert.Equal("Counter-Strike 2", state["name"]);
        Assert.Equal("731", Assert.Single(Assert.Single(state.Blocks).Blocks).Key);
    }

    [Fact]
    public void A_nested_key_does_not_shadow_the_one_above_it()
    {
        // Flattening this file would let a depot's name stand in for the game's, which is the
        // whole reason nesting is modelled rather than collapsed.
        var document = ValveDataFormat.Parse("""
            "AppState"
            {
            	"name"		"Euro Truck Simulator 2"
            	"UserConfig"
            	{
            		"name"		"something else"
            		"appid"		"999"
            	}
            }
            """);

        var state = Assert.Single(document.Blocks);
        Assert.Equal("Euro Truck Simulator 2", state["name"]);
        Assert.Null(state["appid"]);
    }

    [Fact]
    public void Repeated_keys_are_all_readable()
    {
        // libraryfolders.vdf repeats "path" once per library; losing the repeats is exactly
        // the bug this parser exists to rule out.
        var document = ValveDataFormat.Parse("""
            "libraryfolders"
            {
            	"0" { "path" "/one" }
            	"1" { "path" "/two" }
            	"2" { "path" "/three" }
            }
            """);

        var libraries = Assert.Single(document.Blocks);
        Assert.Equal(["/one", "/two", "/three"], libraries.Blocks.Select(b => b["path"]).ToArray());
    }

    [Fact]
    public void Keys_are_matched_without_regard_to_case()
    {
        // Steam itself is inconsistent: "universe" in one manifest, "Universe" in the next.
        var state = Assert.Single(ValveDataFormat.Parse("\"AppState\" { \"AppID\" \"550\" }").Blocks);

        Assert.Equal("550", state["appid"]);
    }

    [Fact]
    public void Comments_and_escapes_are_handled()
    {
        var document = ValveDataFormat.Parse("""
            // a comment Steam wrote
            "libraryfolders"
            {
            	"0"
            	{
            		"path"		"D:\\SteamLibrary"	// and a trailing one
            	}
            }
            """);

        Assert.Equal(@"D:\SteamLibrary", Assert.Single(Assert.Single(document.Blocks).Blocks)["path"]);
    }

    [Fact]
    public void Unquoted_tokens_and_the_old_flat_form_are_read()
    {
        var document = ValveDataFormat.Parse("""
            "libraryfolders"
            {
            	"TimeNextStatsReport"		"1234"
            	"1"		"/mnt/games"
            	"2"		"/mnt/more"
            }
            """);

        var libraries = Assert.Single(document.Blocks);
        Assert.Equal("/mnt/games", libraries["1"]);
        Assert.Equal("/mnt/more", libraries["2"]);
    }

    [Fact]
    public void Malformed_input_yields_what_was_readable_rather_than_throwing()
    {
        // Never throw: the caller's job is to list fewer games, never to fail.
        Assert.Empty(ValveDataFormat.Parse("this is not a manifest").Blocks);
        Assert.Empty(ValveDataFormat.Parse(string.Empty).Children);

        var truncated = ValveDataFormat.Parse("\"AppState\" { \"appid\" \"1\" ");
        Assert.Equal("1", Assert.Single(truncated.Blocks)["appid"]);

        // Unbalanced closing braces stop the document instead of walking off the stack.
        Assert.Empty(ValveDataFormat.Parse("} } }").Blocks);
    }

    [Fact]
    public void Nesting_is_bounded_so_a_hostile_file_cannot_exhaust_the_stack()
    {
        var deep = string.Concat(Enumerable.Repeat("\"a\" {", 5000)) + string.Concat(Enumerable.Repeat("}", 5000));

        var document = ValveDataFormat.Parse(deep);

        // It stops descending rather than overflowing; what it read so far is still a document.
        Assert.Single(document.Blocks);
    }

    [Fact]
    public void A_missing_file_reads_as_null_rather_than_throwing()
    {
        Assert.Null(ValveDataFormat.Read(Path.Combine(Path.GetTempPath(), $"yura-absent-{Guid.NewGuid():N}.vdf")));
    }
}
