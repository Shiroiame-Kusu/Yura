using System.Globalization;
using System.Text.RegularExpressions;

namespace Yura.Core.Games;

/// <summary>
/// Finds installed Steam games by reading the library's own manifests.
/// </summary>
/// <remarks>
/// Steam records every installed app in <c>steamapps/appmanifest_&lt;id&gt;.acf</c>, a simple
/// keyed-value format, and every library root in <c>libraryfolders.vdf</c>. Reading those is
/// the only way to enumerate games without talking to Steam itself, and it degrades well: a
/// missing or unreadable file means fewer games listed, never an error.
///
/// Nothing here guesses an executable. A manifest names the install directory, not the binary,
/// and picking the wrong binary would produce a rule that silently covers nothing — so the
/// profile is created without a path and the UI asks the user to attach the running game,
/// which is also how the per-instance requirement is honoured.
/// </remarks>
public static partial class SteamLibrary
{
    [GeneratedRegex("\"([^\"]+)\"\\s*\"([^\"]*)\"", RegexOptions.Compiled)]
    private static partial Regex KeyValue();

    /// <summary>Candidate Steam roots, in the order they are usually found on Linux.</summary>
    public static IReadOnlyList<string> DefaultRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return
        [
            Path.Combine(home, ".steam", "steam"),
            Path.Combine(home, ".local", "share", "Steam"),
            Path.Combine(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam"),
        ];
    }

    /// <summary>Reads every installed app from every readable library, deduplicated by app id.</summary>
    public static IReadOnlyList<GameProfile> Discover(IEnumerable<string>? roots = null)
    {
        var found = new Dictionary<string, GameProfile>(StringComparer.Ordinal);

        foreach (var library in LibraryPaths(roots ?? DefaultRoots()))
        {
            IEnumerable<string> manifests;
            try
            {
                manifests = Directory.EnumerateFiles(library, "appmanifest_*.acf");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var manifest in manifests)
            {
                var fields = ReadFields(manifest);
                if (fields is null ||
                    !fields.TryGetValue("appid", out var appId) ||
                    !fields.TryGetValue("name", out var name) ||
                    name.Length == 0)
                {
                    continue;
                }

                // Steam's own runtime and compatibility tools are installed as apps but are
                // not games, and offering to accelerate them would be noise.
                if (IsToolDepot(name))
                {
                    continue;
                }

                found.TryAdd(appId, new GameProfile
                {
                    // Derived from the app id so the same game keeps its identity, and its
                    // saved route, across restarts and library moves.
                    Id = DeterministicId(appId),
                    Name = name,
                    SteamAppId = appId,
                    Source = GameSource.Steam,
                });
            }
        }

        return found.Values.OrderBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
    }

    private static IEnumerable<string> LibraryPaths(IEnumerable<string> roots)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var root in roots)
        {
            var primary = Path.Combine(root, "steamapps");
            if (Directory.Exists(primary) && seen.Add(primary))
            {
                yield return primary;
            }

            // Additional libraries on other drives are listed here.
            foreach (var vdf in new[]
                     {
                         Path.Combine(root, "steamapps", "libraryfolders.vdf"),
                         Path.Combine(root, "config", "libraryfolders.vdf"),
                     })
            {
                var fields = ReadFields(vdf);
                if (fields is null)
                {
                    continue;
                }

                foreach (var (key, value) in fields)
                {
                    if (!string.Equals(key, "path", StringComparison.OrdinalIgnoreCase) || value.Length == 0)
                    {
                        continue;
                    }

                    var candidate = Path.Combine(value, "steamapps");
                    if (Directory.Exists(candidate) && seen.Add(candidate))
                    {
                        yield return candidate;
                    }
                }
            }
        }
    }

    /// <summary>
    /// Flattens a VDF/ACF file to its key-value pairs. Later keys win, which is fine for the
    /// handful of scalar fields read here, and nesting is ignored rather than modelled.
    /// </summary>
    private static Dictionary<string, string>? ReadFields(string path)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var match in KeyValue().EnumerateMatches(text))
        {
            var pair = KeyValue().Match(text, match.Index, match.Length);
            fields[pair.Groups[1].Value] = pair.Groups[2].Value;
        }

        return fields;
    }

    private static bool IsToolDepot(string name) =>
        name.StartsWith("Proton", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Steam Linux Runtime", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("Steamworks", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Steamworks Common Redistributables", StringComparison.OrdinalIgnoreCase);

    /// <summary>A stable GUID for a Steam app id, so profiles survive rediscovery.</summary>
    public static Guid DeterministicId(string appId)
    {
        var bytes = new byte[16];
        "steam-game".PadRight(8).AsSpan(0, 8).ToArray().Select(c => (byte)c).ToArray().CopyTo(bytes, 0);
        if (ulong.TryParse(appId, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            BitConverter.GetBytes(value).CopyTo(bytes, 8);
        }

        return new Guid(bytes);
    }
}
