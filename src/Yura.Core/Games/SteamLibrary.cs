using System.Globalization;

namespace Yura.Core.Games;

/// <summary>A library Yura read, and how many games were in it.</summary>
public sealed record ScannedLibrary(string Path, int Games);

/// <summary>Why a library Steam lists could not be read.</summary>
public enum SkipReason
{
    /// <summary>The folder is not there at all — usually a drive that is not mounted.</summary>
    NotPresent,

    /// <summary>The folder is there but holds no <c>steamapps</c> directory.</summary>
    NoSteamApps,

    /// <summary>We are not allowed to read it.</summary>
    PermissionDenied,

    /// <summary>It failed to read for some other reason, which travels in the detail.</summary>
    Unreadable,
}

/// <summary>
/// A library Steam lists that Yura could not read. Reported rather than silently dropped.
/// </summary>
/// <param name="Detail">Operator-facing detail for <see cref="SkipReason.Unreadable"/>.</param>
public sealed record SkippedLibrary(string Path, SkipReason Reason, string? Detail = null);

/// <summary>
/// The result of one scan: the games, and an account of where they came from.
/// </summary>
/// <remarks>
/// The account is the point. A scan that quietly reads one library out of six looks exactly
/// like a scan that read all of them, which is how Yura shipped for one release with a bug
/// that dropped every library but the last. Reporting what was read and what was skipped
/// makes that class of failure visible without anyone having to count their games.
/// </remarks>
public sealed record SteamScan
{
    public static readonly SteamScan Empty = new();

    public IReadOnlyList<GameProfile> Games { get; init; } = [];

    public IReadOnlyList<ScannedLibrary> Libraries { get; init; } = [];

    public IReadOnlyList<SkippedLibrary> Skipped { get; init; } = [];
}

/// <summary>
/// Finds installed Steam games by reading the library's own manifests.
/// </summary>
/// <remarks>
/// Steam records every installed app in <c>steamapps/appmanifest_&lt;id&gt;.acf</c> and every
/// library root in <c>libraryfolders.vdf</c>. Reading those is the only way to enumerate games
/// without talking to Steam itself, and it degrades well: a missing or unreadable file means
/// fewer games listed, never an error — but it is reported, never silent.
///
/// Nothing here guesses an executable. A manifest names the install directory, not the binary,
/// and picking the wrong binary would produce a rule that silently covers nothing — so the
/// profile carries the directory as the fact it is, and a game becomes routable when its
/// process is found, either by its Steam app id or by living inside that directory.
/// </remarks>
public static class SteamLibrary
{
    /// <summary>Candidate Steam roots, in the order they are usually found on Linux.</summary>
    /// <remarks>
    /// Every packaging of Steam puts its root somewhere different, and a user who has moved
    /// between them keeps the old directory. They are all offered and the duplicates collapse
    /// later, when paths are compared after resolving symlinks — <c>~/.steam/steam</c> and
    /// <c>~/.local/share/Steam</c> are usually the same directory.
    /// </remarks>
    public static IReadOnlyList<string> DefaultRoots()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return
        [
            Path.Combine(home, ".steam", "steam"),
            Path.Combine(home, ".steam", "root"),
            Path.Combine(home, ".local", "share", "Steam"),
            // Debian and Ubuntu packages.
            Path.Combine(home, ".steam", "debian-installation"),
            // Flatpak.
            Path.Combine(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam"),
            // Snap.
            Path.Combine(home, "snap", "steam", "common", ".local", "share", "Steam"),
        ];
    }

    /// <summary>Reads every installed app from every readable library, deduplicated by app id.</summary>
    public static IReadOnlyList<GameProfile> Discover(IEnumerable<string>? roots = null) => Scan(roots).Games;

    /// <summary>Reads every library, and reports which ones were read and which were not.</summary>
    public static SteamScan Scan(IEnumerable<string>? roots = null)
    {
        var found = new Dictionary<string, GameProfile>(StringComparer.Ordinal);
        var scanned = new List<ScannedLibrary>();
        var skipped = new List<SkippedLibrary>();

        foreach (var library in LibraryPaths(roots ?? DefaultRoots(), skipped))
        {
            IReadOnlyList<string> manifests;
            try
            {
                manifests = Directory.EnumerateFiles(library, "appmanifest_*.acf").ToArray();
            }
            catch (UnauthorizedAccessException)
            {
                skipped.Add(new SkippedLibrary(library, SkipReason.PermissionDenied));
                continue;
            }
            catch (IOException e)
            {
                skipped.Add(new SkippedLibrary(library, SkipReason.Unreadable, e.Message));
                continue;
            }

            var games = 0;
            foreach (var manifest in manifests)
            {
                if (ReadManifest(manifest, library) is not { } game)
                {
                    continue;
                }

                games++;
                // The same game can be installed in two libraries; the first one wins, and
                // the app id keeps them from being listed twice.
                found.TryAdd(game.SteamAppId!, game);
            }

            scanned.Add(new ScannedLibrary(library, games));
        }

        return new SteamScan
        {
            Games = found.Values.OrderBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase).ToArray(),
            Libraries = scanned,
            Skipped = skipped,
        };
    }

    /// <summary>One app manifest as a profile, or null when it is not a game we can name.</summary>
    private static GameProfile? ReadManifest(string manifest, string library)
    {
        var document = ValveDataFormat.Read(manifest);
        // Fields are read from the top level of the AppState block only. A depot's own keys
        // must not be able to stand in for the app's.
        var state = document?.Blocks.FirstOrDefault();
        if (state?["appid"] is not { Length: > 0 } appId || state["name"] is not { Length: > 0 } name)
        {
            return null;
        }

        // Steam's own runtime and compatibility tools are installed as apps but are not
        // games, and offering to accelerate them would be noise.
        if (IsToolDepot(name))
        {
            return null;
        }

        var installDirectory = state["installdir"] is { Length: > 0 } installDir
            ? Path.Combine(library, "common", installDir)
            : null;

        return new GameProfile
        {
            // Derived from the app id so the same game keeps its identity, and its saved
            // route, across restarts and library moves.
            Id = DeterministicId(appId),
            Name = name,
            SteamAppId = appId,
            // Recorded only when it is actually there: an install directory that does not
            // exist would be a claim, and it is used to recognise the running game.
            InstallDirectory = installDirectory is not null && Directory.Exists(installDirectory)
                ? installDirectory
                : null,
            Source = GameSource.Steam,
        };
    }

    /// <summary>
    /// Every <c>steamapps</c> directory Steam knows about, canonicalised and deduplicated.
    /// </summary>
    /// <remarks>
    /// <c>libraryfolders.vdf</c> holds one entry per library, so every entry has to be read.
    /// Two formats are in the wild: current Steam writes a block per library with a
    /// <c>path</c> key, and older versions wrote <c>"1" "/mnt/games"</c> as a plain pair.
    /// Both appear here because a library added years ago is still a library.
    /// </remarks>
    private static IEnumerable<string> LibraryPaths(IEnumerable<string> roots, List<SkippedLibrary> skipped)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var root in roots)
        {
            var candidates = new List<(string Path, bool FromRoot)> { (root, true) };

            foreach (var vdf in new[]
                     {
                         Path.Combine(root, "steamapps", "libraryfolders.vdf"),
                         Path.Combine(root, "config", "libraryfolders.vdf"),
                     })
            {
                if (ValveDataFormat.Read(vdf) is not { } document)
                {
                    continue;
                }

                foreach (var libraries in document.Blocks)
                {
                    foreach (var entry in libraries.Children)
                    {
                        var path = entry.IsBlock ? entry["path"] : entry.Value;
                        if (path is { Length: > 0 })
                        {
                            candidates.Add((path, false));
                        }
                    }
                }
            }

            foreach (var (candidate, fromRoot) in candidates)
            {
                var steamapps = Canonical(Path.Combine(candidate, "steamapps"));
                if (!seen.Add(steamapps))
                {
                    continue;
                }

                if (Directory.Exists(steamapps))
                {
                    yield return steamapps;
                    continue;
                }

                // A root that is simply not installed is not worth reporting; a library Steam
                // lists and we cannot find is exactly what the user needs to be told about.
                if (!fromRoot)
                {
                    skipped.Add(new SkippedLibrary(
                        candidate,
                        Directory.Exists(candidate) ? SkipReason.NoSteamApps : SkipReason.NotPresent));
                }
            }
        }
    }

    /// <summary>
    /// A path with every symlinked component resolved, so the same directory reached two ways
    /// compares equal.
    /// </summary>
    /// <remarks>
    /// <c>~/.steam/steam</c> is a link to <c>~/.local/share/Steam</c> on most installations, and
    /// both are offered as roots. Comparing the strings would scan the same library twice and,
    /// worse, report six libraries where there are five.
    /// </remarks>
    private static string Canonical(string path)
    {
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path;
        }

        var resolved = Path.GetPathRoot(full) ?? "/";
        foreach (var segment in full[resolved.Length..].Split(Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            resolved = Path.Combine(resolved, segment);
            try
            {
                // Only a link resolves; anything else is already canonical. A broken link
                // throws, and the unresolved path is the honest answer in that case.
                if (Directory.ResolveLinkTarget(resolved, returnFinalTarget: true) is { } target)
                {
                    resolved = target.FullName;
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
            }
        }

        return resolved;
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
