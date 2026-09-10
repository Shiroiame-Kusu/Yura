using Avalonia;
using Avalonia.Media;

namespace Yura.App;

/// <summary>
/// Reports what Avalonia's own font manager can actually resolve on this machine.
/// </summary>
/// <remarks>
/// Run with <c>--font-report</c>. The specification requires reliable offline Latin and
/// Chinese fallback, and fontconfig answering a query is not evidence that Avalonia will
/// resolve the same family: the two use different matching. This asks the renderer directly
/// so the answer reflects what will be drawn.
/// </remarks>
internal static class FontReport
{
    private static readonly string[] Wanted =
    [
        "Inter",
        "Noto Sans",
        "Noto Sans CJK SC",
        "Noto Sans Mono",
        "DejaVu Sans Mono",
        "Liberation Mono",
    ];

    public static int Run(bool verbose)
    {
        // Must be the real platform, not headless: the headless backend substitutes a stub
        // font manager, so a headless report says nothing about what will actually render.
        // Needs a display; run it under Xvfb.
        AppBuilder.Configure<YuraApplication>()
            .UsePlatformDetect()
            .WithInterFont()
            .SetupWithoutStarting();

        var manager = FontManager.Current;
        var installed = manager.SystemFonts.Select(f => f.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Console.WriteLine($"default family : {manager.DefaultFontFamily.Name}");
        Console.WriteLine($"system families: {installed.Count}");
        Console.WriteLine();

        Console.WriteLine("requested families:");
        foreach (var name in Wanted)
        {
            var present = installed.Contains(name);
            // TryMatchCharacter is what actually decides whether a glyph renders.
            Console.WriteLine($"  {(present ? "found  " : "MISSING")}  {name}");
        }

        Console.WriteLine();
        Console.WriteLine("what each FontFamily string actually resolves to:");
        string[] candidates =
        [
            "Inter",
            "Noto Sans CJK SC",
            "Noto Sans Mono",
            "DejaVu Sans Mono",
            // The comma-separated forms: this is the question that matters, because a
            // silently-unresolved list falls back to an arbitrary system font.
            "Noto Sans Mono, DejaVu Sans Mono",
            "Inter, Noto Sans CJK SC, Noto Sans",
            "avares://Avalonia.Fonts.Inter/Assets#Inter",
            "avares://Avalonia.Fonts.Inter/Assets#Inter, Noto Sans CJK SC, Noto Sans",
            "DejaVu Sans Mono, Liberation Mono, Noto Sans Mono",
            "Definitely Not A Real Font",
        ];

        foreach (var candidate in candidates)
        {
            var typeface = new Typeface(new FontFamily(candidate));
            var resolved = manager.TryGetGlyphTypeface(typeface, out var glyphTypeface);
            var actual = resolved && glyphTypeface is not null ? glyphTypeface.FamilyName : "unresolved";
            var flag = string.Equals(actual, candidate.Split(',')[0].Trim(), StringComparison.OrdinalIgnoreCase)
                ? "ok "
                : "!! ";
            Console.WriteLine($"  {flag} \"{candidate}\"");
            Console.WriteLine($"        -> {actual}");
        }

        if (verbose)
        {
            Console.WriteLine();
            Console.WriteLine("all system families:");
            foreach (var name in installed.OrderBy(n => n, StringComparer.Ordinal))
            {
                Console.WriteLine($"  {name}");
            }
        }

        return 0;
    }
}
