namespace Yura.App;

/// <summary>Command-line options, used mainly by the screenshot and review harness.</summary>
public sealed record StartupOptions
{
    /// <summary>Fixed window size and no window chrome interference, for reproducible captures.</summary>
    public bool ScreenshotMode { get; init; }

    public int Width { get; init; } = 1280;

    public int Height { get; init; } = 800;

    public string Theme { get; init; } = "dark";

    public string Language { get; init; } = "en";

    /// <summary>Page to select on launch: processes, games, proxies, …</summary>
    public string Page { get; init; } = "processes";

    /// <summary>
    /// Populate the UI from a simulated daemon.
    /// </summary>
    /// <remarks>
    /// Only for design review. It exists so states that need a running daemon — confirmed
    /// proxying, live measurements, a populated proxy list — can be inspected before the
    /// daemon is built. Screenshots taken this way are labelled as simulated; the default
    /// build never fabricates data.
    /// </remarks>
    public bool Demo { get; init; }

    /// <summary>
    /// Override the configuration directory. Used by the verification harness to load a
    /// seeded configuration without touching the real one.
    /// </summary>
    public string? ConfigDirectory { get; init; }

    /// <summary>Which editor the demo opens on the Proxies page: socks, wireguard or chain.</summary>
    public string DemoEditor { get; init; } = "socks";

    public static StartupOptions Parse(string[] args)
    {
        var options = new StartupOptions();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--screenshot-mode":
                    options = options with { ScreenshotMode = true };
                    break;
                case "--demo":
                    options = options with { Demo = true };
                    break;
                case "--width" when i + 1 < args.Length && int.TryParse(args[i + 1], out var w):
                    options = options with { Width = w };
                    i++;
                    break;
                case "--height" when i + 1 < args.Length && int.TryParse(args[i + 1], out var h):
                    options = options with { Height = h };
                    i++;
                    break;
                case "--theme" when i + 1 < args.Length:
                    options = options with { Theme = args[++i] };
                    break;
                case "--lang" when i + 1 < args.Length:
                    options = options with { Language = args[++i] };
                    break;
                case "--page" when i + 1 < args.Length:
                    options = options with { Page = args[++i] };
                    break;
                case "--config-dir" when i + 1 < args.Length:
                    options = options with { ConfigDirectory = args[++i] };
                    break;
                case "--demo-editor" when i + 1 < args.Length:
                    options = options with { DemoEditor = args[++i] };
                    break;
            }
        }

        return options;
    }
}
