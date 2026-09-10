using Avalonia;

namespace Yura.App;

internal static class Program
{
    /// <summary>Parsed once at startup and read by the application when it builds the shell.</summary>
    public static StartupOptions Options { get; private set; } = new();

    [STAThread]
    public static int Main(string[] args)
    {
        Options = StartupOptions.Parse(args);

        if (args.Contains("--font-report"))
        {
            return FontReport.Run(args.Contains("--verbose"));
        }

        if (args.Contains("--config-report"))
        {
            return ConfigReport.Run();
        }

        if (args.Contains("--service-report"))
        {
            return ServiceReport.Run();
        }

        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<YuraApplication>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
