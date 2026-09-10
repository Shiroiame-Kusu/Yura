using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using Yura.App.Localization;
using Yura.App.Services;
using Yura.App.ViewModels;
using Yura.App.Views;

namespace Yura.App;

public sealed partial class YuraApplication : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var options = Program.Options;

            // The daemon is the only source of privileged truth. Absent one, the app runs
            // fully but reports that nothing will take effect; --demo swaps in a simulated
            // daemon for design review only.
            IDaemonClient daemon = options.Demo
                ? new SimulatedDaemonClient()
                : new UnixSocketDaemonClient();

            Loc.Current.Language = options.Language;
            RequestedThemeVariant = options.Theme.Equals("light", StringComparison.OrdinalIgnoreCase)
                ? ThemeVariant.Light
                : ThemeVariant.Dark;

            var shell = new ShellViewModel(daemon)
            {
                IsDarkTheme = !options.Theme.Equals("light", StringComparison.OrdinalIgnoreCase),
                IsChinese = options.Language.StartsWith("zh", StringComparison.OrdinalIgnoreCase),
            };

            var requested = shell.Pages.FirstOrDefault(p =>
                string.Equals(p.Key, options.Page, StringComparison.OrdinalIgnoreCase));
            if (requested is not null)
            {
                shell.SelectedPage = requested;
            }

            if (options.Demo)
            {
                DemoData.Populate(shell);
            }

            // Probe the daemon once at startup so the shell shows its real state rather
            // than assuming the worst. The result only changes a banner, so it does not
            // block the window from appearing.
            _ = shell.RefreshDaemonStateAsync();

            var window = new MainWindow { DataContext = shell };
            if (options.ScreenshotMode)
            {
                window.Width = options.Width;
                window.Height = options.Height;
                window.WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.Manual;
                // No decorations to strip: the capture runs under a bare Xvfb with no
                // window manager, so the window is drawn exactly at its requested size.
                window.Position = new PixelPoint(0, 0);
            }

            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
