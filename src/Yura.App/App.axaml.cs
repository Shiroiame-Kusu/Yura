using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
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

            // Design review and screenshots must never touch the real configuration: they
            // would otherwise overwrite the user's proxies with demo data.
            var isolated = options.Demo || options.ScreenshotMode;
            var config = options.ConfigDirectory is { Length: > 0 } explicitDirectory
                ? new ConfigStore(explicitDirectory)
                : isolated
                    ? new ConfigStore(Path.Combine(Path.GetTempPath(), $"yura-scratch-{Environment.ProcessId}"))
                    : new ConfigStore();
            // Kept for the session as well as in the secret service: a secret the service will
            // not take must still work until the app exits, which is what the editor promises.
            ISecretStore secrets = isolated
                ? new InMemorySecretStore()
                : new SessionBackedSecretStore(new SecretToolSecretStore());

            // The shell's default. Its configuration and the command line move it from here.
            RequestedThemeVariant = ThemeVariant.Dark;

            // Design review shows a running service; a screenshot of the real app shows the
            // real state, which only ever reads systemd until a button is pressed.
            IServiceManager services = options.Demo ? new SimulatedServiceManager() : new ServiceManager();

            // The saved theme and language are loaded by the constructor; the command line
            // overrides them only when it names one.
            var shell = new ShellViewModel(daemon, secrets, config, services);
            shell.ApplyStartupOverrides(
                dark: options.Theme is { } theme ? !theme.Equals("light", StringComparison.OrdinalIgnoreCase) : null,
                chinese: options.Language is { } language
                    ? language.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
                    : null);

            var requested = shell.Pages.FirstOrDefault(p =>
                string.Equals(p.Key, options.Page, StringComparison.OrdinalIgnoreCase));
            if (requested is not null)
            {
                shell.SelectedPage = requested;
            }

            if (options.Demo)
            {
                DemoData.Populate(shell, options.DemoEditor);
            }

            // Probe the daemon once at startup so the shell shows its real state rather
            // than assuming the worst. The result only changes a banner, so it does not
            // block the window from appearing.
            _ = shell.RefreshDaemonStateAsync();

            var window = new MainWindow { DataContext = shell };

            // Flush any debounced change before the process goes away.
            desktop.ShutdownRequested += (_, _) => shell.SaveConfigurationAsync().GetAwaiter().GetResult();
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
