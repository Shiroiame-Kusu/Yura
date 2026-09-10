using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Yura.App.Localization;
using Yura.App.ViewModels;

namespace Yura.App.Views;

public sealed partial class SettingsPage : UserControl
{
    public SettingsPage() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    private void OnCopyUnit(object? sender, RoutedEventArgs e) =>
        _ = CopyAsync(sender, (DataContext as SettingsPageViewModel)?.UnitPreview);

    private void OnCopyInstallScript(object? sender, RoutedEventArgs e) =>
        _ = CopyAsync(sender, (DataContext as SettingsPageViewModel)?.InstallScriptPreview);

    private void OnCopyUninstallScript(object? sender, RoutedEventArgs e) =>
        _ = CopyAsync(sender, (DataContext as SettingsPageViewModel)?.UninstallScriptPreview);

    /// <summary>The clipboard belongs to the window, so copying lives in the view.</summary>
    private async Task CopyAsync(object? sender, string? text)
    {
        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard is null || string.IsNullOrEmpty(text))
        {
            return;
        }

        await clipboard.SetTextAsync(text);
        if (sender is Button button)
        {
            var original = button.Content;
            button.Content = Loc.Current["Settings.Service.Copied"];
            await Task.Delay(TimeSpan.FromSeconds(2));
            button.Content = original;
        }
    }
}
