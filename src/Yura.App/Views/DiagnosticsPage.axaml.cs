using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Yura.App.Localization;
using Yura.App.ViewModels;

namespace Yura.App.Views;

public sealed partial class DiagnosticsPage : UserControl
{
    public DiagnosticsPage() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    /// <summary>
    /// Puts the whole diagnostic report on the clipboard.
    /// </summary>
    /// <remarks>
    /// In the view rather than the view model because the clipboard belongs to the window, and
    /// a view model that reaches for it cannot be constructed in a test or a headless run.
    /// </remarks>
    private async void OnCopyReport(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not DiagnosticsPageViewModel viewModel)
        {
            return;
        }

        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard is null)
        {
            return;
        }

        await clipboard.SetTextAsync(viewModel.BuildReport());
        if (sender is Button button)
        {
            // Immediate feedback on the control that was pressed, then back to its label.
            await CopyFeedback.ShowAsync(button, Loc.Current["Diagnostics.Copied"]);
        }
    }
}
