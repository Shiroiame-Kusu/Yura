using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Yura.App.ViewModels;

namespace Yura.App.Views;

public sealed partial class ProxiesPage : UserControl
{
    /// <summary>
    /// Below this width a docked 440-DIP editor leaves the list too narrow to read an address
    /// in, so the editor becomes an overlay instead.
    /// </summary>
    private const double CompactThreshold = 1120;

    public ProxiesPage()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is ProxiesPageViewModel viewModel)
            {
                // The file picker belongs to the window, so the view supplies it.
                viewModel.Editor.PickConfigurationFile = PickConfigurationAsync;
            }
        };
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    protected override void OnSizeChanged(SizeChangedEventArgs e)
    {
        base.OnSizeChanged(e);

        if (DataContext is ProxiesPageViewModel viewModel)
        {
            viewModel.IsCompact = e.NewSize.Width < CompactThreshold;
        }
    }

    /// <summary>
    /// Reads a wg-quick configuration the user chooses.
    /// </summary>
    /// <remarks>
    /// In the view because the storage provider belongs to the window; the view model holds it
    /// as a delegate so it can be driven without one.
    /// </remarks>
    private async Task<string?> PickConfigurationAsync(CancellationToken ct)
    {
        var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storage is null)
        {
            return null;
        }

        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType("WireGuard configuration") { Patterns = ["*.conf"] },
                FilePickerFileTypes.All,
            ],
        });

        if (files.Count == 0)
        {
            return null;
        }

        await using var stream = await files[0].OpenReadAsync();
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(ct);
    }
}
