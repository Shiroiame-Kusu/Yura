using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Yura.App.ViewModels;

namespace Yura.App.Views;

public sealed partial class ProcessesPage : UserControl
{
    /// <summary>
    /// Below this width the inspector cannot be docked without squeezing the executable
    /// path column out of the table, so it becomes an overlay instead.
    /// </summary>
    private const double CompactThreshold = 1000;

    public ProcessesPage() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    protected override void OnSizeChanged(SizeChangedEventArgs e)
    {
        base.OnSizeChanged(e);

        if (DataContext is ProcessesPageViewModel viewModel)
        {
            viewModel.IsCompact = e.NewSize.Width < CompactThreshold;
        }
    }
}
