using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Yura.App.ViewModels;

namespace Yura.App.Views;

public sealed partial class RulesPage : UserControl
{
    /// <summary>
    /// Below this width the inspector cannot be docked without squeezing every column of the
    /// rule table into illegibility, so it becomes an overlay instead.
    /// </summary>
    private const double CompactThreshold = 1040;

    public RulesPage() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    protected override void OnSizeChanged(SizeChangedEventArgs e)
    {
        base.OnSizeChanged(e);

        if (DataContext is RulesPageViewModel viewModel)
        {
            viewModel.IsCompact = e.NewSize.Width < CompactThreshold;
        }
    }
}
