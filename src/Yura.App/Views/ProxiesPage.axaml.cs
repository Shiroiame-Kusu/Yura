using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Yura.App.Views;

public sealed partial class ProxiesPage : UserControl
{
    public ProxiesPage() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
}
