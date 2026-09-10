using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Yura.App.Views;

public sealed partial class ProxyInspector : UserControl
{
    public ProxyInspector() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
}
