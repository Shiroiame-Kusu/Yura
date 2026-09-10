using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Yura.App.Views;

public sealed partial class ConnectionsPage : UserControl
{
    public ConnectionsPage() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
}
