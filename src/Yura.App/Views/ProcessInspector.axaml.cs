using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Yura.App.Views;

public sealed partial class ProcessInspector : UserControl
{
    public ProcessInspector() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
}
