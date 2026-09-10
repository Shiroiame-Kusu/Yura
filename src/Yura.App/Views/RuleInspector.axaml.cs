using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Yura.App.Views;

public sealed partial class RuleInspector : UserControl
{
    public RuleInspector() => InitializeComponent();

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
}
