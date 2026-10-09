using System.ComponentModel;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Yura.App.Localization;
using Yura.App.ViewModels;

namespace Yura.App.Views;

/// <summary>The window, and the title bar Yura draws in it.</summary>
/// <remarks>
/// Unless asked not to, Yura draws its own title bar and Avalonia draws the frame around the
/// window: a line, and a shadow whose width is where the pointer catches the window to resize it,
/// since an undecorated X11 window has no other edge. Moving and resizing stay the desktop's job.
/// The title bar only hands it the pointer, as the desktop's own title bar would, so snapping,
/// tiling and its keyboard shortcuts carry on working.
/// </remarks>
public sealed partial class MainWindow : Window
{
    /// <summary>How far, in DIPs, the pointer moves with the button down before a press becomes a move.</summary>
    /// <remarks>
    /// Not the press itself: handing the pointer to the window manager straight away swallows the
    /// release, and the second press of a double click then never counts as one.
    /// </remarks>
    private const double DragThreshold = 4;

    private readonly Control _titleBar;
    private readonly Control _sidebarHeader;
    private readonly Border _windowFrame;
    private readonly Button _maximizeButton;
    private readonly Control _maximizeGlyph;
    private readonly Control _restoreGlyph;

    private ShellViewModel? _shell;
    private PointerPressedEventArgs? _press;
    private Point _pressedAt;
    private bool _frameless;

    public MainWindow()
    {
        InitializeComponent();
        _titleBar = this.Get<Control>("TitleBar");
        _sidebarHeader = this.Get<Control>("SidebarHeader");
        _windowFrame = this.Get<Border>("WindowFrame");
        _maximizeButton = this.Get<Button>("MaximizeButton");
        _maximizeGlyph = this.Get<Control>("MaximizeGlyph");
        _restoreGlyph = this.Get<Control>("RestoreGlyph");
        ApplyChrome();
    }

    private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

    /// <summary>
    /// No frame and square corners: for screenshots, taken under a bare X server where nothing
    /// composites a shadow and the window must be exactly the size asked for.
    /// </summary>
    public bool Frameless
    {
        get => _frameless;
        set
        {
            _frameless = value;
            ApplyChrome();
        }
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (_shell is not null)
        {
            _shell.PropertyChanged -= OnShellChanged;
        }

        _shell = DataContext as ShellViewModel;
        if (_shell is not null)
        {
            _shell.PropertyChanged += OnShellChanged;
        }

        ApplyChrome();
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == WindowStateProperty)
        {
            ApplyChrome();
        }
    }

    private void OnShellChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ShellViewModel.UseSystemTitleBar) or nameof(ShellViewModel.IsChinese))
        {
            ApplyChrome();
        }
    }

    /// <summary>Puts the window's chrome in step with the setting and the window's state.</summary>
    private void ApplyChrome()
    {
        var own = _shell is not { UseSystemTitleBar: true };
        WindowDecorations = !own ? WindowDecorations.Full
            : _frameless ? WindowDecorations.None
            : WindowDecorations.BorderOnly;

        // The rounded corners and the shadow are see-through; with the desktop's frame, or none,
        // nothing is, and the window need not be composited as if it were.
        TransparencyLevelHint = own && !_frameless ? [WindowTransparencyLevel.Transparent] : [];
        _titleBar.IsVisible = own;
        _sidebarHeader.IsVisible = !own;
        _windowFrame.CornerRadius = own && !_frameless && WindowState == WindowState.Normal
            ? new CornerRadius(8)
            : default;

        var maximized = WindowState == WindowState.Maximized;
        _maximizeGlyph.IsVisible = !maximized;
        _restoreGlyph.IsVisible = maximized;
        var label = Loc.Current[maximized ? "Shell.Restore" : "Shell.Maximize"];
        ToolTip.SetTip(_maximizeButton, label);
        AutomationProperties.SetName(_maximizeButton, label);
    }

    private void OnTitleBarPressed(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        e.Handled = true;
        if (e.ClickCount >= 2)
        {
            _press = null;
            ToggleMaximized();
            return;
        }

        _press = e;
        _pressedAt = e.GetPosition(this);
    }

    private void OnTitleBarMoved(object? sender, PointerEventArgs e)
    {
        if (_press is not { } press)
        {
            return;
        }

        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            _press = null;
            return;
        }

        var moved = e.GetPosition(this) - _pressedAt;
        if (Math.Abs(moved.X) >= DragThreshold || Math.Abs(moved.Y) >= DragThreshold)
        {
            _press = null;
            BeginMoveDrag(press);
        }
    }

    private void OnTitleBarReleased(object? sender, PointerReleasedEventArgs e) => _press = null;

    private void ToggleMaximized() =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OnMinimize(object? sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximize(object? sender, RoutedEventArgs e) => ToggleMaximized();

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
