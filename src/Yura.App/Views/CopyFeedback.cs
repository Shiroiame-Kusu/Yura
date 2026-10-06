using System.Runtime.CompilerServices;
using Avalonia.Controls;
using Avalonia.Data;

namespace Yura.App.Views;

/// <summary>"Copied" on a button for a moment, then the button's own label back.</summary>
/// <remarks>
/// The label comes back from its binding, not from a copy of the text it showed. Copying the
/// text meant a second click inside the two seconds saved "Copied" as the label and put that
/// back for good, and writing a plain string over the binding left the label in whatever
/// language it was in at the time.
/// </remarks>
internal static class CopyFeedback
{
    private static readonly ConditionalWeakTable<Button, StrongBox<int>> Clicks = new();

    public static async Task ShowAsync(Button button, string copied)
    {
        var clicks = Clicks.GetOrCreateValue(button);
        var click = ++clicks.Value;

        // Beside the binding rather than over it, so the binding is still there to restore.
        button.SetCurrentValue(ContentControl.ContentProperty, copied);
        await Task.Delay(TimeSpan.FromSeconds(2));

        // A later click is showing its own confirmation, and puts the label back when it ends.
        if (clicks.Value == click)
        {
            BindingOperations.GetBindingExpressionBase(button, ContentControl.ContentProperty)?.UpdateTarget();
        }
    }
}
