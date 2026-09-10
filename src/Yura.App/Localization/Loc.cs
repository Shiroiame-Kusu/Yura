using System.ComponentModel;
using Avalonia.Data;
using Avalonia.Markup.Xaml;

namespace Yura.App.Localization;

/// <summary>
/// The application's string table, switchable at runtime.
/// </summary>
/// <remarks>
/// Exposed as an indexer so views can bind to <c>[Some.Key]</c>. Changing the language
/// raises a change notification for the indexer, which refreshes every bound string in
/// place — the language can be switched without rebuilding the UI, which is what makes it
/// practical to check Chinese text expansion against a live layout.
/// </remarks>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Current { get; } = new();

    private string _language = "en";

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Currently selected language tag: <c>en</c> or <c>zh-Hans</c>.</summary>
    public string Language
    {
        get => _language;
        set
        {
            if (_language == value)
            {
                return;
            }

            _language = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsChinese)));
        }
    }

    public bool IsChinese => _language.StartsWith("zh", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Looks up a key. An unknown key returns the key itself in guillemets rather than an
    /// empty string, so a missing translation is visible in a screenshot instead of
    /// silently collapsing the layout.
    /// </summary>
    public string this[string key] => Strings.Lookup(_language, key);

    public string Get(string key) => this[key];
}

/// <summary>XAML shorthand: <c>Text="{loc:Tr Nav.Processes}"</c>.</summary>
public sealed class TrExtension : MarkupExtension
{
    public TrExtension() => Key = string.Empty;

    public TrExtension(string key) => Key = key;

    public string Key { get; set; }

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]")
        {
            Source = Loc.Current,
            Mode = BindingMode.OneWay,
        };
}
