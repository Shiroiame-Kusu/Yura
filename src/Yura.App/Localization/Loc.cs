using System.ComponentModel;
using Avalonia;
using Avalonia.Markup.Xaml;

namespace Yura.App.Localization;

/// <summary>
/// The application's string table, switchable at runtime.
/// </summary>
/// <remarks>
/// Views take strings through <see cref="TrExtension"/>, which subscribes to <see cref="Observe"/>.
/// Changing the language pushes the new text to every one of them in place, so the language can
/// be switched without rebuilding the UI, which is what makes it practical to check Chinese text
/// expansion against a live layout. The indexer still raises its change notification, for
/// anything that listens to it directly.
/// </remarks>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Current { get; } = new();

    // Weak, because this outlives every view: a strong reference from here would keep alive
    // every control that ever showed a translated string. The binding holds the subscription.
    private readonly List<WeakReference<Subscription>> _subscriptions = [];
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
            foreach (var subscription in Live())
            {
                subscription.Push();
            }

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

    /// <summary>
    /// The text for <paramref name="key"/> now, and again each time the language changes.
    /// </summary>
    /// <remarks>Changing the language pushes on the thread that changed it, which is the UI thread.</remarks>
    public IObservable<string> Observe(string key) => new Translation(this, key);

    /// <summary>How many subscriptions are still alive, for tests.</summary>
    internal int LiveSubscriptions => Live().Length;

    /// <summary>The subscriptions whose bindings still exist, forgetting the rest.</summary>
    private Subscription[] Live()
    {
        lock (_subscriptions)
        {
            var live = new List<Subscription>(_subscriptions.Count);
            _subscriptions.RemoveAll(reference =>
            {
                if (!reference.TryGetTarget(out var subscription))
                {
                    return true;
                }

                live.Add(subscription);
                return false;
            });
            return live.ToArray();
        }
    }

    private void Add(Subscription subscription)
    {
        lock (_subscriptions)
        {
            _subscriptions.Add(new WeakReference<Subscription>(subscription));
        }
    }

    private void Remove(Subscription subscription)
    {
        lock (_subscriptions)
        {
            _subscriptions.RemoveAll(r => !r.TryGetTarget(out var s) || ReferenceEquals(s, subscription));
        }
    }

    private sealed class Translation(Loc loc, string key) : IObservable<string>
    {
        public IDisposable Subscribe(IObserver<string> observer)
        {
            var subscription = new Subscription(loc, key, observer);
            observer.OnNext(loc[key]);
            loc.Add(subscription);
            return subscription;
        }
    }

    /// <summary>One bound string, held by its binding and only weakly by <see cref="Loc"/>.</summary>
    private sealed class Subscription(Loc loc, string key, IObserver<string> observer) : IDisposable
    {
        public void Push() => observer.OnNext(loc[key]);

        public void Dispose() => loc.Remove(this);
    }
}

/// <summary>XAML shorthand: <c>Text="{loc:Tr Nav.Processes}"</c>.</summary>
/// <remarks>
/// Binds to an observable rather than to the indexer by path. A path binding is resolved by
/// reflection when it is first evaluated, which NativeAOT cannot do; this needs none.
/// </remarks>
public sealed class TrExtension : MarkupExtension
{
    public TrExtension() => Key = string.Empty;

    public TrExtension(string key) => Key = key;

    public string Key { get; set; }

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        Loc.Current.Observe(Key).ToBinding();
}
