using System.Runtime.CompilerServices;
using Yura.App.Localization;

namespace Yura.Core.Tests;

/// <summary>
/// What <c>{loc:Tr Key}</c> binds to: a translation that follows the language.
/// </summary>
/// <remarks>
/// It used to be a reflection binding to <see cref="Loc"/>'s indexer, which NativeAOT cannot
/// resolve. The observable that replaced it has to do what that binding did: show the text,
/// change it when the language changes, and not keep a control alive once its binding is gone.
/// </remarks>
public sealed class LocTests
{
    private const string Key = "Nav.Processes";

    private sealed class Recorder : IObserver<string>
    {
        public List<string> Seen { get; } = [];

        public void OnNext(string value) => Seen.Add(value);

        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }
    }

    [Fact]
    public void A_binding_gets_the_text_now_and_again_when_the_language_changes()
    {
        var loc = new Loc();
        var english = loc[Key];
        var recorder = new Recorder();

        using var subscription = loc.Observe(Key).Subscribe(recorder);
        loc.Language = "zh-Hans";

        Assert.NotEqual(english, loc[Key]);
        Assert.Equal([english, loc[Key]], recorder.Seen);
    }

    [Fact]
    public void A_binding_that_has_let_go_hears_nothing_more()
    {
        var loc = new Loc();
        var recorder = new Recorder();

        loc.Observe(Key).Subscribe(recorder).Dispose();
        loc.Language = "zh-Hans";

        Assert.Single(recorder.Seen);
        Assert.Equal(0, loc.LiveSubscriptions);
    }

    [Fact]
    public void The_language_does_not_keep_a_binding_alive()
    {
        var loc = new Loc();
        var subscription = SubscribeAndForget(loc);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.False(subscription.TryGetTarget(out _));
        Assert.Equal(0, loc.LiveSubscriptions);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference<IDisposable> SubscribeAndForget(Loc loc) =>
        new(loc.Observe(Key).Subscribe(new Recorder()));
}
