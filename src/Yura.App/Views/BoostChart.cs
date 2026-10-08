using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Input;
using Avalonia.Media;
using Yura.App.ViewModels;

namespace Yura.App.Views;

/// <summary>
/// A boost session's latency and packet loss over time: two small charts on one time axis.
/// </summary>
/// <remarks>
/// <para>
/// Two charts rather than one with two scales: latency in milliseconds and loss in percent have
/// nothing in common, and putting both on one plot invents a relationship from wherever the two
/// scales happen to line up. They share the time axis, and one crosshair runs through both.
/// </para>
/// <para>
/// The route is the series that matters and wears the accent; the direct path is context, a
/// thinner line in a recessive gray. Each line is named at its end and in the legend, so neither
/// depends on telling the two colours apart. A probe that got no answer leaves a gap in its line
/// rather than a drop to zero, which would read as a perfect round trip.
/// </para>
/// <para>
/// Drawn by hand: no chart library is needed for two lines and some bars, and this one needs no
/// reflection, which a NativeAOT build does not have.
/// </para>
/// </remarks>
public sealed class BoostChart : Control
{
    public static readonly StyledProperty<BoostHistory?> HistoryProperty =
        AvaloniaProperty.Register<BoostChart, BoostHistory?>(nameof(History));

    /// <summary>Bound to the history's version, so a new sample redraws the chart.</summary>
    public static readonly StyledProperty<int> VersionProperty =
        AvaloniaProperty.Register<BoostChart, int>(nameof(Version));

    public static readonly StyledProperty<IBrush?> RouteBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(RouteBrush));

    public static readonly StyledProperty<IBrush?> ContextBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(ContextBrush));

    public static readonly StyledProperty<IBrush?> LossBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(LossBrush));

    public static readonly StyledProperty<IBrush?> GridBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(GridBrush));

    public static readonly StyledProperty<IBrush?> TextBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(TextBrush));

    public static readonly StyledProperty<IBrush?> MutedTextBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(MutedTextBrush));

    public static readonly StyledProperty<IBrush?> SurfaceBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(SurfaceBrush));

    public static readonly StyledProperty<IBrush?> TipBackgroundProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(TipBackground));

    public static readonly StyledProperty<IBrush?> TipBorderBrushProperty =
        AvaloniaProperty.Register<BoostChart, IBrush?>(nameof(TipBorderBrush));

    public static readonly StyledProperty<string> RouteLabelProperty =
        AvaloniaProperty.Register<BoostChart, string>(nameof(RouteLabel), string.Empty);

    public static readonly StyledProperty<string> DirectLabelProperty =
        AvaloniaProperty.Register<BoostChart, string>(nameof(DirectLabel), string.Empty);

    public static readonly StyledProperty<string> LatencyTitleProperty =
        AvaloniaProperty.Register<BoostChart, string>(nameof(LatencyTitle), string.Empty);

    public static readonly StyledProperty<string> LossTitleProperty =
        AvaloniaProperty.Register<BoostChart, string>(nameof(LossTitle), string.Empty);

    public static readonly StyledProperty<string> NoAnswerLabelProperty =
        AvaloniaProperty.Register<BoostChart, string>(nameof(NoAnswerLabel), string.Empty);

    /// <summary>
    /// What a route sample with no figure is called: usually no answer, but not when the route
    /// cannot be timed at all.
    /// </summary>
    public static readonly StyledProperty<string> RouteMissingLabelProperty =
        AvaloniaProperty.Register<BoostChart, string>(nameof(RouteMissingLabel), string.Empty);

    /// <summary>How wide one loss bar's slice of time is.</summary>
    public static readonly TimeSpan LossBucketWidth = TimeSpan.FromSeconds(30);

    /// <summary>The narrowest span the chart shows, so the first samples do not fill the width.</summary>
    private static readonly TimeSpan MinimumSpan = TimeSpan.FromMinutes(2);

    private const double FontSize = 11;
    private const double LeftAxis = 46;
    private const double RightGutter = 64;
    private const double TopBand = 22;
    private const double PanelGap = 26;
    private const double BottomAxis = 20;

    private int? _hover;

    static BoostChart()
    {
        AffectsRender<BoostChart>(
            HistoryProperty, VersionProperty, RouteBrushProperty, ContextBrushProperty, LossBrushProperty,
            GridBrushProperty, TextBrushProperty, MutedTextBrushProperty, SurfaceBrushProperty,
            TipBackgroundProperty, TipBorderBrushProperty, RouteLabelProperty, DirectLabelProperty,
            LatencyTitleProperty, LossTitleProperty, NoAnswerLabelProperty, RouteMissingLabelProperty);
        FocusableProperty.OverrideDefaultValue<BoostChart>(true);
    }

    public BoostHistory? History { get => GetValue(HistoryProperty); set => SetValue(HistoryProperty, value); }

    public int Version { get => GetValue(VersionProperty); set => SetValue(VersionProperty, value); }

    public IBrush? RouteBrush { get => GetValue(RouteBrushProperty); set => SetValue(RouteBrushProperty, value); }

    public IBrush? ContextBrush { get => GetValue(ContextBrushProperty); set => SetValue(ContextBrushProperty, value); }

    public IBrush? LossBrush { get => GetValue(LossBrushProperty); set => SetValue(LossBrushProperty, value); }

    public IBrush? GridBrush { get => GetValue(GridBrushProperty); set => SetValue(GridBrushProperty, value); }

    public IBrush? TextBrush { get => GetValue(TextBrushProperty); set => SetValue(TextBrushProperty, value); }

    public IBrush? MutedTextBrush { get => GetValue(MutedTextBrushProperty); set => SetValue(MutedTextBrushProperty, value); }

    public IBrush? SurfaceBrush { get => GetValue(SurfaceBrushProperty); set => SetValue(SurfaceBrushProperty, value); }

    public IBrush? TipBackground { get => GetValue(TipBackgroundProperty); set => SetValue(TipBackgroundProperty, value); }

    public IBrush? TipBorderBrush { get => GetValue(TipBorderBrushProperty); set => SetValue(TipBorderBrushProperty, value); }

    public string RouteLabel { get => GetValue(RouteLabelProperty); set => SetValue(RouteLabelProperty, value); }

    public string DirectLabel { get => GetValue(DirectLabelProperty); set => SetValue(DirectLabelProperty, value); }

    public string LatencyTitle { get => GetValue(LatencyTitleProperty); set => SetValue(LatencyTitleProperty, value); }

    public string LossTitle { get => GetValue(LossTitleProperty); set => SetValue(LossTitleProperty, value); }

    public string NoAnswerLabel { get => GetValue(NoAnswerLabelProperty); set => SetValue(NoAnswerLabelProperty, value); }

    public string RouteMissingLabel { get => GetValue(RouteMissingLabelProperty); set => SetValue(RouteMissingLabelProperty, value); }

    // -- the scales, shared by drawing and by the pointer -----------------------------------

    private readonly record struct Frame(
        Rect Latency, Rect Loss, DateTimeOffset From, DateTimeOffset To, double LatencyMax, double LatencyStep, double LossMax)
    {
        public double X(DateTimeOffset at) =>
            Latency.Left + (Latency.Width * (at - From).TotalMilliseconds / Math.Max(1, (To - From).TotalMilliseconds));

        public double LatencyY(double milliseconds) =>
            Latency.Bottom - (Latency.Height * Math.Clamp(milliseconds / LatencyMax, 0, 1));

        public double LossY(double percent) => Loss.Bottom - (Loss.Height * Math.Clamp(percent / LossMax, 0, 1));
    }

    private Frame? Layout(IReadOnlyList<LatencySample> samples)
    {
        var width = Bounds.Width - LeftAxis - RightGutter;
        var height = Bounds.Height - TopBand - PanelGap - BottomAxis - TopBand;
        if (samples.Count == 0 || width < 80 || height < 60)
        {
            return null;
        }

        var to = samples[^1].At;
        var from = samples[0].At;
        if (to - from < MinimumSpan)
        {
            to = from + MinimumSpan;
        }

        var latencyHeight = Math.Round(height * 0.66);
        var latency = new Rect(LeftAxis, TopBand, width, latencyHeight);
        var loss = new Rect(LeftAxis, latency.Bottom + PanelGap + TopBand, width, height - latencyHeight);

        var highest = samples
            .SelectMany(s => new[] { s.RoutedMilliseconds, s.DirectMilliseconds })
            .OfType<double>()
            .DefaultIfEmpty(0)
            .Max();
        var lossHighest = History?.RouteLossBuckets(LossBucketWidth).Select(b => b.Percent).DefaultIfEmpty(0).Max() ?? 0;

        var (top, step) = NiceScale(Math.Max(20, highest * 1.05));
        return new Frame(latency, loss, from, to, top, step, Math.Max(10, NiceCeiling(lossHighest)));
    }

    /// <summary>
    /// A clean tick step for about four intervals, and the axis top: the first multiple of the step
    /// at or above the value. Taking the step first keeps the top close to the data — 117 ms gets a
    /// 150 ms axis, where rounding the top itself to a nice number gave 200 and an empty third.
    /// </summary>
    internal static (double Top, double Step) NiceScale(double value)
    {
        var step = NiceCeiling(value / 4);
        return (step * Math.Ceiling((value / step) - 1e-9), step);
    }

    /// <summary>The smallest of 1, 2, 2.5 or 5 times a power of ten at or above the value.</summary>
    internal static double NiceCeiling(double value)
    {
        if (value <= 0)
        {
            return 1;
        }

        var magnitude = Math.Pow(10, Math.Floor(Math.Log10(value)));
        foreach (var step in new[] { 1, 2, 2.5, 5, 10 })
        {
            if (step * magnitude >= value - 1e-9)
            {
                return step * magnitude;
            }
        }

        return 10 * magnitude;
    }

    // -- drawing ---------------------------------------------------------------------------

    public override void Render(DrawingContext context)
    {
        // Transparent but painted: a pointer is only delivered where a control has drawn something,
        // and without this the crosshair answered on the lines and nowhere between them.
        context.FillRectangle(Brushes.Transparent, new Rect(Bounds.Size));

        var history = History;
        var samples = history?.Samples ?? [];
        if (Layout(samples) is not { } frame)
        {
            return;
        }

        var muted = MutedTextBrush ?? Brushes.Gray;
        var text = TextBrush ?? Brushes.White;
        var grid = new Pen(GridBrush ?? Brushes.DimGray, 1);

        DrawLatencyAxis(context, frame, grid, muted);
        DrawLossAxis(context, frame, grid, muted);
        DrawTimeAxis(context, frame, muted);
        DrawLegend(context, frame, text, muted);

        DrawLossBars(context, frame, history!);
        DrawSeries(context, frame, samples, s => s.DirectMilliseconds, ContextBrush ?? Brushes.Gray, 1.5, wash: false);
        DrawSeries(context, frame, samples, s => s.RoutedMilliseconds, RouteBrush ?? Brushes.Teal, 2, wash: true);
        DrawEnds(context, frame, samples, text, muted);

        if (_hover is { } index && index < samples.Count)
        {
            DrawCrosshair(context, frame, samples, index, history!, text, muted);
        }
    }

    private FormattedText Text(string value, IBrush brush, bool strong = false) => new(
        value,
        CultureInfo.CurrentCulture,
        FlowDirection.LeftToRight,
        new Typeface(GetValue(TextElement.FontFamilyProperty), FontStyle.Normal, strong ? FontWeight.SemiBold : FontWeight.Normal),
        FontSize,
        brush);

    private static string Milliseconds(double value) =>
        string.Create(CultureInfo.CurrentCulture, $"{value:0} ms");

    private void DrawLatencyAxis(DrawingContext context, Frame frame, Pen grid, IBrush muted)
    {
        var intervals = (int)Math.Round(frame.LatencyMax / frame.LatencyStep);
        for (var i = 0; i <= intervals; i++)
        {
            var value = frame.LatencyStep * i;
            var y = Math.Round(frame.LatencyY(value)) + 0.5;
            context.DrawLine(grid, new Point(frame.Latency.Left, y), new Point(frame.Latency.Right, y));
            // The unit once, on the top tick; the rest are numbers on the same scale.
            var label = Text(i == intervals ? Milliseconds(value) : value.ToString("0.#", CultureInfo.CurrentCulture), muted);
            context.DrawText(label, new Point(frame.Latency.Left - label.Width - 8, y - (label.Height / 2)));
        }
    }

    private void DrawLossAxis(DrawingContext context, Frame frame, Pen grid, IBrush muted)
    {
        foreach (var value in new[] { 0, frame.LossMax })
        {
            var y = Math.Round(frame.LossY(value)) + 0.5;
            context.DrawLine(grid, new Point(frame.Loss.Left, y), new Point(frame.Loss.Right, y));
            var label = Text(string.Create(CultureInfo.CurrentCulture, $"{value:0} %"), muted);
            context.DrawText(label, new Point(frame.Loss.Left - label.Width - 8, y - (label.Height / 2)));
        }

        var title = Text(LossTitle, muted);
        context.DrawText(title, new Point(frame.Loss.Left, frame.Loss.Top - TopBand + 2));
    }

    private void DrawTimeAxis(DrawingContext context, Frame frame, IBrush muted)
    {
        // A step that leaves room between labels: 30 seconds when the session is young.
        var span = frame.To - frame.From;
        var step = new[] { 30, 60, 120, 300 }.Select(s => TimeSpan.FromSeconds(s))
            .FirstOrDefault(s => frame.Latency.Width * (s / span) >= 72, TimeSpan.FromMinutes(5));
        var first = new DateTimeOffset(frame.From.UtcTicks - (frame.From.UtcTicks % step.Ticks), TimeSpan.Zero) + step;
        for (var at = first; at <= frame.To; at += step)
        {
            var label = Text(at.ToLocalTime().ToString(step.TotalSeconds < 60 ? "HH:mm:ss" : "HH:mm", CultureInfo.CurrentCulture), muted);
            var x = frame.X(at) - (label.Width / 2);
            if (x >= frame.Loss.Left - 4 && x + label.Width <= frame.Loss.Right + RightGutter)
            {
                context.DrawText(label, new Point(x, frame.Loss.Bottom + 4));
            }
        }
    }

    private void DrawLegend(DrawingContext context, Frame frame, IBrush text, IBrush muted)
    {
        var title = Text(LatencyTitle, muted);
        context.DrawText(title, new Point(frame.Latency.Left, 2));

        // Line keys, the shape of the marks they stand for. Read right to left so the legend ends
        // where the plot does.
        var x = frame.Latency.Right;
        foreach (var (label, brush, thickness) in new[]
                 {
                     (DirectLabel, ContextBrush ?? Brushes.Gray, 1.5),
                     (RouteLabel, RouteBrush ?? Brushes.Teal, 2.0),
                 })
        {
            var name = Text(label, text);
            x -= name.Width;
            context.DrawText(name, new Point(x, 2));
            var y = 2 + (name.Height / 2);
            context.DrawLine(new Pen(brush, thickness, lineCap: PenLineCap.Round), new Point(x - 22, y), new Point(x - 6, y));
            x -= 22 + 18;
        }
    }

    private void DrawLossBars(DrawingContext context, Frame frame, BoostHistory history)
    {
        var brush = LossBrush ?? Brushes.Orange;
        foreach (var bucket in history.RouteLossBuckets(LossBucketWidth))
        {
            if (bucket.Lost == 0)
            {
                continue;
            }

            var left = Math.Max(frame.X(bucket.Start), frame.Loss.Left);
            var right = Math.Min(frame.X(bucket.Start + bucket.Width), frame.Loss.Right);
            // At most 24 pixels wide, and 2 short of the slice so neighbours keep a gap.
            var width = Math.Min(24, right - left - 2);
            if (width < 2)
            {
                continue;
            }

            var top = frame.LossY(bucket.Percent);
            var x = left + ((right - left - width) / 2);
            var bar = new Rect(x, top, width, frame.Loss.Bottom - top);
            // Rounded where the data ends, square where it meets the baseline.
            context.DrawRectangle(brush, null, bar, 4, 4);
            if (bar.Height > 4)
            {
                context.DrawRectangle(brush, null, new Rect(x, bar.Bottom - 4, width, 4));
            }
        }
    }

    private static void DrawSeries(
        DrawingContext context, Frame frame, IReadOnlyList<LatencySample> samples,
        Func<LatencySample, double?> value, IBrush brush, double thickness, bool wash)
    {
        var pen = new Pen(brush, thickness, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
        foreach (var run in Runs(samples, value))
        {
            if (run.Count == 1)
            {
                // One answer between two silences: a point, so it is not lost entirely.
                var only = new Point(frame.X(run[0].At), frame.LatencyY(value(run[0])!.Value));
                context.DrawEllipse(brush, null, only, thickness, thickness);
                continue;
            }

            var points = run.Select(s => new Point(frame.X(s.At), frame.LatencyY(value(s)!.Value))).ToList();
            if (wash)
            {
                var area = new StreamGeometry();
                using (var shape = area.Open())
                {
                    shape.BeginFigure(new Point(points[0].X, frame.Latency.Bottom), isFilled: true);
                    foreach (var point in points)
                    {
                        shape.LineTo(point);
                    }

                    shape.LineTo(new Point(points[^1].X, frame.Latency.Bottom));
                    shape.EndFigure(isClosed: true);
                }

                using (context.PushOpacity(0.1))
                {
                    context.DrawGeometry(brush, null, area);
                }
            }

            var line = new StreamGeometry();
            using (var shape = line.Open())
            {
                shape.BeginFigure(points[0], isFilled: false);
                foreach (var point in points.Skip(1))
                {
                    shape.LineTo(point);
                }

                shape.EndFigure(isClosed: false);
            }

            context.DrawGeometry(null, pen, line);
        }
    }

    /// <summary>The stretches of consecutive answers, between the probes that got none.</summary>
    private static List<List<LatencySample>> Runs(IReadOnlyList<LatencySample> samples, Func<LatencySample, double?> value)
    {
        var runs = new List<List<LatencySample>>();
        List<LatencySample>? current = null;
        foreach (var sample in samples)
        {
            if (value(sample) is null)
            {
                current = null;
                continue;
            }

            if (current is null)
            {
                current = [];
                runs.Add(current);
            }

            current.Add(sample);
        }

        return runs;
    }

    private void DrawEnds(DrawingContext context, Frame frame, IReadOnlyList<LatencySample> samples, IBrush text, IBrush muted)
    {
        var route = LastAnswer(samples, s => s.RoutedMilliseconds);
        var direct = LastAnswer(samples, s => s.DirectMilliseconds);
        double? routeY = null;

        if (route is { } r)
        {
            var point = new Point(frame.X(r.At), frame.LatencyY(r.RoutedMilliseconds!.Value));
            Dot(context, point, RouteBrush ?? Brushes.Teal);
            var label = Text(Milliseconds(r.RoutedMilliseconds.Value), text, strong: true);
            routeY = point.Y;
            context.DrawText(label, new Point(frame.Latency.Right + 10, point.Y - (label.Height / 2)));
        }

        if (direct is { } d)
        {
            var point = new Point(frame.X(d.At), frame.LatencyY(d.DirectMilliseconds!.Value));
            Dot(context, point, ContextBrush ?? Brushes.Gray);

            // Labels that would touch are not pushed apart, which would part them from their
            // lines: the route keeps its label, and the direct figure is still in the tiles above,
            // the tooltip and the table.
            if (routeY is not { } taken || Math.Abs(taken - point.Y) >= 16)
            {
                var label = Text(Milliseconds(d.DirectMilliseconds.Value), muted);
                context.DrawText(label, new Point(frame.Latency.Right + 10, point.Y - (label.Height / 2)));
            }
        }
    }

    private static LatencySample? LastAnswer(IReadOnlyList<LatencySample> samples, Func<LatencySample, double?> value)
    {
        for (var i = samples.Count - 1; i >= 0; i--)
        {
            if (value(samples[i]) is not null)
            {
                return samples[i];
            }
        }

        return null;
    }

    /// <summary>An 8-pixel dot in a 2-pixel ring of the surface, so it reads where it crosses a line.</summary>
    private void Dot(DrawingContext context, Point at, IBrush brush)
    {
        context.DrawEllipse(SurfaceBrush ?? Brushes.Black, null, at, 6, 6);
        context.DrawEllipse(brush, null, at, 4, 4);
    }

    private void DrawCrosshair(
        DrawingContext context, Frame frame, IReadOnlyList<LatencySample> samples, int index, BoostHistory history,
        IBrush text, IBrush muted)
    {
        var sample = samples[index];
        var x = Math.Round(frame.X(sample.At)) + 0.5;
        var hair = new Pen(muted, 1);
        context.DrawLine(hair, new Point(x, frame.Latency.Top), new Point(x, frame.Latency.Bottom));
        context.DrawLine(hair, new Point(x, frame.Loss.Top), new Point(x, frame.Loss.Bottom));

        if (sample.DirectMilliseconds is { } directValue)
        {
            Dot(context, new Point(x, frame.LatencyY(directValue)), ContextBrush ?? Brushes.Gray);
        }

        if (sample.RoutedMilliseconds is { } routeValue)
        {
            Dot(context, new Point(x, frame.LatencyY(routeValue)), RouteBrush ?? Brushes.Teal);
        }

        // Values lead and labels follow: the reader has the series and wants the number.
        var bucket = history.RouteLossBuckets(LossBucketWidth)
            .LastOrDefault(b => b.Start <= sample.At && sample.At < b.Start + b.Width);
        var rows = new List<(IBrush? Key, double KeyThickness, FormattedText Value, FormattedText Label)>
        {
            (RouteBrush, 2, Text(sample.RoutedMilliseconds is { } rv ? Milliseconds(rv) : RouteMissingLabel, text, strong: true), Text(RouteLabel, muted)),
            (ContextBrush, 1.5, Text(sample.DirectMilliseconds is { } dv ? Milliseconds(dv) : NoAnswerLabel, text, strong: true), Text(DirectLabel, muted)),
        };
        if (bucket.Probes > 0)
        {
            rows.Add((null, 0, Text(string.Create(CultureInfo.CurrentCulture, $"{bucket.Percent:0.#} %"), text, strong: true), Text(LossTitle, muted)));
        }

        var time = Text(sample.At.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture), muted);
        var valueWidth = rows.Max(r => r.Value.Width);
        var width = 12 + 20 + valueWidth + 8 + rows.Max(r => r.Label.Width) + 12;
        width = Math.Max(width, time.Width + 24);
        var rowHeight = time.Height + 4;
        var height = 10 + time.Height + 6 + (rows.Count * rowHeight) + 6;

        var left = x + 12 + width <= Bounds.Width ? x + 12 : x - 12 - width;
        var box = new Rect(Math.Max(0, left), frame.Latency.Top, width, height);
        context.DrawRectangle(TipBackground ?? Brushes.Black, new Pen(TipBorderBrush ?? Brushes.Gray, 1), box, 6, 6);
        context.DrawText(time, new Point(box.Left + 12, box.Top + 10));

        var y = box.Top + 10 + time.Height + 6;
        foreach (var (key, thickness, value, label) in rows)
        {
            var middle = y + (value.Height / 2);
            if (key is not null)
            {
                context.DrawLine(new Pen(key, thickness, lineCap: PenLineCap.Round),
                    new Point(box.Left + 12, middle), new Point(box.Left + 26, middle));
            }

            context.DrawText(value, new Point(box.Left + 32, y));
            context.DrawText(label, new Point(box.Left + 32 + valueWidth + 8, y));
            y += rowHeight;
        }
    }

    // -- the crosshair follows the pointer, or the arrow keys -----------------------------

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var samples = History?.Samples ?? [];
        if (Layout(samples) is not { } frame)
        {
            return;
        }

        var x = e.GetPosition(this).X;
        var nearest = Enumerable.Range(0, samples.Count)
            .MinBy(i => Math.Abs(frame.X(samples[i].At) - x));
        SetHover(nearest);
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        SetHover(null);
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        Focus();
    }

    protected override void OnLostFocus(FocusChangedEventArgs e)
    {
        base.OnLostFocus(e);
        SetHover(null);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        var count = History?.Samples.Count ?? 0;
        if (count == 0)
        {
            return;
        }

        var at = _hover ?? count;
        int? next = e.Key switch
        {
            Key.Left => Math.Max(0, at - 1),
            Key.Right => Math.Min(count - 1, at + 1),
            Key.Home => 0,
            Key.End => count - 1,
            Key.Escape => null,
            _ => _hover,
        };

        if (e.Key is Key.Left or Key.Right or Key.Home or Key.End or Key.Escape)
        {
            SetHover(next);
            e.Handled = true;
        }
    }

    private void SetHover(int? index)
    {
        if (_hover != index)
        {
            _hover = index;
            InvalidateVisual();
        }
    }
}
