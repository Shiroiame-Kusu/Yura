using System.Globalization;

namespace Yura.Core.Net;

/// <summary>An inclusive TCP/UDP port range.</summary>
public readonly record struct PortRange(ushort From, ushort To)
{
    public static PortRange Single(ushort port) => new(port, port);

    public bool IsSingle => From == To;

    public bool Contains(ushort port) => port >= From && port <= To;

    /// <summary>Parses <c>"443"</c> or <c>"1000-2000"</c>. Returns false rather than throwing.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, out PortRange range)
    {
        range = default;
        text = text.Trim();
        if (text.IsEmpty)
        {
            return false;
        }

        var dash = text.IndexOf('-');
        if (dash < 0)
        {
            if (!ushort.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var single))
            {
                return false;
            }

            range = Single(single);
            return true;
        }

        if (!ushort.TryParse(text[..dash].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var from) ||
            !ushort.TryParse(text[(dash + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var to))
        {
            return false;
        }

        if (from > to)
        {
            (from, to) = (to, from);
        }

        range = new PortRange(from, to);
        return true;
    }

    public override string ToString() =>
        IsSingle
            ? From.ToString(CultureInfo.InvariantCulture)
            : string.Create(CultureInfo.InvariantCulture, $"{From}-{To}");
}
