using System.Globalization;
using Avalonia.Data;
using Avalonia.Data.Converters;
using Yura.App.ViewModels;

namespace Yura.App.Converters;

/// <summary>
/// Two-way binding between an enum property and a set of radio buttons.
/// </summary>
/// <remarks>
/// Converting back only when the button is being checked matters: a radio group raises
/// <c>false</c> on the outgoing button before <c>true</c> on the incoming one, and acting
/// on the <c>false</c> would clear the selection.
/// </remarks>
public sealed class EnumToBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is null || parameter is not string name)
        {
            return false;
        }

        return string.Equals(value.ToString(), name, StringComparison.Ordinal);
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not true || parameter is not string name)
        {
            return BindingOperations.DoNothing;
        }

        var enumType = Nullable.GetUnderlyingType(targetType) ?? targetType;
        return Enum.TryParse(enumType, name, ignoreCase: false, out var parsed)
            ? parsed
            : BindingOperations.DoNothing;
    }
}

/// <summary>Renders a <see cref="Yura.Core.Rules.DnsPolicy"/> as the choice it represents.</summary>
public sealed class DnsPolicyDisplayConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Yura.Core.Rules.DnsPolicy policy
            ? Yura.App.Localization.Loc.Current[policy == Yura.Core.Rules.DnsPolicy.ThroughProxy
                ? "Settings.Dns.ThroughProxy"
                : "Settings.Dns.Direct"]
            : value?.ToString();

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        BindingOperations.DoNothing;
}

/// <summary>Renders a <see cref="Yura.Core.Proxies.ProxyProtocol"/> the way it is written.</summary>
public sealed class ProtocolDisplayConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Yura.Core.Proxies.ProxyProtocol protocol
            ? protocol switch
            {
                Yura.Core.Proxies.ProxyProtocol.Socks5 => "SOCKS5",
                Yura.Core.Proxies.ProxyProtocol.Http => "HTTP",
                Yura.Core.Proxies.ProxyProtocol.Https => "HTTPS",
                _ => protocol.ToString(),
            }
            : value?.ToString();

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        BindingOperations.DoNothing;
}
