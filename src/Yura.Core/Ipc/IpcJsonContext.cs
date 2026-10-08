using System.Text.Json;
using System.Text.Json.Serialization;
using Yura.Core.Connections;
using Yura.Core.Net;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.Core.Ipc;

/// <summary>
/// An enum written as its camelCase name, which is how the protocol and the configuration file
/// have always written them, by a converter the JSON source generator can see.
/// </summary>
/// <remarks>
/// The non-generic <see cref="JsonStringEnumConverter"/> makes a converter for each enum type
/// at run time, which NativeAOT cannot do. This one is made at compile time, once per enum
/// that a context's options name.
/// </remarks>
public sealed class CamelCaseEnumConverter<TEnum>() : JsonStringEnumConverter<TEnum>(JsonNamingPolicy.CamelCase)
    where TEnum : struct, Enum;

/// <summary>
/// The wire format of <see cref="IpcRequest"/> and <see cref="IpcResponse"/>, generated at
/// compile time: NativeAOT has no reflection-based serialization to fall back on.
/// </summary>
/// <remarks>
/// Every enum that crosses the socket has to be listed here. One left out travels as a number,
/// which the other side reads as some other value or rejects, so a test walks the contract
/// types and fails on any enum not written as a camelCase name.
///
/// A contract member with a default is settable rather than init-only, for the same kind of
/// reason. The generated serializer builds a type's init-only members in one object initializer
/// and gives any the JSON leaves out <c>default</c>, not its initializer's value: a rule sent
/// without "enabled", as yura-daemon ctl users write them, arrived disabled, and one without
/// "hosts" crashed the daemon. A test reads every contract type from JSON holding only its
/// required members.
/// </remarks>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters =
    [
        typeof(CamelCaseEnumConverter<CapabilityState>),
        typeof(CamelCaseEnumConverter<ConnectionState>),
        typeof(CamelCaseEnumConverter<DescendantPolicy>),
        typeof(CamelCaseEnumConverter<DnsPolicy>),
        typeof(CamelCaseEnumConverter<NatFiltering>),
        typeof(CamelCaseEnumConverter<NatMapping>),
        typeof(CamelCaseEnumConverter<NatVerdict>),
        typeof(CamelCaseEnumConverter<ProcessSelectorKind>),
        typeof(CamelCaseEnumConverter<ProxyProtocol>),
        typeof(CamelCaseEnumConverter<RouteObservation>),
        typeof(CamelCaseEnumConverter<RuleLifetime>),
        typeof(CamelCaseEnumConverter<RuleOrigin>),
        typeof(CamelCaseEnumConverter<TransportFilter>),
        typeof(CamelCaseEnumConverter<TransportProtocol>),
    ])]
[JsonSerializable(typeof(IpcRequest))]
[JsonSerializable(typeof(IpcResponse))]
public sealed partial class IpcJsonContext : JsonSerializerContext;
