using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Yura.App.Services;
using Yura.Core.Ipc;

namespace Yura.Core.Tests;

/// <summary>
/// The JSON between the app and the daemon, and in the configuration file, now that the
/// serializers are generated at compile time for NativeAOT.
/// </summary>
/// <remarks>
/// A generated serializer only knows what it was told. An enum missing from a context's list is
/// written as a number, with no warning anywhere, and a property shape that differs from before
/// leaves files written by earlier versions unreadable. So these walk the types the way the
/// serializer does, and compare against the reflection serializer the generated ones replace.
/// </remarks>
public sealed class JsonContextTests
{
    /// <summary>The protocol's options before the change: reflection, camelCase, enums as names.</summary>
    private static readonly JsonSerializerOptions WireBefore = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    /// <summary>The configuration file's options before the change: the same, indented.</summary>
    private static readonly JsonSerializerOptions FileBefore = new(WireBefore) { WriteIndented = true };

    [Fact]
    public void Every_enum_on_the_wire_is_written_as_its_camelCase_name()
    {
        var enums = EnumsReachableFrom(typeof(IpcRequest)).Union(EnumsReachableFrom(typeof(IpcResponse)));
        AssertWrittenAsNames(enums, IpcJsonContext.Default);
    }

    [Fact]
    public void Every_enum_in_the_configuration_file_is_written_as_its_camelCase_name() =>
        AssertWrittenAsNames(EnumsReachableFrom(typeof(ConfigDocument)), ConfigJsonContext.Default);

    [Theory]
    [InlineData(typeof(IpcRequest))]
    [InlineData(typeof(IpcResponse))]
    public void The_wire_carries_what_it_carried_before(Type type) =>
        AssertSameAsBefore(type, WireBefore, IpcJsonContext.Default);

    [Fact]
    public void The_configuration_file_reads_and_writes_as_it_did_before() =>
        AssertSameAsBefore(typeof(ConfigDocument), FileBefore, ConfigJsonContext.Default);

    [Fact]
    public void A_member_left_out_on_the_wire_keeps_its_default_as_before() =>
        AssertAbsentMembersKeepDefaults(
            ClassesReachableFrom(typeof(IpcRequest)).Union(ClassesReachableFrom(typeof(IpcResponse))),
            WireBefore, IpcJsonContext.Default);

    [Fact]
    public void A_member_left_out_of_the_configuration_file_keeps_its_default_as_before() =>
        AssertAbsentMembersKeepDefaults(ClassesReachableFrom(typeof(ConfigDocument)), FileBefore, ConfigJsonContext.Default);

    /// <summary>
    /// Read from JSON that has only the required members, the way a hand-written <c>ctl</c> body
    /// or a file from an older version comes, every other member has to keep its default.
    /// </summary>
    /// <remarks>
    /// The generated serializer creates a type with init-only members in one object initializer,
    /// and gives a member the JSON leaves out <c>default</c> rather than the value its initializer
    /// sets: a list came out null instead of empty, and <c>enabled</c> false instead of true.
    /// </remarks>
    private static void AssertAbsentMembersKeepDefaults(
        IEnumerable<Type> types, JsonSerializerOptions before, JsonSerializerContext now)
    {
        var wrong = new List<string>();
        foreach (var type in types.Where(t => t.GetConstructor(Type.EmptyTypes) is not null).OrderBy(t => t.Name, StringComparer.Ordinal))
        {
            var sparse = (JsonObject)JsonNode.Parse(JsonSerializer.Serialize(Sample(type, depth: 0), type, before))!;
            var required = Serialized(type)
                .Where(p => p.IsDefined(typeof(RequiredMemberAttribute)))
                .Select(p => before.PropertyNamingPolicy!.ConvertName(p.Name))
                .ToHashSet(StringComparer.Ordinal);
            foreach (var name in sparse.Select(member => member.Key).Where(name => !required.Contains(name)).ToList())
            {
                sparse.Remove(name);
            }

            var json = sparse.ToJsonString();
            var expected = JsonSerializer.Serialize(JsonSerializer.Deserialize(json, type, before), type, before);
            var actual = JsonSerializer.Serialize(JsonSerializer.Deserialize(json, type, now), type, before);
            if (expected != actual)
            {
                wrong.Add($"{type.Name}\n  before: {expected}\n  now:    {actual}");
            }
        }

        Assert.True(wrong.Count == 0, string.Join("\n", wrong));
    }

    /// <summary>Every one of our classes a serializer of <paramref name="root"/> can meet.</summary>
    private static HashSet<Type> ClassesReachableFrom(Type root)
    {
        var classes = new HashSet<Type>();
        var seen = new HashSet<Type>();

        void Visit(Type type)
        {
            type = Nullable.GetUnderlyingType(type) ?? type;
            if (!seen.Add(type) || type.IsPrimitive || type == typeof(string) || type.IsEnum)
            {
                return;
            }

            if (type.IsArray)
            {
                Visit(type.GetElementType()!);
            }
            else if (type.IsGenericType && typeof(IEnumerable).IsAssignableFrom(type))
            {
                foreach (var argument in type.GetGenericArguments())
                {
                    Visit(argument);
                }
            }
            else if (IsOurs(type))
            {
                classes.Add(type);
                foreach (var property in Serialized(type))
                {
                    Visit(property.PropertyType);
                }
            }
        }

        Visit(root);
        return classes;
    }

    /// <summary>
    /// Written now as before, for an instance with every member set, and what was written before
    /// reads back to the same thing.
    /// </summary>
    private static void AssertSameAsBefore(Type type, JsonSerializerOptions before, JsonSerializerContext now)
    {
        var value = Sample(type, depth: 0);
        var written = JsonSerializer.Serialize(value, type, before);

        Assert.Equal(written, JsonSerializer.Serialize(value, type, now));
        var read = JsonSerializer.Deserialize(written, type, now);
        Assert.Equal(written, JsonSerializer.Serialize(read, type, now));
    }

    private static void AssertWrittenAsNames(IEnumerable<Type> enums, JsonSerializerContext context)
    {
        var wrong = new List<string>();
        foreach (var type in enums.OrderBy(t => t.Name, StringComparer.Ordinal))
        {
            // The last member, so a converter that is missing cannot pass by writing 0.
            var values = Enum.GetValues(type);
            var value = values.GetValue(values.Length - 1)!;
            var expected = $"\"{JsonNamingPolicy.CamelCase.ConvertName(value.ToString()!)}\"";
            try
            {
                var json = JsonSerializer.Serialize(value, type, context);
                if (json != expected)
                {
                    wrong.Add($"{type.Name} is written as {json}, not {expected}");
                }
                else if (!Equals(JsonSerializer.Deserialize(json, type, context), value))
                {
                    wrong.Add($"{type.Name} does not read back from {json}");
                }
            }
            catch (Exception e) when (e is NotSupportedException or InvalidOperationException or JsonException)
            {
                wrong.Add($"{type.Name}: {e.Message}");
            }
        }

        Assert.True(wrong.Count == 0, string.Join("\n", wrong));
    }

    /// <summary>Every enum a serializer of <paramref name="root"/> can meet.</summary>
    private static HashSet<Type> EnumsReachableFrom(Type root)
    {
        var enums = new HashSet<Type>();
        var seen = new HashSet<Type>();

        void Visit(Type type)
        {
            type = Nullable.GetUnderlyingType(type) ?? type;
            if (!seen.Add(type) || type.IsPrimitive || type == typeof(string))
            {
                return;
            }

            if (type.IsEnum)
            {
                enums.Add(type);
            }
            else if (type.IsArray)
            {
                Visit(type.GetElementType()!);
            }
            else if (type.IsGenericType && typeof(IEnumerable).IsAssignableFrom(type))
            {
                foreach (var argument in type.GetGenericArguments())
                {
                    Visit(argument);
                }
            }
            else if (IsOurs(type))
            {
                // Framework types such as DateTimeOffset have converters of their own and are
                // written as one value, not member by member.
                foreach (var property in Serialized(type))
                {
                    Visit(property.PropertyType);
                }
            }
        }

        Visit(root);
        return enums;
    }

    private static bool IsOurs(Type type) =>
        type.Assembly.GetName().Name?.StartsWith("Yura", StringComparison.Ordinal) == true;

    private static IEnumerable<PropertyInfo> Serialized(Type type) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetIndexParameters().Length == 0 && !p.IsDefined(typeof(JsonIgnoreAttribute)));

    /// <summary>An instance with every serialized member set to something other than its default.</summary>
    private static object? Sample(Type type, int depth)
    {
        if (Nullable.GetUnderlyingType(type) is { } underlying)
        {
            return Sample(underlying, depth);
        }

        if (type == typeof(string)) return "sample";
        if (type == typeof(bool)) return true;
        if (type == typeof(Guid)) return Guid.Parse("6a1b2c3d-0000-4000-8000-0000000000aa");
        if (type == typeof(DateTimeOffset)) return new DateTimeOffset(2026, 10, 6, 12, 0, 0, TimeSpan.Zero);
        if (type == typeof(DateTime)) return new DateTime(2026, 10, 6, 12, 0, 0, DateTimeKind.Utc);
        if (type == typeof(TimeSpan)) return TimeSpan.FromSeconds(7);
        if (type.IsEnum)
        {
            var values = Enum.GetValues(type);
            return values.GetValue(values.Length - 1);
        }

        if (type.IsPrimitive || type == typeof(decimal))
        {
            return Convert.ChangeType(7, type, System.Globalization.CultureInfo.InvariantCulture);
        }

        if (depth > 6)
        {
            return null;
        }

        if (type.IsArray)
        {
            var element = type.GetElementType()!;
            var array = Array.CreateInstance(element, 1);
            array.SetValue(Sample(element, depth + 1), 0);
            return array;
        }

        if (type.IsGenericType && typeof(IEnumerable).IsAssignableFrom(type))
        {
            var arguments = type.GetGenericArguments();
            if (arguments.Length == 2)
            {
                var dictionary = (IDictionary)Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(arguments))!;
                dictionary[Sample(arguments[0], depth + 1)!] = Sample(arguments[1], depth + 1);
                return dictionary;
            }

            var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(arguments[0]))!;
            list.Add(Sample(arguments[0], depth + 1));
            return list;
        }

        if (type.GetConstructor(Type.EmptyTypes) is null)
        {
            return null;
        }

        var instance = Activator.CreateInstance(type)!;
        foreach (var property in Serialized(type).Where(p => p.CanWrite))
        {
            property.SetValue(instance, Sample(property.PropertyType, depth + 1));
        }

        return instance;
    }
}
