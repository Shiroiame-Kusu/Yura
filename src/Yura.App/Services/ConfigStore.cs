using System.Text.Json;
using System.Text.Json.Serialization;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>A proxy as it is written to disk. Never carries the password itself.</summary>
public sealed class PersistedProxy
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public required ProxyProtocol Protocol { get; init; }

    public required string Host { get; init; }

    public required ushort Port { get; init; }

    public string? Username { get; init; }

    /// <summary>Key into the secret store. The secret itself lives there, not here.</summary>
    public string? PasswordRef { get; init; }

    public static PersistedProxy From(ProxyEndpoint endpoint) => new()
    {
        Id = endpoint.Id,
        Name = endpoint.Name,
        Protocol = endpoint.Protocol,
        Host = endpoint.Host,
        Port = endpoint.Port,
        Username = endpoint.Username,
        PasswordRef = endpoint.PasswordRef,
    };

    public ProxyEndpoint ToEndpoint() => new()
    {
        Id = Id,
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        PasswordRef = PasswordRef,
    };
}

/// <summary>User preferences that survive a restart.</summary>
public sealed class PersistedSettings
{
    public string Theme { get; set; } = "dark";

    public string Language { get; set; } = "en";

    public bool ReducedMotion { get; set; }
}

/// <summary>The whole configuration file.</summary>
public sealed class ConfigDocument
{
    /// <summary>Bumped when the shape changes, so a future build can migrate rather than guess.</summary>
    public int Version { get; set; } = 1;

    public PersistedSettings Settings { get; set; } = new();

    public List<PersistedProxy> Proxies { get; set; } = [];

    /// <summary>Only persistent rules. See <see cref="ConfigStore.SaveAsync"/>.</summary>
    public List<RuleDto> Rules { get; set; } = [];
}

/// <summary>What happened when the configuration was loaded.</summary>
public sealed record ConfigLoadResult(ConfigDocument Document, string? Warning);

/// <summary>
/// Reads and writes <c>~/.config/Yura/config.json</c>.
/// </summary>
/// <remarks>
/// The application owns the configuration, not the daemon. The daemon runs as root, and a
/// root process writing into a user's home directory leaves root-owned files that the
/// application can then no longer rewrite. So the app is the source of truth and pushes
/// state to the daemon whenever it connects; the daemon holds nothing across a restart.
///
/// Writes are atomic — a temporary file in the same directory followed by a rename — so a
/// crash or a full disk mid-write cannot leave a half-written config that fails to parse on
/// next launch.
/// </remarks>
public sealed class ConfigStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly SemaphoreSlim _writeGate = new(1, 1);

    public ConfigStore(string? directory = null)
    {
        Directory = directory ?? DefaultDirectory();
        FilePath = Path.Combine(Directory, "config.json");
    }

    public string Directory { get; }

    public string FilePath { get; }

    /// <summary>
    /// <c>$XDG_CONFIG_HOME/Yura</c>, falling back to <c>~/.config/Yura</c>.
    /// </summary>
    public static string DefaultDirectory()
    {
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        var root = !string.IsNullOrWhiteSpace(xdg)
            ? xdg
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
        return Path.Combine(root, "Yura");
    }

    /// <summary>
    /// Loads the configuration, degrading to defaults rather than failing to start.
    /// </summary>
    /// <remarks>
    /// An unreadable config is preserved as <c>config.json.corrupt</c> instead of being
    /// overwritten. Losing a user's proxy list because one byte went wrong is not an
    /// acceptable outcome, and the warning gives them something to act on.
    /// </remarks>
    public ConfigLoadResult Load()
    {
        if (!File.Exists(FilePath))
        {
            return new ConfigLoadResult(new ConfigDocument(), null);
        }

        string text;
        try
        {
            text = File.ReadAllText(FilePath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new ConfigLoadResult(new ConfigDocument(),
                $"Could not read {FilePath}: {e.Message}. Starting with an empty configuration.");
        }

        try
        {
            var document = JsonSerializer.Deserialize<ConfigDocument>(text, Json);
            if (document is null)
            {
                throw new JsonException("the file contained no object");
            }

            if (document.Version > 1)
            {
                return new ConfigLoadResult(new ConfigDocument(),
                    $"{FilePath} was written by a newer version of Yura (format {document.Version}). " +
                    "It has been left alone and this session starts empty.");
            }

            return new ConfigLoadResult(document, null);
        }
        catch (JsonException e)
        {
            var backup = FilePath + ".corrupt";
            try
            {
                File.Move(FilePath, backup, overwrite: true);
            }
            catch (Exception move) when (move is IOException or UnauthorizedAccessException)
            {
                // Keeping the original is still better than deleting it.
            }

            return new ConfigLoadResult(new ConfigDocument(),
                $"{FilePath} could not be parsed ({e.Message}). It was moved to {backup} and " +
                "this session starts with an empty configuration.");
        }
    }

    /// <summary>
    /// Writes the configuration atomically.
    /// </summary>
    /// <param name="rules">
    /// Every rule in the store. Only <see cref="RuleLifetime.Persistent"/> ones are written:
    /// an instance rule names a pid and a start time, which mean nothing after a reboot, and
    /// a session rule is scoped to a daemon that has since exited.
    /// </param>
    public async Task<string?> SaveAsync(
        PersistedSettings settings,
        IEnumerable<ProxyEndpoint> proxies,
        IEnumerable<RoutingRule> rules,
        CancellationToken cancellationToken = default)
    {
        var document = new ConfigDocument
        {
            Version = 1,
            Settings = settings,
            Proxies = proxies.Select(PersistedProxy.From).ToList(),
            Rules = rules.Where(r => r.Lifetime == RuleLifetime.Persistent)
                         .Select(RuleDto.From)
                         .ToList(),
        };

        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            // The directory may hold nothing secret today, but it names every proxy the user
            // reaches; there is no reason for it to be world-readable.
            TrySetMode(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var temporary = FilePath + ".tmp";
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(document, Json), cancellationToken)
                .ConfigureAwait(false);
            TrySetMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            // Rename is atomic within a filesystem: readers see either the old file or the
            // new one, never a partial write.
            File.Move(temporary, FilePath, overwrite: true);
            return null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return $"Could not save settings to {FilePath}: {e.Message}";
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private static void TrySetMode(string path, UnixFileMode mode)
    {
        try
        {
            File.SetUnixFileMode(path, mode);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Best effort: a filesystem without Unix modes is not a reason to lose the config.
        }
    }
}
