using System.Collections.Concurrent;
using System.Diagnostics;

namespace Yura.App.Services;

/// <summary>Stores proxy passwords outside the configuration file.</summary>
/// <remarks>
/// The configuration file holds only a reference. A password that lands in a JSON file is a
/// password in every backup, every sync tool and every support bundle from then on, so the
/// indirection is the point rather than an implementation detail.
/// </remarks>
public interface ISecretStore
{
    /// <summary>True when secrets can actually be persisted on this machine.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// A noun phrase naming where secrets go, e.g. "the desktop secret service". Callers
    /// pick the surrounding sentence from <see cref="IsAvailable"/>, so this must stay a
    /// phrase rather than growing a clause of its own.
    /// </summary>
    string Description { get; }

    Task<bool> SetAsync(string reference, string secret, CancellationToken cancellationToken = default);

    Task<string?> GetAsync(string reference, CancellationToken cancellationToken = default);

    Task DeleteAsync(string reference, CancellationToken cancellationToken = default);
}

/// <summary>
/// Freedesktop Secret Service backend, reached through <c>secret-tool</c>.
/// </summary>
/// <remarks>
/// Shelling out to <c>secret-tool</c> rather than binding libsecret keeps the dependency to
/// a binary that ships with libsecret on every desktop distribution, and works against
/// whichever agent is running — gnome-keyring or kwallet — because both implement the same
/// D-Bus interface. Secrets never appear on a command line: they are written to the tool's
/// stdin.
/// </remarks>
public sealed class SecretToolSecretStore : ISecretStore
{
    private const string Attribute = "yura-proxy";
    private readonly string? _toolPath;

    public SecretToolSecretStore() => _toolPath = Which("secret-tool");

    public bool IsAvailable => _toolPath is not null;

    public string Description => "the desktop secret service";

    public async Task<bool> SetAsync(string reference, string secret, CancellationToken cancellationToken = default)
    {
        if (_toolPath is null)
        {
            return false;
        }

        var result = await RunAsync(
            ["store", "--label", $"Yura proxy {reference}", Attribute, reference],
            secret,
            cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0;
    }

    public async Task<string?> GetAsync(string reference, CancellationToken cancellationToken = default)
    {
        if (_toolPath is null)
        {
            return null;
        }

        var result = await RunAsync(["lookup", Attribute, reference], null, cancellationToken)
            .ConfigureAwait(false);
        // secret-tool exits non-zero when nothing matches, which is not an error here.
        return result.ExitCode == 0 && result.Output.Length > 0 ? result.Output : null;
    }

    public async Task DeleteAsync(string reference, CancellationToken cancellationToken = default)
    {
        if (_toolPath is null)
        {
            return;
        }

        await RunAsync(["clear", Attribute, reference], null, cancellationToken).ConfigureAwait(false);
    }

    private async Task<(int ExitCode, string Output)> RunAsync(
        string[] arguments, string? standardInput, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _toolPath!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return (-1, string.Empty);
            }

            if (standardInput is not null)
            {
                // secret-tool reads the secret from stdin precisely so it never appears in
                // the process table.
                await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken)
                    .ConfigureAwait(false);
                process.StandardInput.Close();
            }

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            // The tool appends a newline that is not part of the secret.
            return (process.ExitCode, output.TrimEnd('\n'));
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or OperationCanceledException)
        {
            return (-1, string.Empty);
        }
    }

    private static string? Which(string tool)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "/usr/bin:/bin";
        foreach (var directory in path.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(directory, tool);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}

/// <summary>Used when no secret service is available. Keeps passwords in memory only.</summary>
/// <remarks>
/// Deliberately forgetful rather than falling back to a file. Writing a password to disk
/// because the keyring was missing would be a silent downgrade of the one guarantee this
/// interface exists to make.
/// </remarks>
public sealed class InMemorySecretStore : ISecretStore
{
    private readonly ConcurrentDictionary<string, string> _secrets = new();

    public bool IsAvailable => false;

    public string Description => "memory";

    public Task<bool> SetAsync(string reference, string secret, CancellationToken cancellationToken = default)
    {
        _secrets[reference] = secret;
        return Task.FromResult(false);
    }

    public Task<string?> GetAsync(string reference, CancellationToken cancellationToken = default) =>
        Task.FromResult(_secrets.GetValueOrDefault(reference));

    public Task DeleteAsync(string reference, CancellationToken cancellationToken = default)
    {
        _secrets.TryRemove(reference, out _);
        return Task.CompletedTask;
    }
}

/// <summary>
/// A persistent store, with a copy of every secret set this session kept in memory beside it.
/// </summary>
/// <remarks>
/// What the app runs with. When the persistent store cannot take a secret — no
/// <c>secret-tool</c>, or one with no secret service running behind it — the secret still
/// works until the app exits, which is what the editor tells the user will happen. Without the
/// copy it was silently discarded: the proxy was saved referring to a secret nothing held, and
/// the daemon was handed an exit without its password or key.
///
/// The copy is read first, so a secret changed this session is the one used even when the
/// persistent store still holds the previous one.
/// </remarks>
public sealed class SessionBackedSecretStore(ISecretStore persistent) : ISecretStore
{
    private readonly InMemorySecretStore _session = new();

    public bool IsAvailable => persistent.IsAvailable;

    public string Description => persistent.Description;

    /// <returns>Whether the persistent store took it. It is kept for the session either way.</returns>
    public async Task<bool> SetAsync(string reference, string secret, CancellationToken cancellationToken = default)
    {
        await _session.SetAsync(reference, secret, cancellationToken).ConfigureAwait(false);
        return await persistent.SetAsync(reference, secret, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> GetAsync(string reference, CancellationToken cancellationToken = default) =>
        await _session.GetAsync(reference, cancellationToken).ConfigureAwait(false)
        ?? await persistent.GetAsync(reference, cancellationToken).ConfigureAwait(false);

    public async Task DeleteAsync(string reference, CancellationToken cancellationToken = default)
    {
        await _session.DeleteAsync(reference, cancellationToken).ConfigureAwait(false);
        await persistent.DeleteAsync(reference, cancellationToken).ConfigureAwait(false);
    }
}
