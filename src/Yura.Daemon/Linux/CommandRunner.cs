using System.Diagnostics;
using System.Text;

namespace Yura.Daemon.Linux;

/// <summary>Result of running a privileged helper.</summary>
public sealed record CommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>Operator-facing failure text, preferring stderr but never empty.</summary>
    public string FailureText =>
        StandardError.Trim() is { Length: > 0 } err ? err
        : StandardOutput.Trim() is { Length: > 0 } outp ? outp
        : $"exited with status {ExitCode}";
}

/// <summary>
/// Runs the small set of external tools the daemon depends on, with every invocation logged.
/// </summary>
/// <remarks>
/// The daemon shells out to <c>nft</c> and <c>ip</c> rather than binding libnftnl or writing
/// netlink by hand. That is a deliberate trade: these are the exact commands the routing
/// spike proved, they can be copied out of the log and re-run by hand during an incident,
/// and a reviewer can audit what the daemon does to a machine without reading netlink
/// serialisation code.
///
/// Nothing user-supplied is ever interpolated into a shell. Arguments are passed as an argv
/// array and no shell is involved, so quoting is not a security boundary here.
/// </remarks>
public sealed class CommandRunner
{
    private readonly Action<string> _log;

    public CommandRunner(Action<string> log) => _log = log;

    public async Task<CommandResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? standardInput = null,
        CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        _log($"exec: {fileName} {string.Join(' ', arguments)}");
        if (standardInput is not null)
        {
            _log($"stdin:\n{Indent(standardInput)}");
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            return new CommandResult(-1, string.Empty, $"could not start {fileName}");
        }

        // Read both pipes concurrently: a tool that fills stderr while we block on stdout
        // would deadlock.
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken)
                .ConfigureAwait(false);
            process.StandardInput.Close();
        }

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        var result = new CommandResult(
            process.ExitCode,
            await stdoutTask.ConfigureAwait(false),
            await stderrTask.ConfigureAwait(false));

        if (!result.Succeeded)
        {
            _log($"failed ({result.ExitCode}): {result.FailureText}");
        }

        return result;
    }

    private static string Indent(string text) =>
        string.Join('\n', text.Split('\n').Select(line => "    " + line));
}
