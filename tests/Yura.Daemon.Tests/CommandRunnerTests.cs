using Yura.Daemon.Linux;

namespace Yura.Daemon.Tests;

/// <summary>Running the external tools the daemon depends on.</summary>
public sealed class CommandRunnerTests
{
    [Fact]
    public async Task A_tool_that_is_not_installed_is_an_answer_not_a_crash()
    {
        // Process.Start throws for a missing executable rather than returning false, and the
        // exception went through the startup checks and out of Main: a machine without
        // wireguard-tools could not run the daemon at all, although WireGuard is optional.
        var log = new List<string>();
        var runner = new CommandRunner(log.Add);

        var result = await runner.RunAsync(
            "yura-test-no-such-tool", ["--version"], cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Succeeded);
        Assert.Equal(127, result.ExitCode);
        Assert.Contains("yura-test-no-such-tool", result.FailureText, StringComparison.Ordinal);
        Assert.Contains(log, line => line.StartsWith("failed (127)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_quiet_command_that_is_missing_is_not_logged_as_a_failure()
    {
        var log = new List<string>();
        var runner = new CommandRunner(log.Add);

        var result = await runner.RunAsync(
            "yura-test-no-such-tool", [], cancellationToken: TestContext.Current.CancellationToken, quiet: true);

        Assert.Equal(127, result.ExitCode);
        Assert.DoesNotContain(log, line => line.StartsWith("failed", StringComparison.Ordinal));
    }
}
