using System.Text.Json;

namespace Yura.Daemon.Tests;

/// <summary>
/// The request line <c>yura-daemon ctl</c> sends, which the acceptance suite uses for every check.
/// </summary>
/// <remarks>
/// It was serialized from a dictionary, or from an anonymous object when there was no body, and
/// NativeAOT can serialize neither. Now it is written member by member, and has to come out the
/// same.
/// </remarks>
public sealed class ControlRequestTests
{
    [Fact]
    public void An_op_on_its_own_is_the_whole_request() =>
        Assert.Equal("""{"op":"status"}""", Program.ControlRequest("status", null));

    [Fact]
    public void A_body_follows_the_op_exactly_as_it_was_written() =>
        Assert.Equal(
            """{"op":"apply-rule","rule":{"id":"x","order":1,"hosts":["*.example.com"]},"resetExisting":true}""",
            Program.ControlRequest("apply-rule", """{ "rule": { "id": "x", "order": 1, "hosts": [ "*.example.com" ] }, "resetExisting": true }"""));

    [Fact]
    public void A_body_that_names_its_own_op_has_the_last_word()
    {
        using var request = JsonDocument.Parse(Program.ControlRequest("status", """{"op":"ping"}"""));

        Assert.Equal("ping", request.RootElement.GetProperty("op").GetString());
        Assert.Single(request.RootElement.EnumerateObject());
    }
}
