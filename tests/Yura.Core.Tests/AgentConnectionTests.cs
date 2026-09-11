using System.Security.Cryptography;
using Yura.Core.Agent;

namespace Yura.Core.Tests;

/// <summary>
/// The connect string is the whole of the agent's setup experience, so it has to parse what
/// a user will actually paste — and refuse, with a reason, what it cannot use.
/// </summary>
public sealed class AgentConnectionTests
{
    private static string Token => AgentConnection.Encode(RandomNumberGenerator.GetBytes(AgentProtocol.TokenBytes));

    private static string Fingerprint => AgentConnection.Encode(RandomNumberGenerator.GetBytes(32));

    private static AgentConnection Sample() => new()
    {
        Host = "203.0.113.9",
        Port = 7311,
        Token = Token,
        Fingerprint = Fingerprint,
        Name = "frankfurt-1",
    };

    [Fact]
    public void A_connect_string_survives_the_round_trip()
    {
        var original = Sample();

        Assert.True(AgentConnection.TryParse(original.ToConnectString(), out var parsed, out var problem));

        Assert.Null(problem);
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void A_name_with_spaces_survives()
    {
        var original = Sample() with { Name = "Frankfurt (EU central)" };

        Assert.True(AgentConnection.TryParse(original.ToConnectString(), out var parsed, out _));

        Assert.Equal("Frankfurt (EU central)", parsed.Name);
    }

    [Fact]
    public void An_ipv6_agent_is_written_and_read_in_brackets()
    {
        var original = Sample() with { Host = "2001:db8::7" };

        Assert.Equal($"[2001:db8::7]:7311", original.Authority);
        Assert.True(AgentConnection.TryParse(original.ToConnectString(), out var parsed, out _));
        Assert.Equal("2001:db8::7", parsed.Host);
        Assert.Equal(7311, parsed.Port);
    }

    [Fact]
    public void A_missing_port_means_the_default_one()
    {
        Assert.True(AgentConnection.TryParse($"yura://{Token}@agent.example.com?fp={Fingerprint}",
            out var parsed, out _));

        Assert.Equal(AgentProtocol.DefaultPort, parsed.Port);
        Assert.Equal("agent.example.com", parsed.Host);
    }

    [Fact]
    public void The_fingerprint_is_accepted_in_the_form_it_is_displayed_in()
    {
        // The agent prints "SHA256:…" beside the connect string, so someone will paste that.
        var fingerprint = Fingerprint;

        Assert.True(AgentConnection.TryParse(
            $"yura://{Token}@203.0.113.9:7311?fp=SHA256:{fingerprint}", out var parsed, out _));

        Assert.Equal(fingerprint, parsed.Fingerprint);
        Assert.Equal($"SHA256:{fingerprint}", parsed.FingerprintDisplay);
    }

    [Fact]
    public void Parameters_after_a_hash_are_read_too()
    {
        // A string that has been through a chat client sometimes comes back with '#'.
        Assert.True(AgentConnection.TryParse(
            $"yura://{Token}@203.0.113.9:7311#fp={Fingerprint}&name=tokyo", out var parsed, out _));

        Assert.Equal("tokyo", parsed.Name);
    }

    [Fact]
    public void Surrounding_whitespace_is_forgiven()
    {
        Assert.True(AgentConnection.TryParse($"  yura://{Token}@203.0.113.9:7311?fp={Fingerprint}\n",
            out _, out _));
    }

    [Theory]
    [InlineData("", "Paste the connect string")]
    [InlineData("   ", "Paste the connect string")]
    [InlineData("https://example.com", "starts with yura://")]
    [InlineData("yura://203.0.113.9:7311?fp=x", "no token")]
    public void What_cannot_be_used_is_refused_with_the_reason(string text, string expected)
    {
        Assert.False(AgentConnection.TryParse(text, out _, out var problem));

        Assert.Contains(expected, problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_token_of_the_wrong_length_is_refused()
    {
        var short_ = AgentConnection.Encode(RandomNumberGenerator.GetBytes(16));

        Assert.False(AgentConnection.TryParse($"yura://{short_}@203.0.113.9:7311?fp={Fingerprint}",
            out _, out var problem));

        Assert.Contains("32-byte", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_connect_string_without_a_fingerprint_is_refused()
    {
        // Without it there is nothing to identify the agent by, and an exit that trusts
        // whatever answers is not an exit worth having.
        Assert.False(AgentConnection.TryParse($"yura://{Token}@203.0.113.9:7311", out _, out var problem));

        Assert.Contains("no key fingerprint", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_fingerprint_that_is_not_a_sha256_is_refused()
    {
        Assert.False(AgentConnection.TryParse($"yura://{Token}@203.0.113.9:7311?fp=abcdef", out _, out var problem));

        Assert.Contains("SHA-256", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Base64_in_either_alphabet_is_read()
    {
        // The agent writes base64url; a token that has been through something that re-encoded
        // it may come back in the standard alphabet.
        var raw = RandomNumberGenerator.GetBytes(AgentProtocol.TokenBytes);
        var standard = Convert.ToBase64String(raw);

        Assert.True(AgentConnection.TryParse($"yura://{standard}@203.0.113.9:7311?fp={Fingerprint}",
            out var parsed, out _));

        // Stored in one form whichever way it arrived, so two spellings are one exit.
        Assert.Equal(AgentConnection.Encode(raw), parsed.Token);
    }

    [Fact]
    public void The_redacted_form_keeps_the_token_out_of_logs()
    {
        var connection = Sample();

        var redacted = connection.Redacted;

        Assert.DoesNotContain(connection.Token, redacted, StringComparison.Ordinal);
        Assert.Contains(connection.Fingerprint, redacted, StringComparison.Ordinal);
        Assert.Contains("203.0.113.9:7311", redacted, StringComparison.Ordinal);
        // ToString is what ends up in a log line by accident, so it must be the safe one.
        Assert.Equal(redacted, connection.ToString());
    }

    [Fact]
    public void A_token_and_a_fingerprint_can_be_checked_on_their_own()
    {
        // The editor validates the fields as they are typed, without a whole connect string.
        Assert.True(AgentConnection.IsValidToken(Token));
        Assert.False(AgentConnection.IsValidToken("not-a-token"));
        Assert.False(AgentConnection.IsValidToken(null));
        Assert.True(AgentConnection.IsValidFingerprint(Fingerprint));
        Assert.False(AgentConnection.IsValidFingerprint("SHA256:"));
    }
}
