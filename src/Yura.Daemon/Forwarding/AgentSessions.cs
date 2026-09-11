using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Yura.Core.Agent;
using Yura.Core.Proxies;
using Yura.Daemon.Linux;

namespace Yura.Daemon.Forwarding;

/// <summary>What the daemon currently knows about one agent exit. Never carries the token.</summary>
public sealed record AgentState
{
    public required Guid ProxyId { get; init; }

    public required string Name { get; init; }

    /// <summary>True when the control session is up. TCP flows can work without it; UDP cannot.</summary>
    public required bool Connected { get; init; }

    /// <summary>What the agent calls itself, which is not necessarily what the exit is named.</summary>
    public string? AgentName { get; init; }

    public string? AgentVersion { get; init; }

    /// <summary>Round trip to the agent on the control connection, from the last ping.</summary>
    public double? RoundTripMilliseconds { get; init; }

    public bool Udp { get; init; }

    /// <summary>The resolver the agent offered, used for lookups from processes on this exit.</summary>
    public IPAddress? Resolver { get; init; }

    public string? Failure { get; init; }
}

/// <summary>
/// Keeps one live session per agent exit.
/// </summary>
/// <remarks>
/// <para>
/// A session is worth keeping open for three reasons: it is where the datagram key comes
/// from, so UDP cannot work without one; it is how the daemon knows the agent is there before
/// a game starts; and it means the first connection a game makes does not pay for a
/// handshake. So sessions are opened when the proxy list is pushed, not when a flow arrives.
/// </para>
/// <para>
/// TCP flows do not use the session at all — each opens its own connection — so an agent
/// whose session is down is degraded rather than unusable, and that distinction is reported
/// rather than flattened.
/// </para>
/// </remarks>
public sealed class AgentSessionManager : IAsyncDisposable
{
    /// <summary>Long enough to be worth retrying, short enough that a game start is not blocked.</summary>
    private static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(5);

    private readonly Action<string> _log;
    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();
    private readonly SemaphoreSlim _connecting = new(1, 1);

    public AgentSessionManager(Action<string> log) => _log = log;

    /// <summary>Every agent exit the daemon has been given, connected or not.</summary>
    public IReadOnlyList<AgentState> States => _entries.Values.Select(e => e.State()).ToArray();

    /// <summary>The resolver each connected agent offered, for the DNS redirect.</summary>
    public IReadOnlyDictionary<Guid, IPAddress> Resolvers => _entries.Values
        .Where(e => e.Resolver is not null)
        .ToDictionary(e => e.ProxyId, e => e.Resolver!);

    /// <summary>
    /// Brings the set of sessions in line with the proxy list.
    /// </summary>
    /// <returns>A warning for each agent that could not be reached, for the apply result.</returns>
    public async Task<IReadOnlyList<string>> ReconcileAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, ProxySecrets Secrets)> proxies, CancellationToken ct = default)
    {
        var wanted = proxies
            .Where(p => p.Endpoint.Protocol == ProxyProtocol.YuraAgent)
            .ToDictionary(p => p.Endpoint.Id);

        foreach (var (id, entry) in _entries)
        {
            if (!wanted.TryGetValue(id, out var proxy) || SignatureOf(proxy.Endpoint, proxy.Secrets) != entry.Signature)
            {
                // Removed, re-addressed, re-keyed or re-tokened: the old session is not the
                // right one to keep using.
                _entries.TryRemove(id, out _);
                await entry.CloseAsync().ConfigureAwait(false);
                _log($"agent '{entry.Name}': session closed ({(wanted.ContainsKey(id) ? "its settings changed" : "removed")})");
            }
        }

        var warnings = new List<string>();
        foreach (var (id, proxy) in wanted)
        {
            var entry = _entries.GetOrAdd(id, _ => new Entry(proxy.Endpoint, proxy.Secrets));
            entry.Update(proxy.Endpoint, proxy.Secrets);

            if (await OpenAsync(entry, ct).ConfigureAwait(false) is null && entry.Failure is { } failure)
            {
                warnings.Add($"Agent exit '{entry.Name}' is not answering: {failure}");
            }
        }

        return warnings;
    }

    /// <summary>
    /// The live session for an agent, opening or repairing one if need be, or null with the
    /// reason recorded.
    /// </summary>
    public async Task<AgentSession?> GetAsync(ProxyEndpoint endpoint, string? token, CancellationToken ct = default)
    {
        if (_entries.TryGetValue(endpoint.Id, out var existing) && existing.Live is { IsOpen: true } live)
        {
            return live;
        }

        var entry = _entries.GetOrAdd(endpoint.Id, _ => new Entry(endpoint, new ProxySecrets(token)));
        entry.Update(endpoint, new ProxySecrets(token));
        return await OpenAsync(entry, ct).ConfigureAwait(false);
    }

    /// <summary>Why an agent is not connected, or null when it is.</summary>
    public string? FailureFor(Guid proxyId) =>
        _entries.TryGetValue(proxyId, out var entry) ? entry.Failure : null;

    private async Task<AgentSession?> OpenAsync(Entry entry, CancellationToken ct)
    {
        if (entry.Live is { IsOpen: true } live)
        {
            return live;
        }

        await _connecting.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Another caller may have opened it while we waited.
            if (entry.Live is { IsOpen: true } opened)
            {
                return opened;
            }

            await entry.CloseAsync().ConfigureAwait(false);

            if (DateTimeOffset.UtcNow - entry.LastAttemptUtc < RetryAfter && entry.Failure is not null)
            {
                // Recently failed. Retrying on every datagram would turn one unreachable agent
                // into a connection storm.
                return null;
            }

            entry.LastAttemptUtc = DateTimeOffset.UtcNow;
            try
            {
                var options = ProxyDialer.AgentOptionsFor(
                    new ProxyHop(entry.Endpoint, entry.Token),
                    socket => socket.SetMark(PolicyRouting.BypassMark));

                var session = await AgentSession.ConnectAsync(options, ct).ConfigureAwait(false);
                entry.Adopt(session);
                var resolver = session.Welcome.Resolver is { Length: > 0 } text && IPAddress.TryParse(text, out var address)
                    ? address
                    : null;
                entry.Resolver = resolver;

                _log($"agent '{entry.Name}': session up with {session.AgentName} " +
                     $"({(session.UdpAvailable ? "udp available" : "no udp")}" +
                     $"{(resolver is null ? string.Empty : $", dns {resolver}")})");

                // The first ping is what makes the round trip known before anything asks.
                try
                {
                    await session.PingAsync(ct).ConfigureAwait(false);
                }
                catch (Exception e) when (e is AgentProtocolException or TimeoutException or IOException)
                {
                }

                return session;
            }
            catch (Exception e) when (e is AgentRefusedException or AgentProtocolException or ProxyHandshakeException
                                          or System.Net.Sockets.SocketException or IOException
                                          or OperationCanceledException)
            {
                entry.Failure = e is OperationCanceledException ? "it did not answer in time" : e.Message;
                _log($"agent '{entry.Name}': {entry.Failure}");
                return null;
            }
        }
        finally
        {
            _connecting.Release();
        }
    }

    /// <summary>
    /// Identifies the settings a session depends on, so a change to any of them reconnects.
    /// </summary>
    /// <remarks>
    /// The token is included as a hash rather than a value: this string is compared, logged
    /// nowhere, and a token that appeared in a key would be a token in a memory dump of the
    /// dictionary for the rest of the process's life.
    /// </remarks>
    private static string SignatureOf(ProxyEndpoint endpoint, ProxySecrets secrets)
    {
        var token = secrets.Password ?? string.Empty;
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)))[..16];
        return $"{endpoint.Host}|{endpoint.Port}|{endpoint.Agent?.Fingerprint}|{digest}";
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var entry in _entries.Values)
        {
            await entry.CloseAsync().ConfigureAwait(false);
        }

        _entries.Clear();
        _connecting.Dispose();
    }

    /// <summary>One agent exit, its settings, and the session if there is one.</summary>
    private sealed class Entry
    {
        private AgentSession? _session;

        public Entry(ProxyEndpoint endpoint, ProxySecrets secrets)
        {
            Endpoint = endpoint;
            Token = secrets.Password;
            Signature = SignatureOf(endpoint, secrets);
        }

        public ProxyEndpoint Endpoint { get; private set; }

        public string? Token { get; private set; }

        public string Signature { get; private set; }

        public Guid ProxyId => Endpoint.Id;

        public string Name => Endpoint.Name;

        public string? Failure { get; set; }

        public IPAddress? Resolver { get; set; }

        public DateTimeOffset LastAttemptUtc { get; set; }

        public AgentSession? Live => _session is { IsOpen: true } session ? session : null;

        public void Update(ProxyEndpoint endpoint, ProxySecrets secrets)
        {
            Endpoint = endpoint;
            Token = secrets.Password ?? Token;
            Signature = SignatureOf(endpoint, new ProxySecrets(Token));
        }

        public void Adopt(AgentSession session)
        {
            _session = session;
            Failure = null;
            session.Closed += reason => Failure = reason;
        }

        public async Task CloseAsync()
        {
            if (_session is { } session)
            {
                _session = null;
                Resolver = null;
                await session.DisposeAsync().ConfigureAwait(false);
            }
        }

        public AgentState State()
        {
            var session = _session;
            var connected = session is { IsOpen: true };
            return new AgentState
            {
                ProxyId = ProxyId,
                Name = Name,
                Connected = connected,
                AgentName = session?.AgentName,
                AgentVersion = session?.Welcome.AgentVersion,
                RoundTripMilliseconds = connected ? session?.LastRoundTrip?.TotalMilliseconds : null,
                Udp = connected && session!.UdpAvailable,
                Resolver = connected ? Resolver : null,
                Failure = connected ? null : Failure ?? "no session yet",
            };
        }
    }
}
