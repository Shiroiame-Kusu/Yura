using System.Net;
using Yura.Core.Connections;
using Yura.Core.Ipc;
using Yura.Core.Proxies;
using Yura.Core.Rules;

namespace Yura.App.Services;

/// <summary>
/// A stand-in daemon used only for design review (<c>--demo</c>).
/// </summary>
/// <remarks>
/// This exists so states that cannot occur without a running daemon — a confirmed proxy
/// route, a populated connection list, a successful probe, a latency comparison — can be laid
/// out and inspected without a privileged process and a real proxy. It is never selected by
/// default, and every screenshot produced with it is labelled as simulated. Nothing here is a
/// substitute for the acceptance tests: it proves the UI can render a state, not that the
/// state is achievable.
/// </remarks>
public sealed class SimulatedDaemonClient : IDaemonClient
{
    private readonly Random _random = new(20260910);
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(41);
    private DnsPolicy _dnsPolicy = DnsPolicy.ThroughProxy;

    public DaemonState State => DaemonState.Connected;

    public event EventHandler<DaemonState>? StateChanged
    {
        add { }
        remove { }
    }

    public string? UnavailableReason => null;

    public Task ConnectAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<DaemonStatus?>(new DaemonStatus
        {
            Version = "0.2.0 (simulated)",
            ActiveRules = 3,
            ActiveFlows = 12,
            ActiveGroups = 2,
            Uptime = DateTimeOffset.UtcNow - _startedAt,
            ProcessWatcher = "netlink",
            DnsPolicy = _dnsPolicy,
            KernelRelease = "7.2.0-3-cachyos",
            NftVersion = "nftables v1.1.7 (Commodore Bullmoose)",
            CgroupRoot = "/sys/fs/cgroup/yura",
            SocketPath = "/run/yura/yura.sock",
            AllowedUids = [0, 1000],
            Checks =
            [
                new DaemonCheck("Running as root", true, null),
                new DaemonCheck("cgroup v2 unified hierarchy", true, "/sys/fs/cgroup"),
                new DaemonCheck("nft available", true, "nftables v1.1.7 (Commodore Bullmoose)"),
                new DaemonCheck("Policy routing installed", true, "fwmark 0x7100/0xffffff00 -> table 711"),
                new DaemonCheck("Kernel accepts the base ruleset (nft_socket, nft_tproxy)", true, null),
                new DaemonCheck("rp_filter relaxed on lo and all", true, null),
                new DaemonCheck("Kernel process events (netlink connector)", true, null),
            ],
        });

    public Task<IReadOnlyDictionary<int, int>> GetConnectionCountsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyDictionary<int, int>>(new Dictionary<int, int>());

    /// <summary>
    /// A deliberately awkward set: a confirmed proxied flow, a pre-existing one on its old
    /// route, a failure with a reason, an IPv6 peer, and one whose owner is unknown.
    /// </summary>
    public Task<IReadOnlyList<ConnectionRecord>> GetConnectionsAsync(
        int? pid = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var ruleId = Guid.Parse("dddddddd-0000-4000-8000-000000000001");

        IReadOnlyList<ConnectionRecord> rows =
        [
            new ConnectionRecord
            {
                Id = "f:1", OwnerPid = 4821, ProcessDisplayName = "cs2",
                Local = IPEndPoint.Parse("192.168.1.24:51544"),
                Remote = IPEndPoint.Parse("162.254.192.71:27015"),
                Protocol = TransportProtocol.Udp, State = ConnectionState.Established,
                Route = RouteObservation.ConfirmedProxied, ProxyName = "Home server",
                MatchedRuleId = ruleId, MatchedRuleName = "cs2 (pid 4821)",
                BytesUp = 1_482_311, BytesDown = 9_922_104, CreatedAtUtc = now.AddMinutes(-7),
            },
            new ConnectionRecord
            {
                Id = "f:2", OwnerPid = 4821, ProcessDisplayName = "cs2",
                Local = IPEndPoint.Parse("192.168.1.24:51546"),
                Remote = IPEndPoint.Parse("104.18.32.7:443"),
                RemoteHost = "steamcommunity.com",
                Protocol = TransportProtocol.Tcp, State = ConnectionState.Established,
                Route = RouteObservation.ConfirmedProxied, ProxyName = "Home server",
                MatchedRuleId = ruleId, MatchedRuleName = "cs2 (pid 4821)",
                BytesUp = 18_204, BytesDown = 441_882, CreatedAtUtc = now.AddMinutes(-6),
            },
            new ConnectionRecord
            {
                Id = "s:44120", OwnerPid = 4821, ProcessDisplayName = "cs2",
                Local = IPEndPoint.Parse("192.168.1.24:51502"),
                Remote = IPEndPoint.Parse("162.254.195.47:27020"),
                Protocol = TransportProtocol.Tcp, State = ConnectionState.Established,
                KernelState = "ESTABLISHED",
                Route = RouteObservation.PreExistingPreviousRoute,
                MatchedRuleId = ruleId, MatchedRuleName = "cs2 (pid 4821)",
                CreatedAtUtc = now.AddMinutes(-23),
                Note = "Opened before the rule was applied. Restart the application, or reconnect, to move it.",
            },
            new ConnectionRecord
            {
                Id = "f:3", OwnerPid = 3160, ProcessDisplayName = "firefox",
                Local = IPEndPoint.Parse("192.168.1.24:49288"),
                Remote = IPEndPoint.Parse("[2606:4700:3037::ac43:a5d2]:443"),
                RemoteHost = "cdn.example.com",
                Protocol = TransportProtocol.Tcp, State = ConnectionState.Failed,
                Route = RouteObservation.Unknown,
                MatchedRuleId = Guid.Parse("dddddddd-0000-4000-8000-000000000002"),
                MatchedRuleName = "firefox (all instances)",
                FailureReason = "The proxy's ruleset does not allow this connection.",
                CreatedAtUtc = now.AddSeconds(-34),
            },
            new ConnectionRecord
            {
                Id = "s:51992", OwnerPid = 1284, ProcessDisplayName = "systemd-resolved",
                Local = IPEndPoint.Parse("127.0.0.53:53"),
                Remote = IPEndPoint.Parse("1.1.1.1:53"),
                Protocol = TransportProtocol.Udp, State = ConnectionState.Established,
                KernelState = "UDP", Route = RouteObservation.ConfirmedDirect,
                CreatedAtUtc = now.AddMinutes(-41),
            },
            new ConnectionRecord
            {
                Id = "s:52140",
                Local = IPEndPoint.Parse("192.168.1.24:60122"),
                Remote = IPEndPoint.Parse("140.82.121.4:443"),
                Protocol = TransportProtocol.Tcp, State = ConnectionState.Closing,
                KernelState = "TIME_WAIT", Route = RouteObservation.Unknown,
                Note = "The owning process could not be determined.",
                CreatedAtUtc = now.AddMinutes(-2),
            },
        ];

        return Task.FromResult(pid is { } wanted ? rows.Where(r => r.OwnerPid == wanted).ToArray() : rows);
    }

    public async Task<RuleApplyResult> ApplyRuleAsync(RoutingRule rule, CancellationToken cancellationToken = default)
    {
        // A real apply is not instant, and the UI has to look right while it is in flight.
        await Task.Delay(320, cancellationToken).ConfigureAwait(false);

        return new RuleApplyResult
        {
            Succeeded = true,
            ConfirmedAtUtc = DateTimeOffset.UtcNow,
            PreExistingConnections = _random.Next(0, 4),
        };
    }

    public async Task<RuleApplyResult> RemoveRuleAsync(Guid ruleId, CancellationToken cancellationToken = default)
    {
        await Task.Delay(180, cancellationToken).ConfigureAwait(false);
        return new RuleApplyResult { Succeeded = true, ConfirmedAtUtc = DateTimeOffset.UtcNow };
    }

    public Task<RuleApplyResult> SetProxiesAsync(
        IReadOnlyList<(ProxyEndpoint Endpoint, string? Password)> proxies,
        IReadOnlyList<ProxyChain> chains,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(new RuleApplyResult { Succeeded = true, ConfirmedAtUtc = DateTimeOffset.UtcNow });

    public Task<RuleApplyResult> SetDnsPolicyAsync(DnsPolicy policy, CancellationToken cancellationToken = default)
    {
        _dnsPolicy = policy;
        return Task.FromResult(new RuleApplyResult { Succeeded = true, ConfirmedAtUtc = DateTimeOffset.UtcNow });
    }

    public async Task<ProxyProbeResult> ProbeProxyAsync(
        ProxyEndpoint endpoint,
        string? password,
        CancellationToken cancellationToken = default)
    {
        await Task.Delay(500, cancellationToken).ConfigureAwait(false);

        return new ProxyProbeResult
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            Reachable = true,
            HandshakeLatency = TimeSpan.FromMilliseconds(_random.Next(12, 60)),
            Udp = endpoint.Protocol == ProxyProtocol.Socks5
                ? CapabilityState.Supported
                : CapabilityState.Unsupported,
            Diagnostics = endpoint.Protocol == ProxyProtocol.Socks5
                ? "SOCKS5 negotiation and UDP ASSOCIATE both succeeded."
                : "TCP connect succeeded. HTTP CONNECT itself is only exercised by a real flow.",
        };
    }

    public async Task<MeasurementDto?> MeasureAsync(
        string host, ushort port, Guid? proxyId, Guid? chainId, int samples,
        CancellationToken cancellationToken = default)
    {
        await Task.Delay(900, cancellationToken).ConfigureAwait(false);

        static SampleSetDto Set(int samples, int successes, double latency, double jitter) => new()
        {
            Samples = samples,
            Successes = successes,
            LatencyMilliseconds = latency,
            JitterMilliseconds = jitter,
            LossPercent = 100.0 * (samples - successes) / samples,
            RoundTripsMilliseconds = Enumerable.Range(0, successes).Select(i => latency + (i % 3 - 1) * jitter).ToList(),
        };

        return new MeasurementDto
        {
            Target = $"{host}:{port}",
            Method = "TCP connect",
            Direct = Set(samples, samples, 84.3, 11.2),
            Routed = proxyId is null && chainId is null ? null : Set(samples, samples, 46.1, 3.7),
            MeasuredAtUtc = DateTimeOffset.UtcNow,
        };
    }

    public Task<string?> DumpRulesetAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<string?>("""
            # nft list table inet yura
            table inet yura {
            	chain classify {
            		type route hook output priority mangle; policy accept;
            		meta mark 0x7200 return
            		oifname "lo" return
            		ip daddr 127.0.0.1 th dport 1080 return
            		# s001: cs2 (pid 4821)
            		meta l4proto { tcp, udp } socket cgroupv2 level 2 "yura/g001" meta mark set 0x7101 counter packets 10482 bytes 9911204 accept
            	}

            	chain capture {
            		type filter hook prerouting priority mangle; policy accept;
            		meta mark 0x7101 meta l4proto tcp tproxy ip to :17801 counter packets 844 bytes 58122 accept
            		meta mark 0x7101 meta l4proto udp tproxy ip to :17801 counter packets 9638 bytes 9853082 accept
            	}
            }
            # ip rule show
            0:	from all lookup local
            7100:	from all fwmark 0x7100/0xffffff00 lookup 711
            32766:	from all lookup main
            # ip route show table 711
            local default dev lo scope host
            # process groups
            g001: pids [4821] rules [cs2 (pid 4821)]
            """);

    public Task<IReadOnlyList<string>> GetLogAsync(int lines = 200, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<string>>(
        [
            "12:04:18.221 yura-daemon 0.2.0 starting on kernel 7.2.0-3-cachyos; nftables v1.1.7 (Commodore Bullmoose)",
            "12:04:18.244 policy routing installed: fwmark 0x7100/0xffffff00 -> table 711",
            "12:04:18.251 process events: subscribed to the kernel process connector",
            "12:04:18.258 ipc listening on /run/yura/yura.sock (allowed uids: 0, 1000)",
            "12:04:18.259 ready",
            "12:11:02.118 created cgroup /sys/fs/cgroup/yura/g001",
            "12:11:02.119 group g001 = {cs2 (pid 4821)}",
            "12:11:02.121 migrated pid 4821 (cs2) into yura/g001",
            "12:11:02.140 slot s001: tcp listener on :17801 for 'cs2 (pid 4821)'",
            "12:11:02.141 slot s001: udp listener on :17801 for 'cs2 (pid 4821)'",
            "12:11:02.168 nftables ruleset installed",
        ]);
}
