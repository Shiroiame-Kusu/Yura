# Daemon acceptance results

The privileged daemon driven end to end through its real IPC socket, on the same controlled
network the routing spike uses.

```bash
dotnet build src/Yura.Daemon
sudo tests/acceptance/daemon-acceptance.sh
```

**29 passed, 0 failed**, reproduced across consecutive runs on kernel 7.2 / nftables 1.1.7.

Nothing in the harness touches nftables, cgroups or policy routing directly. Every kernel
change is made by `yura-daemon` in response to a rule sent over the Unix socket, which is
exactly the path the desktop application uses.

## Mandatory acceptance tests

| # | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Start an ordinary application, then select it; new connections traverse the proxy | **Verified** | Instance A receives `YURA-VIA-PROXY-A`, a payload only reachable through proxy A |
| 2 | Two instances of one executable; proxy one, the other stays direct | **Verified** | B keeps timing out while A is proxied; proxy B's log stays empty |
| 3 | Persistent executable rule survives an application restart | Not covered | Needs config persistence, which is not built |
| 4 | Rule expires on process exit and cannot affect a reused PID | **Verified** | Killing A removes the rule and its cgroup; a fresh instance of the same binary is unaffected |
| 5 | Two processes through different proxies simultaneously | **Verified** | A receives proxy A's marker while B receives proxy B's, in the same window |
| 6 | Direct and Block for selected processes | **Verified** | Block yields `ConnectionRefused` (a reset, not a timeout); Direct returns to timing out |
| 7 | TCP and UDP from a selected running process | **Verified** | A receives both `YURA-VIA-PROXY-A` and `YURA-UDP-VIA-PROXY-A` |
| 8 | Child-process inclusion | **Verified** | curl children forked after a tree rule receive the marker |
| 8 | Child-process exclusion | Not covered | Needs the process-event watcher to move new children back out |
| 9 | Precedence between manual rules and game profiles | Partly | Ordering is unit-tested in `RuleEvaluatorTests`; not exercised against the kernel |
| 10 | Unrelated Wine/Proton applications unaffected | Not covered | Needs a Wine runtime in the harness |
| 11 | Existing connections distinguished from new ones | **Verified** | A's pre-rule connection stays open on its old route; the proxy never sees its destination |

## Beyond the mandatory list

| Check | Result |
| --- | --- |
| The routed process keeps running as its original user | uid 1000, never root |
| The daemon reports flows as `confirmedProxied` only when it holds both sockets | 33 flows confirmed, with proxy name and destination |
| Pre-existing connections are counted at apply time | `preExistingConnections: 2` |
| Socket ownership attribution | 24 processes with sockets; top process 103 |
| Clean shutdown removes the nft table, the ip rule and the cgroup subtree | All three verified absent afterwards |

## Bugs this suite found

Each would have shipped as a confident wrong behaviour:

- **Signal handlers were being garbage collected.** `PosixSignalRegistration.Create` returns
  an `IDisposable` that unregisters the handler when finalised. The return value was
  discarded, so SIGTERM was silently disarmed and the daemon died without removing its
  nftables table, ip rule or cgroups from the machine. Caught only because the suite asserts
  on kernel state *after* shutdown rather than trusting the exit code.
- **The `ctl` client half-closed its socket before reading.** `NetworkStream` refuses to wrap
  a socket that has been shut down in either direction, so every command after the first
  threw. It looked like a daemon fault; it was entirely client-side.
- **A stale PID file made a test build a rule from a dead process.** Preflight cleared
  `*.jsonl`, `*.out` and `*.log` but not `*.pid`, so a readiness loop succeeded instantly
  against the previous run's leftovers.
- **A `fail()` helper returned non-zero.** Under `set -e` that ended the whole run at the
  first failure, hiding every later result.

One apparent bug was not one: slot `s002` looked like it was classifying only intermittently.
Per-rule nftables counters showed it climbing from 7 packets to 31 over the same window — the
assertion window was simply shorter than the direct instance's timeout cycle. Counters on
every rule are now permanent for exactly this reason.

## Not proven here

- Persistent rules across a restart, child exclusion, and Wine/Proton isolation. Each needs a
  piece that is not built: config persistence, the process-event watcher, and a Wine runtime
  in the harness.
- Behaviour under a hostile connection rate, or with a proxy that stalls mid-handshake.
- IPv6. The classifier renders IPv6 destination rules, but every test here is IPv4, and the
  UDP path is IPv4-only by construction.
