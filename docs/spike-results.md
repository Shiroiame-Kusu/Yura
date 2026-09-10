# Routing spike results

The de-risking experiment the specification asks for before building the product:
**can an already-running, unmodified process be re-routed, per instance?**

Answer: yes. Verified on 2026-09-10, reproduced across three consecutive runs.

```
sudo ./spikes/routing-spike.sh
```

```
==> Applying an instance rule to A only
    re-verified pid 54272 start ticks 489195 before acting
    migrated pid 54272 into yura/spike-a while it was running
    cgroup now contains: 54272
    process still runs as uid 1000
    nftables classifier installed

    PASS A's new TCP connections now traverse the proxy (acceptance test 1)
    PASS B, the same executable, is still direct and still fails (acceptance test 2)
    PASS A's UDP traffic traverses the proxy (acceptance test 7)
    PASS B's UDP traffic is unaffected
    PASS proxy-side log confirms A's flows and only A's — 17 CONNECT and 17 UDP relays
    PASS A's pre-rule connection is still open on its previous route (acceptance test 11)
    PASS the proxy never saw the pre-rule connection's destination
    PASS A returns to direct routing once the override is removed
    PASS the cgroup is empty after the override is removed

    12 passed, 0 failed
```

## Environment

| | |
| --- | --- |
| Kernel | 7.2.0 (CachyOS) |
| nftables | 1.1.7 |
| cgroup | v2 unified |
| `pid_max` | 4194304 |

## Why the result is trustworthy

The spike is built so that a false pass is hard to produce:

- **The destination is unreachable by design.** `198.51.100.7` sits on a dummy interface
  that goes nowhere. Direct traffic to it times out; it has no route to anything.
- **The marker payload only exists behind the proxy.** The spike's SOCKS5 server rewrites
  `198.51.100.7:8080` to a local marker server. Receiving `YURA-TCP-PROXIED-OK` is
  therefore *proof* that the flow traversed the proxy, not an inference from configuration.
- **Three independent witnesses agree.** The client's own log, the proxy's audit log, and
  the destination server's log are written by three separate processes and cross-checked.
- **The control is a sibling.** Instance B is the same executable, same user, same
  arguments, started the same way. Only A is selected.
- **No packet leaves the machine.**

Verified evidence from the run:

```
client A:  {"detail": "YURA-TCP-PROXIED-OK", "ok": true,  "target": "198.51.100.7:8080"}
           {"detail": "YURA-UDP-PROXIED-OK", "ok": true,  "target": "198.51.100.7:9090"}
client B:  {"detail": "TimeoutError: timed out", "ok": false, "target": "198.51.100.7:8080"}
proxy:     17x connect  requested=198.51.100.7:8080  dialled=198.51.100.1:18080
           17x udp_send requested=198.51.100.7:9090  dialled=198.51.100.1:19090
```

## Confirmed by counters

`spikes/debug-classify.sh` puts an nftables counter on every rule and reports which ones a
packet actually reached. It confirms each link of the chain independently:

```
saw-target-tcp      packets 4    the packet reached the output chain
cgroup-matched      packets 4    socket cgroupv2 matched the migrated process
mark-set            packets 4    fwmark applied, forcing a re-route
prerouting-marked   packets 4    the local route looped it back into the input path
tproxy-applied      packets 4    TPROXY claimed it

ACCEPTED from ('198.51.100.1', 63084) original-dest=('198.51.100.7', 8080)
```

That last line is the load-bearing one: with `IP_TRANSPARENT`, the accepted socket's own
local address **is** the original destination. No conntrack, no NAT, no `SO_ORIGINAL_DST`.

Keep this script. When routing breaks, "which link?" is the only question worth asking, and
guessing at it costs far more than the counters do.

## What the spike proves, and what it does not

**Proved**

| Acceptance test | Status |
| --- | --- |
| 1 — select a running application, its new connections traverse the proxy | Verified |
| 2 — two instances of one executable, one proxied, one direct | Verified |
| 7 — TCP and UDP from a selected running process | Verified |
| 11 — pre-existing connections distinguished from new ones | Verified |
| Removing a temporary override restores direct routing | Verified |
| The process keeps running as its original user (uid 1000) | Verified |

**Not proved — these need the daemon**

Tests 3 (persistent executable rules across a restart), 4 (rule expiry and PID reuse),
5 (two processes through two different proxies simultaneously), 6 (Direct and Block
actions), 8 (child inclusion and exclusion), 9 (rule precedence), 10 (unrelated Wine/Proton
applications unaffected).

The mechanisms they rest on are all exercised here — cgroup membership, instance identity
re-verification, classifier withdrawal — but the daemon that drives them does not exist yet.

## Bugs the spike found in itself

Worth recording, because each one would have produced a confident wrong answer:

- **`$!` after backgrounding a shell function returns the subshell, not the command.** The
  spike wrapped its clients in an `as_user` function to drop privileges; `$!` gave the
  subshell's pid, so it migrated the *wrong process* into the cgroup. Classification was
  correct throughout — it was simply classifying a process that made no network calls. The
  client now reports its own pid on its first log line, and the harness reads that.
- **The settle window has to be sized for the slow side.** Once instance A was proxied it
  answered instantly, while instance B still burned a full timeout per attempt. A window
  tuned to A starved B's assertions of records and reported a routing failure that was not.
- **An assertion checked a field the client never emitted.** `--expect-ok false` against
  records with no `ok` field passed for the wrong reason. The pre-existing-connection check
  was, until fixed, asserting nothing at all.

## Known sharp edges

- **`socket cgroupv2` resolves the path to a cgroup id at rule-load time.** Delete and
  recreate a cgroup and matching silently stops. The daemon must reload the ruleset whenever
  it recreates one.
- **`rp_filter` must be relaxed** or the looped-back packets are dropped. The spike saves
  and restores the previous values.
- **Orphaned helpers hold ports.** Killing a backgrounded subshell does not kill what
  `setpriv` exec'd inside it. `spikes/kill-orphans.sh` clears them; it lives in a file
  because a `pkill -f` pattern typed at a shell also matches that shell.
