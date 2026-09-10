# UX verification report

Covers the design and usability acceptance criteria for the first release: the design system
and all seven pages.

Every screenshot referenced here was rendered from the real application under Xvfb at a fixed
surface size and scale factor, then inspected. Reproduce the whole set with:

```bash
./tools/capture-all.sh
```

Screenshots whose filename contains `demo` are rendered against a **simulated daemon**
(`--demo`). They show what a connected, populated UI looks like. They are not evidence that
routing works — see [daemon-acceptance.md](daemon-acceptance.md) for that.

---

## What was checked, and what it found

### Pages

All seven: Processes, Games, Connections, Proxies, Rules, Diagnostics, Settings. Every page
is kept alive rather than swapped when navigating, so search text, filters, selection and
scroll position survive moving between them; the pages that poll are started and stopped by
the shell instead, so a page nobody is looking at costs nothing.

| | |
| --- | --- |
| Processes | `01-processes-dark.png`, `02-processes-light.png` |
| Games | `03-games-dark-demo.png`, `04-games-light-demo.png` |
| Proxies | `05-proxy-editor-dark-demo.png`, `06-proxy-editor-light-demo.png` |
| Connections | `17-connections-dark-demo.png`, `18-connections-light-demo.png` |
| Rules | `19-rules-dark-demo.png`, `20-rules-light-demo.png` |
| Diagnostics | `21-diagnostics-dark-demo.png` |
| Settings | `22-settings-dark-demo.png` |

### Themes

Contrast is measured from the token file itself by `tools/check-contrast.py`, so it cannot
drift from what renders. **52 of 52 required pairs pass** in both themes — 4.5:1 for all
normal text, 3:1 for focus rings and control boundaries.

One finding worth recording: meeting 3:1 on control outlines conflicts with the
"subtle borders" direction if a single border token is used for both. Resolved by splitting
the token — `YuraBorderControl` (3:1, outlines inputs) is distinct from `YuraBorderSubtle`
(dividers and panel edges, deliberately quiet).

### Languages

`07-processes-zh.png`, `08-games-zh-demo.png`, `09-proxy-editor-zh-demo.png`,
`23-connections-zh-demo.png`, `24-rules-zh-demo.png`, `25-settings-zh-demo.png`.

All 308 strings exist in both tables, which is checked mechanically. Three classes of defect
were found *only* by rendering Chinese and have been fixed:

- `138 of 730 processes` and `Live sorting` were hard-coded English.
- **Domain descriptions leaked into the interface.** The Rules table showed `Any destination`,
  `Name firefox` and `port 25` in a Chinese layout, because they came from
  `ProcessSelector.Describe()` and `DestinationSelector.Describe()` in the domain — which are
  deliberately English, since they also go into daemon logs and match explanations. Anything
  user-facing now goes through `RuleDescriber` in the app, which has the string table. This is
  the same class of bug as the first one and would not have been visible in English.
- Chinese labels are shorter than English ones, which exposed that the Processes column
  widths had been tuned to the English strings rather than to the data.

### Window sizes

| Size | Screenshots | Result |
| --- | --- | --- |
| 1280×800 (reference) | `01`, `17`, `19`, `21`, `22` | All columns readable on every page |
| 960×640 (minimum) | `10-processes-min.png`, `11-games-min-demo.png`, `26-connections-min-demo.png`, `27-rules-min-demo.png` | Usable |

Three defects were found at the minimum size, all by rendering it:

- A docked 288-DIP inspector squeezed the Processes executable-path column out of existence.
  Fixed by making the inspector responsive: below 1000 DIPs of page width it floats above the
  table instead of competing with it. The markup lives in one control used in both placements,
  so the two cannot drift.
- The Rules table had the same problem, worse: rule names truncated to `cs...`. Fixed the same
  way, with the inspector extracted into `RuleInspector` and floated below 1040 DIPs.
- The Connections table had **seven fixed-width columns**, which at 960 exceeded the available
  width and collapsed the destination column to nothing while the traffic and age columns
  overflowed past the panel edge. Fixed by making the columns proportional and pairing the
  variable-length values: process over destination, state over age, bytes up over bytes down.
  Nothing is clipped at either size now.

### Scaling

`12-processes-125.png`, `13-processes-150.png`, `14-processes-200.png` — 125%, 150% and
200%. Layout is stable in DIPs at every step; no clipping, no overlap, no fractional-scale
seams. The 200% capture is a true 2560×1600 framebuffer.

### Fonts

Verified with a purpose-built `--font-report` flag that asks Avalonia's own font manager
what it resolves, rather than trusting fontconfig. This found two real bugs:

- **`Inter` never resolved.** `WithInterFont()` registers Inter as an embedded *asset*, not
  a system family, so the bare name `Inter` silently fell back to the system default —
  defeating the point of embedding it for offline Latin rendering. Fixed by referencing
  `avares://Avalonia.Fonts.Inter/Assets#Inter`.
- **`Noto Sans Mono` renders oblique** under Avalonia 12 on this font stack, which made
  every executable path and address in the UI italic. Fixed by preferring
  `DejaVu Sans Mono`. This was caught by magnifying a screenshot, not by reading code.

Chinese fallback is now explicit and ordered: Inter → Noto Sans CJK SC → Noto Sans.

### Data-shape edge cases

- **Long executable paths** — trimmed from the *head* so the file name stays visible, with
  the full value in a tooltip and in the inspector.
- **IPv6 literals** — `[2001:0db8:…:7334]:1080` renders bracketed and unwrapped in the proxy
  list. On the Connections page a peer with a learned name shows the name, with the name and
  the address together in the tooltip: showing both in the cell meant neither fitted, since an
  IPv6 literal alone is 45 characters.
- **7-digit PIDs** — `pid_max` on this kernel is 4194304, so PIDs can be seven digits. The
  PID and Parent columns had been sized for five and were clipping real values; both are now
  sized for seven. Found by reading `/proc/sys/kernel/pid_max`, not by guessing.
- **Unavailable values** — a process whose path cannot be read shows *Permission denied* in a
  muted italic style, never a blank cell. A connection count the daemon cannot supply shows
  `—`, never `0` — including in the window between connecting to the daemon and its first
  answer arriving, which previously showed `0` for every process.
- **Unmeasured metrics** — routed packet loss in `03-games-dark-demo.png` reads
  *Not measured*. `Metric.Value` is deliberately nullable so a missing measurement cannot
  be rendered as a zero.

### States

| State | Where |
| --- | --- |
| Disconnected | `28-connections-disconnected.png`, `29-diagnostics-disconnected.png`, and the default in every non-demo screenshot: persistent banner plus sidebar dot, both with text, and every action explains why it is unavailable |
| Empty | Proxy list, rule list, process list behind a filter, connection list — each with a hint naming what would fill it |
| Populated | All `demo` screenshots |
| Pending | A rule the user has asked for but the daemon has not confirmed reads *Pending*, distinct from *Active*; visible on rule 501 in `19-rules-dark-demo.png` |
| Error | Failure banner with an expandable technical-details section, on the process inspector, the rule inspector and the proxy editor |
| Degraded | A boost whose route answers nothing becomes *Degraded* rather than staying *Routing* with bad numbers |

The Connections page distinguishes the three cases the whole design turns on, in one table:
*Home server* (the daemon is relaying it), *Previous route* (opened before the rule, still on
its old path, with the reconnect explanation), and *Unknown* (ownership could not be
established) — see `17-connections-dark-demo.png`.

### Colour is never load-bearing

Every status carries a word as well as a colour: routing policy badges read
*Direct* / *Proxied* / *Blocked* / *Applying…*; the daemon dot sits next to
*Daemon not connected*; a route reads *Previous route* rather than an amber mark; startup
checks read *OK* / *Failed*; transport support reads *UDP not supported*.

### Recovery

Diagnostics exists for the "diagnose and recover from a proxy failure" workflow: it reports
what the daemon found on this machine, which startup checks passed, whether process tracking
is event-driven or polled, the nftables ruleset actually installed with its per-rule counters,
and the recent daemon log — with one button that puts all of it on the clipboard, because a
bug report about routing is unactionable without it and asking a user to run four commands
loses most of them.

Undo is offered for rule edits, including in the kernel: undoing a removal reapplies the rule,
and undoing a replacement puts the previous version back and reapplies that. A reorder touches
two rules and is deliberately not undoable as one step, which the button reflects by clearing.

---

## Not verified

Stated plainly, because these are acceptance criteria that remain open.

**Keyboard-only walkthroughs of the five workflows.** The screenshot harness drives a bare
Xvfb with no window manager, so it cannot meaningfully exercise focus traversal, focus visuals
or keyboard activation. Every control is a standard FluentAvalonia control in tab order, the
reorder affordance is buttons rather than drag and drop specifically so it is reachable from
the keyboard, and accessible names are set on icon-only and ambiguous controls — but this
needs a human at a real keyboard.

**Screen reader behaviour.** `AutomationProperties.Name` is set throughout, but no AT-SPI
client was run against the application.

**Reduced motion.** The setting is wired and replaces transition durations with zero, but it
has not been checked against a real animated transition, because the current screens use
almost no motion.

**Large connection lists under a hostile update rate.** The Processes table was exercised with
~840 live processes and stays responsive; both it and the Connections table update rows in
place — never rebuilt — specifically so selection, keyboard focus and scroll position survive
the two-second refresh. That mechanism is implemented and exercised at a normal rate, not at a
deliberately hostile one.

**Real application icons.** The process list shows a category glyph, not the application's
own icon. Resolving real icons means matching executables against installed `.desktop`
entries and loading themed icons; a wrong icon would be worse than an honest generic one, so
that work is deferred rather than approximated.

**Measured latency for a real game.** The direct-versus-routed comparison is a TCP connect
round trip to a target the user supplies or that is taken from an observed connection. It was
verified against a controlled server in the acceptance suite, not against a live game server.
