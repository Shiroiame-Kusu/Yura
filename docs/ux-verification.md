# UX verification report

Covers the design and usability acceptance criteria for the first milestone: the design
system plus the representative Processes, Games and Proxy Editor screens.

Every screenshot referenced here was rendered from the real application under Xvfb at a
fixed surface size and scale factor, then inspected. Reproduce the whole set with:

```bash
./tools/capture-all.sh
```

Screenshots whose filename contains `demo` are rendered against a **simulated daemon**
(`--demo`). They show what a connected, populated UI looks like. They are not evidence
that routing works — see [Not verified](#not-verified).

---

## What was checked, and what it found

### Themes

| | |
| --- | --- |
| Dark | `01-processes-dark.png`, `03-games-dark-demo.png`, `05-proxy-editor-dark-demo.png` |
| Light | `02-processes-light.png`, `04-games-light-demo.png`, `06-proxy-editor-light-demo.png` |

Contrast is measured from the token file itself by `tools/check-contrast.py`, so it cannot
drift from what renders. **52 of 52 required pairs pass** in both themes — 4.5:1 for all
normal text, 3:1 for focus rings and control boundaries.

One finding worth recording: meeting 3:1 on control outlines conflicts with the
"subtle borders" direction if a single border token is used for both. Resolved by splitting
the token — `YuraBorderControl` (3:1, outlines inputs) is distinct from `YuraBorderSubtle`
(dividers and panel edges, deliberately quiet).

### Languages

`07-processes-zh.png`, `08-games-zh-demo.png`, `09-proxy-editor-zh-demo.png`.

Simplified Chinese renders correctly and the layout absorbs the length difference. Two
defects were found *only* by rendering Chinese and have been fixed:

- `138 of 730 processes` and `Live sorting` were hard-coded English. Both are now in the
  string table.
- Chinese labels are shorter than English ones, which exposed that the Processes column
  widths had been tuned to the English strings rather than to the data.

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

### Window sizes

| Size | Screenshot | Result |
| --- | --- | --- |
| 1280×800 (reference) | `01-processes-dark.png` | All seven columns readable |
| 960×640 (minimum) | `10-processes-min.png`, `11-games-min-demo.png` | Usable |

At 960 a docked 288-DIP inspector squeezed the executable path column out of existence
entirely. Fixed by making the inspector responsive: below 1000 DIPs of page width it
becomes an overlay that floats above the table when a row is selected, instead of competing
with it for width. The inspector markup lives in one control used in both placements, so
the two cannot drift apart.

### Scaling

`12-processes-125.png`, `13-processes-150.png`, `14-processes-200.png` — 125%, 150% and
200%. Layout is stable in DIPs at every step; no clipping, no overlap, no fractional-scale
seams. The 200% capture is a true 2560×1600 framebuffer.

### Data-shape edge cases

- **Long executable paths** — trimmed from the *head* so the file name stays visible, with
  the full value in a tooltip and in the inspector.
- **IPv6 literals** — `[2001:0db8:…:7334]:1080` renders bracketed and unwrapped in the
  proxy list (`06-proxy-editor-light-demo.png`).
- **7-digit PIDs** — `pid_max` on this kernel is 4194304, so PIDs can be seven digits. The
  PID and Parent columns had been sized for five and were clipping real values; both are
  now sized for seven. Found by reading `/proc/sys/kernel/pid_max`, not by guessing.
- **Unavailable values** — a process whose path cannot be read shows *Permission denied* in
  a muted italic style, never a blank cell. A connection count the daemon cannot supply
  shows `—`, never `0`.
- **Unmeasured metrics** — routed packet loss in `03-games-dark-demo.png` reads
  *Not measured*. `Metric.Value` is deliberately nullable so a missing measurement cannot
  be rendered as a zero.

### States

| State | Where |
| --- | --- |
| Disconnected | Default in every non-demo screenshot: persistent banner plus sidebar dot, both with text, and every action explains why it is unavailable |
| Empty | Proxy list empty state; process list empty state behind a filter |
| Populated | All `demo` screenshots |
| Error | Modelled and rendered: failure banner with an expandable technical-details section |
| Loading / pending | Modelled: a rule shows as *Applying…* until the daemon confirms it |

### Colour is never load-bearing

Every status carries a word as well as a colour: routing policy badges read
*Direct* / *Proxied* / *Blocked* / *Applying…*; the daemon dot sits next to
*Daemon not connected*; transport support reads *UDP not supported* rather than a red mark.

---

## Not verified

Stated plainly, because these are acceptance criteria that remain open.

**Three of the eleven routing acceptance tests.** Tests 1, 2, 4, 5, 6, 7, 8 (inclusion) and
11 are verified by the daemon acceptance suite — see
[daemon-acceptance.md](daemon-acceptance.md). Test 3 needs configuration persistence, child
*exclusion* needs the process-event watcher, and test 10 needs a Wine runtime in the harness.
None of the three is built.

**Keyboard-only walkthroughs of the five workflows.** The screenshot harness drives a bare
Xvfb with no window manager, so it cannot meaningfully exercise focus traversal, focus
visuals or keyboard activation. Accessible names and keyboard-reachable controls are in
place in the markup, and FluentAvalonia's own focus behaviour is inherited rather than
reimplemented, but this needs a human at a real keyboard.

**Screen reader behaviour.** `AutomationProperties.Name` is set on icon-only and
ambiguous controls, but no AT-SPI client was run against the application.

**Reduced motion.** The setting is wired and replaces transition durations with zero, but
it has not been checked against a real animated transition, because the current screens use
almost no motion.

**Large connection lists.** The Connections page is not built. The Processes table was
exercised with ~730 live processes and stays responsive, and rows are updated in place —
never rebuilt — specifically so selection, keyboard focus and scroll position survive the
two-second refresh. That mechanism is implemented but has not been tested under a
deliberately hostile update rate.

**Real application icons.** The process list shows a category glyph, not the application's
own icon. Resolving real icons means matching executables against installed `.desktop`
entries and loading themed icons; a wrong icon would be worse than an honest generic one,
so that work is deferred rather than approximated.
