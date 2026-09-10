# Configuration

Yura stores its configuration in **`~/.config/Yura/config.json`**, honouring
`$XDG_CONFIG_HOME` when it is set.

```bash
dotnet run --project src/Yura.App -- --config-report
```

```
config directory : /home/hakuu/.config/Yura
config file      : /home/hakuu/.config/Yura/config.json
XDG_CONFIG_HOME  : (unset, using ~/.config)
secret store     : the desktop secret service
```

## Who owns it

The **application** owns the configuration; the daemon owns nothing across a restart.

That split is deliberate. The daemon runs as root, and a root process writing into a user's
home directory leaves root-owned files the application can then no longer rewrite. So the
app is the source of truth, and it re-sends its proxies and persistent rules to the daemon
every time it connects. A restart of either process converges to the same state, and there
is no second copy of the truth to drift.

## What is written

```json
{
  "version": 1,
  "settings": { "theme": "dark", "language": "en", "reducedMotion": false },
  "proxies": [
    { "id": "…", "name": "Home server", "protocol": "socks5",
      "host": "127.0.0.1", "port": 1080, "passwordRef": "…" }
  ],
  "rules": [
    { "id": "…", "name": "curl (all instances)", "lifetime": "persistent",
      "processKind": "executablePath", "executablePath": "/usr/bin/curl",
      "action": "proxy", "proxyId": "…" }
  ]
}
```

**Only persistent rules are saved.** An instance rule names a pid and a process start time,
which mean nothing after a reboot; persisting one would let a reused pid inherit a policy,
which is the single thing the whole design exists to prevent. Session rules belong to a
daemon that has since exited. Both are dropped on save and the omission is tested.

Restored rules come back **unapplied**. A rule that was live in a previous session is not
live now, and the UI shows it as pending until the daemon confirms it.

## Passwords are not in this file

`passwordRef` is a key into the desktop secret service, reached through `secret-tool`, which
works with gnome-keyring and kwallet alike because both implement the same D-Bus interface.
The secret is written to the tool's stdin, so it never appears in the process table.

If no secret service is available Yura keeps the password **in memory for that session
only** and says so under the password field. It does not fall back to a file: writing a
password to disk because the keyring was missing would be a silent downgrade of the one
guarantee worth making here.

The reference is the proxy's id, not its name, so renaming a proxy cannot orphan its
password.

## Durability and permissions

- Writes are **atomic**: a temporary file in the same directory, then a rename. A crash or a
  full disk cannot leave a half-written file that fails to parse on next launch.
- The directory is `700` and the file is `600`. It names every proxy you reach; there is no
  reason for it to be world-readable.
- An **unparseable file is preserved** as `config.json.corrupt` rather than overwritten, and
  the app reports it. Losing someone's proxy list to one bad byte is not an acceptable
  outcome.
- A file written by a **newer version** is left untouched and the session starts empty,
  rather than being downgraded in place.
- Saves are coalesced, so a burst of edits produces one write.

## Verified

`ConfigStoreTests` covers the round trip, the exclusion of instance and session rules, the
absence of passwords in the file, permissions, the corrupt-file path, the newer-version
path, and `XDG_CONFIG_HOME`. End to end, the application writes `config.json` at mode 600
in a 700 directory on first run, and restores proxies and rules from a hand-written file —
see `docs/screenshots/16-proxies-restored-from-config.png`.

## What else is in the file

Beyond settings, proxies and persistent rules, the configuration also holds:

- **Proxy chains**, as an ordered list of proxy ids. The order is the whole meaning of a
  chain — element 0 is dialled first — so it round-trips exactly. A chain whose hop no longer
  exists is kept and shown with the missing hop marked rather than silently repaired.
- **Game profiles**, but only once the user has told Yura something rediscovery cannot find
  again: a chosen route, a path learned by attaching to a running process, or a measurement
  target. A game that is merely installed is rediscovered from the Steam library on every
  start, so the file does not fill up with games nobody has configured.
- **The DNS policy**, which is global rather than per rule because it changes the shape of the
  installed nftables ruleset.

A game profile's id is derived from its Steam app id, so a saved route survives the library
moving to another drive or being rescanned.
