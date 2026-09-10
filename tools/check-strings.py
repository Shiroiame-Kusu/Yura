#!/usr/bin/env python3
"""Checks that every string key the application uses exists in both language tables.

A missing key renders as «Key.Name» rather than crashing, which means a typo survives a
build, a test run and a screenshot review. This finds it mechanically instead.

Usage:  python3 tools/check-strings.py [--verbose]
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
STRINGS = ROOT / "src/Yura.App/Localization/Strings.cs"

# The two tables are `private static readonly Dictionary<...> English = new(...)  { ... };`
TABLE = re.compile(r"Dictionary<string, string> (\w+) = new\(StringComparer\.Ordinal\)\s*\{(.*?)\n    \};", re.S)
ENTRY = re.compile(r'\["([^"]+)"\]\s*=')

# Keys used from code and from markup.
CODE_USE = re.compile(r'Loc\.Current\[\s*"([^"]+)"\s*\]')
CODE_GET = re.compile(r'Loc\.Current\.Get\(\s*"([^"]+)"\s*\)')
XAML_USE = re.compile(r"loc:Tr\s+([A-Za-z0-9_.]+)")
# Keys built by a switch that returns a key literal, e.g. => "Settings.Service.Running"
CODE_LITERAL_KEY = re.compile(r'"((?:App|Nav|Shell|Common|Proxy|Chain|Games|Rules|Processes|Connections|Diagnostics|Settings|Describe|Policy|Route)\.[A-Za-z0-9_.]+)"')


def tables() -> dict[str, set[str]]:
    text = STRINGS.read_text(encoding="utf-8")
    found = {name: set(ENTRY.findall(body)) for name, body in TABLE.findall(text)}
    if not found:
        sys.exit(f"could not parse any string table out of {STRINGS}")
    return found


def strip_comments(text: str) -> str:
    """Drops comment lines, so a `<see cref="Rules.Foo"/>` is not mistaken for a key."""
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("//"))


def used() -> dict[str, list[str]]:
    """Every key the application asks for, with the files that ask for it."""
    where: dict[str, list[str]] = {}
    # Only the app has a string table; the domain is deliberately English (see RuleDescriber).
    for path in sorted((ROOT / "src/Yura.App").rglob("*")):
        if path.suffix not in (".cs", ".axaml") or "/obj/" in str(path) or "/bin/" in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        keys = set()
        if path.suffix == ".cs":
            code = strip_comments(text)
            keys |= set(CODE_USE.findall(code)) | set(CODE_GET.findall(code))
            # A key returned from a switch or held in a variable is still a key.
            keys |= {k for k in CODE_LITERAL_KEY.findall(code) if "." in k}
        else:
            keys |= set(XAML_USE.findall(text))
        for key in keys:
            where.setdefault(key, []).append(str(path.relative_to(ROOT)))
    return where


def main() -> int:
    verbose = "--verbose" in sys.argv
    tbl = tables()
    english = tbl.get("English", set())
    other = {name: keys for name, keys in tbl.items() if name != "English"}
    usage = used()

    failures = 0
    for key, files in sorted(usage.items()):
        if key not in english:
            print(f"MISSING from English: {key}  (used in {', '.join(sorted(set(files)))})")
            failures += 1

    for name, keys in sorted(other.items()):
        for key in sorted(english - keys):
            print(f"MISSING from {name}: {key}")
            failures += 1
        for key in sorted(keys - english):
            print(f"EXTRA in {name} (not in English): {key}")
            failures += 1

    unused = sorted(english - set(usage))
    if verbose:
        for key in unused:
            print(f"note: {key} is in the table but not referenced")

    print(f"\n{len(english)} key(s) in English, {len(usage)} referenced, "
          f"{len(unused)} unreferenced, {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
