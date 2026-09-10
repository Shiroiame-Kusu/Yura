#!/usr/bin/env python3
"""Assertion helper over the JSONL logs the spike components write.

Keeping assertions here rather than in shell means each check states exactly what it
expected and what it actually saw, which is what makes a failed spike diagnosable instead
of just red.
"""

from __future__ import annotations

import argparse
import json
import sys


def load(path: str, event: str | None, since: float | None) -> list[dict]:
    records: list[dict] = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event and record.get("event") != event:
                    continue
                if since is not None and float(record.get("ts", 0)) < since:
                    continue
                records.append(record)
    except FileNotFoundError:
        pass
    return records


def cmd_assert(args: argparse.Namespace) -> int:
    records = load(args.file, args.event, args.since)
    considered = records[-args.window:] if args.window else records

    if args.min_count is not None and len(considered) < args.min_count:
        print(
            f"expected at least {args.min_count} '{args.event}' record(s) after "
            f"{args.since}, saw {len(considered)}"
        )
        return 1

    problems: list[str] = []
    for record in considered:
        if args.expect_ok is not None and bool(record.get("ok")) != args.expect_ok:
            problems.append(
                f"ok={record.get('ok')} (wanted {args.expect_ok}) detail={record.get('detail')!r}"
            )
            continue
        if args.expect_contains and args.expect_contains not in str(record.get("detail", "")):
            problems.append(
                f"detail {record.get('detail')!r} does not contain {args.expect_contains!r}"
            )

    if problems:
        print(f"{len(problems)}/{len(considered)} record(s) failed:")
        for problem in problems[:5]:
            print(f"  - {problem}")
        return 1

    print(f"{len(considered)} record(s) matched")
    return 0


def cmd_count(args: argparse.Namespace) -> int:
    records = load(args.file, args.event, args.since)
    if args.where_contains:
        key, _, needle = args.where_contains.partition("=")
        records = [r for r in records if needle in str(r.get(key, ""))]
    print(len(records))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    records = load(args.file, args.event, args.since)
    for record in records[-args.window:] if args.window else records:
        print(json.dumps(record, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assert", help="Fail unless every considered record matches")
    a.add_argument("file")
    a.add_argument("--event")
    a.add_argument("--since", type=float)
    a.add_argument("--window", type=int, default=0, help="Only consider the last N records")
    a.add_argument("--min-count", type=int)
    a.add_argument("--expect-ok", type=lambda v: v.lower() in ("1", "true", "yes"))
    a.add_argument("--expect-contains")
    a.set_defaults(func=cmd_assert)

    c = sub.add_parser("count")
    c.add_argument("file")
    c.add_argument("--event")
    c.add_argument("--since", type=float)
    c.add_argument("--where-contains", metavar="KEY=NEEDLE")
    c.set_defaults(func=cmd_count)

    s = sub.add_parser("show")
    s.add_argument("file")
    s.add_argument("--event")
    s.add_argument("--since", type=float)
    s.add_argument("--window", type=int, default=10)
    s.set_defaults(func=cmd_show)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
