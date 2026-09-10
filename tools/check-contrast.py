#!/usr/bin/env python3
"""Checks the Yura palette against WCAG contrast targets, per theme.

The specification makes 4.5:1 for normal text an acceptance criterion, which means it has
to be measured rather than eyeballed. This parses the real token file, so it cannot drift
away from what the application actually renders.

Usage:  python3 tools/check-contrast.py [--tokens PATH] [--verbose]
Exit code is non-zero if any required pair fails.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Foreground token, background token, minimum ratio, what it is used for.
# 3.0 is the WCAG threshold for large text and for non-text UI boundaries.
REQUIRED: list[tuple[str, str, float, str]] = [
    ("YuraTextPrimaryColor",   "YuraSurfaceBaseColor",     4.5, "body text on the window"),
    ("YuraTextPrimaryColor",   "YuraSurfaceRaisedColor",   4.5, "body text on panels"),
    ("YuraTextPrimaryColor",   "YuraSurfaceSunkenColor",   4.5, "table text"),
    ("YuraTextPrimaryColor",   "YuraSurfaceOverlayColor",  4.5, "dialog text"),
    ("YuraTextPrimaryColor",   "YuraSurfaceHoverColor",    4.5, "text on a hovered row"),
    ("YuraTextPrimaryColor",   "YuraSurfaceSelectedColor", 4.5, "text on a selected row"),
    ("YuraTextSecondaryColor", "YuraSurfaceBaseColor",     4.5, "secondary text"),
    ("YuraTextSecondaryColor", "YuraSurfaceRaisedColor",   4.5, "secondary text on panels"),
    ("YuraTextSecondaryColor", "YuraSurfaceSunkenColor",   4.5, "secondary text in tables"),
    ("YuraTextTertiaryColor",  "YuraSurfaceBaseColor",     4.5, "tertiary text"),
    ("YuraTextTertiaryColor",  "YuraSurfaceRaisedColor",   4.5, "column headers"),
    ("YuraAccentTextColor",    "YuraSurfaceBaseColor",     4.5, "accent text and links"),
    ("YuraAccentTextColor",    "YuraSurfaceRaisedColor",   4.5, "accent text on panels"),
    ("YuraTextOnAccentColor",  "YuraAccentColor",          4.5, "label on an accent button"),
    ("YuraSuccessColor",       "YuraSurfaceRaisedColor",   4.5, "success status text"),
    ("YuraWarningColor",       "YuraSurfaceRaisedColor",   4.5, "warning status text"),
    ("YuraDangerColor",        "YuraSurfaceRaisedColor",   4.5, "failure status text"),
    ("YuraSuccessColor",       "YuraSuccessSubtleColor",   4.5, "success badge"),
    ("YuraWarningColor",       "YuraWarningSubtleColor",   4.5, "warning badge"),
    ("YuraDangerColor",        "YuraDangerSubtleColor",    4.5, "failure badge"),
    ("YuraAccentTextColor",    "YuraAccentSubtleColor",    4.5, "accent badge"),
    ("YuraNeutralStateColor",  "YuraSurfaceRaisedColor",   4.5, "neutral status text"),
    ("YuraFocusColor",         "YuraSurfaceBaseColor",     3.0, "focus ring"),
    ("YuraFocusColor",         "YuraSurfaceRaisedColor",   3.0, "focus ring on panels"),
    ("YuraBorderControlColor", "YuraSurfaceRaisedColor",   3.0, "input boundary"),
    ("YuraBorderControlColor", "YuraSurfaceSunkenColor",   3.0, "input boundary on sunken fill"),
]


def parse_tokens(path: Path) -> dict[str, dict[str, str]]:
    """Returns {theme: {token: hex}} for the ThemeDictionaries in the token file."""
    text = path.read_text(encoding="utf-8")
    themes: dict[str, dict[str, str]] = {}

    # Each <ResourceDictionary x:Key="Dark"> ... </ResourceDictionary> block.
    for match in re.finditer(
        r'<ResourceDictionary\s+x:Key="(Dark|Light)"\s*>(.*?)</ResourceDictionary>',
        text,
        re.DOTALL,
    ):
        theme, body = match.group(1), match.group(2)
        colors: dict[str, str] = {}
        for color in re.finditer(r'<Color\s+x:Key="([^"]+)"\s*>\s*(#[0-9A-Fa-f]{6,8})\s*</Color>', body):
            colors[color.group(1)] = color.group(2)
        themes[theme] = colors

    return themes


def to_rgb(value: str) -> tuple[int, int, int]:
    digits = value.lstrip("#")
    if len(digits) == 8:  # AARRGGBB
        digits = digits[2:]
    if len(digits) != 6:
        raise ValueError(f"cannot parse colour {value!r}")
    return tuple(int(digits[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def relative_luminance(rgb: tuple[int, int, int]) -> float:
    def channel(raw: int) -> float:
        c = raw / 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(v) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = relative_luminance(to_rgb(a)), relative_luminance(to_rgb(b))
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tokens",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "src/Yura.App/Themes/Tokens.axaml",
    )
    parser.add_argument("--verbose", action="store_true", help="Also print passing pairs")
    args = parser.parse_args()

    themes = parse_tokens(args.tokens)
    if not themes:
        print(f"no theme dictionaries found in {args.tokens}", file=sys.stderr)
        return 2

    failures = 0
    checked = 0

    for theme in ("Light", "Dark"):
        colors = themes.get(theme)
        if colors is None:
            print(f"{theme}: MISSING theme dictionary")
            failures += 1
            continue

        print(f"\n{theme}")
        for fg_key, bg_key, minimum, purpose in REQUIRED:
            fg, bg = colors.get(fg_key), colors.get(bg_key)
            if fg is None or bg is None:
                missing = fg_key if fg is None else bg_key
                print(f"  MISSING  {missing}")
                failures += 1
                continue

            ratio = contrast(fg, bg)
            checked += 1
            ok = ratio >= minimum
            if not ok:
                failures += 1
            if not ok or args.verbose:
                mark = "ok  " if ok else "FAIL"
                print(f"  {mark} {ratio:5.2f}:1  (need {minimum:.1f})  {purpose}")
                print(f"       {fg_key} {fg} on {bg_key} {bg}")

        if args.verbose is False and failures == 0:
            print("  all pairs meet their target")

    print(f"\n{checked} pair(s) checked, {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
