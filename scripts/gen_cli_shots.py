"""Regenerate the simple CLI captures (help / doctor) at WORMY_MEDIA_COLS.

Reuses the round-4 pipeline functions (pty capture → rich SVG → 2x HTML
wrap). No lab fixtures needed for these two commands.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

import generate_docs_media as gdm  # noqa: E402

REPO = gdm.REPO
PY = gdm.PY

CAPTURES = {
    "clihelp": [PY, "-m", "worm_core", "--help"],
    "clidoctor": [PY, "-m", "worm_core", "doctor"],
}
TITLES = {
    "clihelp": "wormy --help",
    "clidoctor": "wormy doctor",
}


def main() -> int:
    for name, cmd in CAPTURES.items():
        print(f"capturing {name}: {' '.join(cmd[2:])} …")
        raw = gdm.capture(cmd)
        svg = gdm.ansi_to_svg(raw, TITLES[name])
        w = gdm.write_svg_asset(name, svg)
        print(f"  → media_work/{name}.svg (wrap width {w})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
