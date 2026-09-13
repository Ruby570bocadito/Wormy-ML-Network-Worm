#!/usr/bin/env python3
"""Measure real CLI output widths at a candidate terminal width.

Used to pick the terminal size for README media: every captured surface must
render without rich wrapping rows (the 'descuadrado' look).
"""
import os
import pty
import re
import select
import struct
import subprocess
import fcntl
import termios
import time
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(REPO, ".venv", "bin", "python")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def capture(cmd, cols, rows=200, timeout=90, cwd=REPO):
    m, s = pty.openpty()
    fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = os.environ.copy()
    env.update({"COLUMNS": str(cols), "LINES": str(rows), "TERM": "xterm-256color"})
    p = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=s, stderr=subprocess.DEVNULL, cwd=cwd, env=env
    )
    os.close(s)
    chunks, dl = [], time.time() + timeout
    while time.time() < dl:
        r, _, _ = select.select([m], [], [], 0.3)
        if r:
            try:
                d = os.read(m, 65536)
            except OSError:
                break
            if not d:
                break
            chunks.append(d)
            dl = time.time() + 5
        if p.poll() is not None:
            time.sleep(0.3)
            r, _, _ = select.select([m], [], [], 0.3)
            if r:
                chunks.append(os.read(m, 65536))
            break
    try:
        p.kill()
    except Exception:
        pass
    os.close(m)
    raw = b"".join(chunks).decode("utf-8", "replace")
    raw = raw.replace("\r\n", "\n")
    lines = [l.rsplit("\r", 1)[-1] for l in raw.split("\n")]
    return "\n".join(lines)


def report(name, raw, cols):
    plain = [ANSI_RE.sub("", l) for l in raw.splitlines()]
    plain = [l.rstrip() for l in plain]
    maxw = max((len(l) for l in plain), default=0)
    status = "OK " if maxw <= cols else "WRAP"
    print(f"[{status}] {name}: max width {maxw} @ {cols} cols, {len(plain)} lines")
    if maxw > cols:
        for l in plain:
            if len(l) > cols:
                print("   ", repr(l[:110]))
    return maxw


if __name__ == "__main__":
    cols = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    wm = [PY, "-m", "worm_core"]
    report("doctor", capture(wm + ["doctor"], cols), cols)
    report("help", capture(wm + ["--help"], cols), cols)
    report("version", capture(wm + ["version"], cols), cols)
    report("lab-status", capture(wm + ["lab", "status"], cols), cols)
