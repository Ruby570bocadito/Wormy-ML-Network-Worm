#!/usr/bin/env python3
"""Regenerate the README terminal screenshots and the demo player.

Produces REAL assets from REAL runs — nothing is mocked:

  1. Runs three dry-run engagements (weak baseline, full lab candidate, and a
     capped third one for the prune story) against a temporary loopback lab
     of fake-but-honest services (scripts/demo_listeners.py).
  2. Captures the actual CLI/REPL output through a pty (rich colors intact,
     loguru INFO on stderr dropped) and renders:
       - SVG terminal shots (rich export_svg) + HTML wrappers for 2x
         screenshots
       - an HTML "player" that types the commands and reveals the output,
         ready to record as a GIF.

Usage::

    .venv/bin/python scripts/generate_docs_media.py

Then take the pictures with a headless browser and ffmpeg (manual)::

    agent-browser set viewport 2100 2300
    agent-browser open file://media_work/compare_wrap.html
    agent-browser screenshot docs/images/report-compare.png --full   # crop 2x
    agent-browser set viewport 900 560
    agent-browser open file://media_work/player.html
    agent-browser record start media_work/demo.webm
    agent-browser press Space            # starts the typed demo
    agent-browser record stop
    ffmpeg -i media_work/demo.webm -vf "fps=12,scale=720:-1:flags=lanczos,\\
split[a][b];[a]palettegen[p];[b][p]paletteuse" docs/images/demo-report-hub.gif

The loopback demo needs the geofence to allow the operator's outbound IP;
the script writes a throwaway config (media_work/demo_config.yaml) for that.
"""
import html
import io
import os
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import fcntl
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
LISTENERS = os.path.join(REPO, "scripts", "demo_listeners.py")
WORK = os.path.join(REPO, "media_work")
COLS = 100

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def collapse_cr(s: str) -> str:
    """Normalize pty CRLF, then keep only the final frame of \\r redraws."""
    s = s.replace("\r\n", "\n")
    lines = []
    for line in s.split("\n"):
        if "\r" in line:
            line = line.rsplit("\r", 1)[-1]
        lines.append(line)
    return "\n".join(lines)


# ── pty capture ─────────────────────────────────────────────────


def capture(cmd, cols=COLS, rows=120, cwd=REPO, timeout=120, env_extra=None):
    """Run cmd in a pty; stdout (rich colors) is captured, stderr dropped."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = os.environ.copy()
    env.update({"COLUMNS": str(cols), "LINES": str(rows), "TERM": "xterm-256color"})
    if env_extra:
        env.update(env_extra)
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=slave,
        stderr=subprocess.DEVNULL,
        cwd=cwd,
        env=env,
    )
    os.close(slave)
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        _drain(master, chunks, 0.3)
        if p.poll() is not None:
            _drain(master, chunks, 0.4)
            break
    p.kill()
    os.close(master)
    return collapse_cr(b"".join(chunks).decode("utf-8", "replace"))


def _drain(master, out, timeout):
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.05)
        if r:
            try:
                data = os.read(master, 65536)
            except OSError:
                return
            if not data:
                return
            out.append(data)
            end = time.time() + timeout


def capture_repl(cmd, feed, cols=COLS, rows=140, cwd=REPO, timeout=180):
    """Spawn an interactive process; feed a line whenever the prompt appears."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = os.environ.copy()
    env.update({"COLUMNS": str(cols), "LINES": str(rows), "TERM": "xterm-256color"})
    p = subprocess.Popen(
        cmd, stdin=slave, stdout=slave, stderr=subprocess.DEVNULL, cwd=cwd, env=env
    )
    os.close(slave)
    chunks, queue = [], list(feed)
    deadline = time.time() + timeout
    last_write = 0.0
    while time.time() < deadline:
        _drain(master, chunks, 0.3)
        if p.poll() is not None:
            _drain(master, chunks, 0.4)
            break
        tail = strip_ansi(b"".join(chunks).decode("utf-8", "replace"))[-3:]
        if queue and tail.endswith("> ") and (time.time() - last_write) > 1.0:
            os.write(master, queue.pop(0).encode() + b"\n")
            last_write = time.time()
    if p.poll() is None:
        p.kill()
    os.close(master)
    return collapse_cr(b"".join(chunks).decode("utf-8", "replace"))


# ── ANSI -> SVG / HTML lines ────────────────────────────────────

from rich.console import Console  # noqa: E402
from rich.text import Text  # noqa: E402


def ansi_to_svg(raw, title, cols=COLS):
    c = Console(file=io.StringIO(), width=cols, record=True, force_terminal=True)
    c.print(Text.from_ansi(raw))
    return c.export_svg(title=title)


def lines_to_html(raw, cols=COLS):
    c = Console(file=io.StringIO(), width=cols, record=True, force_terminal=True)
    c.print(Text.from_ansi(raw))
    segs = list(c._record_buffer)
    out = []
    for line_runs in _split_lines(segs):
        pieces = []
        for text, style in line_runs:
            css = _style_css(style, c)
            esc = html.escape(text)
            pieces.append(f'<span style="{css}">{esc}</span>' if css else f"<span>{esc}</span>")
        out.append("".join(pieces))
    return out


def _split_lines(segs):
    lines = [[]]
    for seg in segs:
        parts = seg.text.split("\n")
        for i, part in enumerate(parts):
            if i > 0:
                lines.append([])
            if part:
                lines[-1].append((part, seg.style))
    return lines


def _style_css(style, console):
    st = console.get_style(style) if isinstance(style, str) else style
    css = []
    if st.color:
        t = st.color.get_truecolor()
        css.append(f"color:#{t.red:02x}{t.green:02x}{t.blue:02x}")
    if st.bgcolor:
        t = st.bgcolor.get_truecolor()
        css.append(f"background-color:#{t.red:02x}{t.green:02x}{t.blue:02x}")
    if st.bold:
        css.append("font-weight:700")
    if st.italic:
        css.append("font-style:italic")
    if st.underline:
        css.append("text-decoration:underline")
    if st.dim:
        css.append("opacity:0.6")
    return ";".join(css)


# ── output shaping ──────────────────────────────────────────────

ESC = chr(27)
# The REPL prompt goes through built-in input(), so its rich markup renders
# literally; translate the tags to the ANSI styles they were meant to be.
_PROMPT_MARKUP = {
    "[dim]": ESC + "[2m",
    "[bold cyan]": ESC + "[1;36m",
    "[bold green]": ESC + "[1;32m",
    "[/]": ESC + "[0m",
}


def fix_repl_prompt(raw):
    for tag, ansi in _PROMPT_MARKUP.items():
        raw = raw.replace(tag, ansi)
    return re.sub(ESC + r"(?!\[)", "", raw)


def cut_at(raw, marker):
    idx = raw.find(marker)
    return raw[:idx] if idx != -1 else raw


def keep_block(raw, start_re):
    lines, out, keeping = raw.splitlines(), [], False
    for line in lines:
        if not keeping and re.search(start_re, strip_ansi(line)):
            keeping = True
        if keeping:
            out.append(line)
    return "\n".join(out)


# ── asset writers ───────────────────────────────────────────────

WRAP_TMPL = """<!doctype html>
<html><head><meta charset="utf-8"><style>
html,body{margin:0;padding:0;background:#0d1117;}
img{display:block;}
</style></head>
<body><img src="{src}" width="{width}"></body></html>
"""


def write_svg_asset(name, svg, scale=2):
    os.makedirs(WORK, exist_ok=True)
    with open(os.path.join(WORK, f"{name}.svg"), "w", encoding="utf-8") as fh:
        fh.write(svg)
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    w = int(float(m.group(1))) * scale
    with open(os.path.join(WORK, f"{name}_wrap.html"), "w", encoding="utf-8") as fh:
        fh.write(WRAP_TMPL.format(src=f"{name}.svg", width=w))
    return w


PLAYER_TMPL = """<!doctype html>
<html><head><meta charset="utf-8"><title>wormy demo</title>
<style>
*{box-sizing:border-box;}
html,body{margin:0;padding:0;background:#0d1117;}
body{font-family:"Sarasa Mono SC","DejaVu Sans Mono",Menlo,Consolas,monospace;
      font-size:13px;line-height:1.5;}
.term{width:900px;height:560px;background:#0d1117;color:#e6edf3;
      padding:12px 16px 16px;border-radius:10px;overflow:hidden;
      display:flex;flex-direction:column;}
.bar{flex:0 0 auto;display:flex;align-items:center;gap:8px;margin:0 -16px 10px;
      padding:9px 14px;background:#161b22;border-bottom:1px solid #21262d;
      border-radius:10px 10px 0 0;}
.dot{width:11px;height:11px;border-radius:50%;}
.r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}
.title{flex:1;text-align:center;color:#8b949e;font-size:12px;user-select:none;}
.screen{flex:1 1 auto;overflow:hidden;display:flex;flex-direction:column;
         justify-content:flex-end;}
.line{white-space:pre;min-height:19.5px;}
.p{color:#3fb950;font-weight:700}
.cmd{color:#e6edf3;font-weight:600}
.cursor{display:inline-block;width:7.5px;height:15px;background:#3fb950;
         vertical-align:-2px;animation:blink 1s steps(1) infinite;}
@keyframes blink{50%{opacity:0;}}
.hidden{visibility:hidden;}
</style></head>
<body>
<div class="term" id="term">
  <div class="bar"><div class="dot r"></div><div class="dot y"></div><div class="dot g"></div>
    <div class="title">wormy — engagement reports — zsh</div></div>
  <div class="screen" id="screen"></div>
</div>
<script>
const steps = {steps_json};
const screen = document.getElementById('screen');
function outLine(htmlLine) {
  const div = document.createElement('div');
  div.className = 'line hidden';
  div.innerHTML = htmlLine || '&nbsp;';
  screen.appendChild(div);
  while (screen.children.length > 24) screen.removeChild(screen.firstChild);
  return div;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function typeCmd(cmd) {
  const div = outLine('<span class="p">$ </span><span class="cmd"></span><span class="cursor"></span>');
  const span = div.querySelector('.cmd');
  for (const ch of cmd) { span.textContent += ch; await sleep(26); }
  await sleep(240);
  div.querySelector('.cursor').remove();
}
async function reveal(lines, ms=70) {
  for (const line of lines) { outLine(line).classList.remove('hidden'); await sleep(ms); }
}
async function play() {
  await sleep(400);
  for (const step of steps) {
    if (step.cmd !== undefined) await typeCmd(step.cmd);
    if (step.out) await reveal(step.out, step.ms || 70);
    await sleep(850);
  }
  const end = outLine('<span class="p">$ </span><span class="cursor"></span>');
  end.classList.remove('hidden');
  await sleep(1600);
  document.title = 'DONE';
}
const hint = outLine('<span style="color:#8b949e">&#9654; press any key to start</span>');
hint.classList.remove('hidden');
function start() {
  if (window.__started) return;
  window.__started = true;
  hint.remove();
  play();
}
document.addEventListener('keydown', start);
document.addEventListener('mousedown', start);
</script>
</body></html>
"""


def write_player(steps):
    path = os.path.join(WORK, "player.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(PLAYER_TMPL.replace("{steps_json}", json_dumps(steps)))
    return path


def json_dumps(steps):
    import json

    return json.dumps(steps)


# ── demo engagement helpers ─────────────────────────────────────


def _outbound_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _write_demo_config():
    ip = _outbound_ip()
    path = os.path.join(WORK, "demo_config.yaml")
    os.makedirs(WORK, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "# throwaway demo config (auto-generated, not committed)\n"
            "safety:\n"
            "  geofence_enabled: true\n"
            "  allowed_networks:\n"
            '    - "127.0.0.0/8"\n'
            f'    - "{ip}/32"\n'
            "  max_runtime_hours: 1\n"
            "network:\n"
            "  target_ranges:\n"
            '    - "127.0.0.0/29"\n'
            "propagation:\n"
            "  max_infections: 5\n"
            "  propagation_delay: 0.2\n"
        )
    return path


def _engagement_ids():
    ids = sorted(
        m.group(1)
        for m in re.finditer(
            r"audit_report_(\d{8}_\d{6})\.json",
            " ".join(os.listdir(os.path.join(REPO, "reports"))),
        )
    )
    return ids


def _run_engagement(config, target, cap):
    wm = [PY, "-m", "worm_core"]
    before = set(_engagement_ids())
    capture(
        wm
        + [
            "run",
            "--dry-run",
            "--config",
            config,
            "--target",
            target,
            "--max-infections",
            str(cap),
        ],
        timeout=180,
    )
    new = set(_engagement_ids()) - before
    return sorted(new)[-1] if new else None


# ── main ────────────────────────────────────────────────────────


def main():
    os.makedirs(WORK, exist_ok=True)
    config = _write_demo_config()
    wm = [PY, "-m", "worm_core"]

    print("[1/5] weak baseline engagement (no lab services)…")
    id_a = _run_engagement(config, "127.0.0.1/32", 2)

    print("[2/5] starting loopback lab + full candidate engagement…")
    listeners = subprocess.Popen(
        [PY, LISTENERS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1.2)
    try:
        id_b = _run_engagement(config, "127.0.0.0/29", 5)
        id_c = _run_engagement(config, "127.0.0.0/29", 2)

        print("[3/5] static captures (compare + REPL)…")
        cmp_raw = capture(wm + ["report", "compare", id_a, id_b])
        write_svg_asset(
            "compare", ansi_to_svg(cmp_raw, "wormy report compare")
        )

        repl_raw = capture_repl(
            wm + ["shell", "--dry-run"],
            ["report list", f"report compare {id_a} {id_b}", "exit"],
        )
        repl_raw = fix_repl_prompt(cut_at(repl_raw, "Exiting"))
        write_svg_asset("repl", ansi_to_svg(repl_raw, "wormy shell — report hub"))

        print("[4/5] player steps…")
        steps = [
            {"cmd": "wormy report list", "out": lines_to_html(capture(wm + ["report", "list"])), "ms": 110},
            {"cmd": f"wormy report compare {id_a} {id_b}", "out": lines_to_html(cmp_raw), "ms": 80},
            {
                "cmd": f"wormy report compare {id_a} {id_b} --metrics infected,hosts_discovered,vulnerabilities",
                "out": lines_to_html(
                    capture(
                        wm
                        + [
                            "report",
                            "compare",
                            id_a,
                            id_b,
                            "--metrics",
                            "infected,hosts_discovered,vulnerabilities",
                        ]
                    )
                ),
                "ms": 90,
            },
        ]

        iso = os.path.join(WORK, "reports_iso")
        os.makedirs(iso, exist_ok=True)
        for f in os.listdir(iso):
            os.remove(os.path.join(iso, f))
        for rid in (id_a, id_b, id_c):
            for ext in ("json", "csv", "txt"):
                src = os.path.join(REPO, "reports", f"audit_report_{rid}.{ext}")
                if os.path.exists(src):
                    shutil.copy(src, iso)
        steps.append(
            {
                "cmd": "wormy report prune --dry-run --keep 2",
                "out": lines_to_html(
                    capture(
                        wm
                        + ["report", "prune", "--dry-run", "--keep", "2", "--reports-dir", iso]
                    )
                ),
                "ms": 90,
            }
        )

        scan_raw = capture(
            wm + ["scan", "--target", "127.0.0.0/29", "--csv", "hosts.csv", "--config", config]
        )
        block = keep_block(scan_raw, r"hosts  \|  Found")
        scan_lines = [block.splitlines()[-1]] if block else []
        csv_written = [l for l in scan_raw.splitlines() if "CSV written" in strip_ansi(l)]
        steps.append(
            {
                "cmd": "wormy scan --target 127.0.0.0/29 --csv hosts.csv",
                "out": lines_to_html("\n".join(scan_lines + csv_written)),
                "ms": 220,
            }
        )
        cat_lines = ["ip,hostname,os_guess,open_ports,services,vulnerability_score,scan_time"]
        with open(os.path.join(REPO, "hosts.csv"), encoding="utf-8") as fh:
            cat_lines += [l.rstrip("\n") for l in fh]
        steps.append(
            {
                "cmd": "cat hosts.csv",
                "out": [f'<span style="color:#e6edf3">{html.escape(l)}</span>' for l in cat_lines],
                "ms": 130,
            }
        )

        path = write_player(steps)
        print(f"[5/5] assets ready in {WORK}/ (player: {path})")
        print("ids:", {"baseline": id_a, "candidate": id_b, "prune-third": id_c})
    finally:
        listeners.terminate()
        listeners.wait(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
