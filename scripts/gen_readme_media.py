#!/usr/bin/env python3
"""README media pipeline — REAL recordings of the real tool.

Everything produced here is a genuine pty session of the actual CLI
(asciinema v2 cast with real timing), replayed through a terminal
emulator (pyte) and rendered frame-by-frame (Pillow), then assembled
into GIFs by ffmpeg. No fake typing players, no mockups.

Outputs (docs/images/):
  demo-cli.gif     bash: wormy doctor + wormy scan (live progress bar)
  demo-shell.gif   wormy shell --dry-run: scan / exploit / creds / report / exit
  cli-help.png     wormy --help (final frame)
  report-compare.png  wormy report compare <a> <b> (final frame)

Terminal geometry is chosen so nothing ever wraps (see
scripts/measure_widths.py) and every asset renders inside an exact-fit
window: no dead space, no portrait monsters, no full-bleed images.

Run:
    .venv/bin/python scripts/gen_readme_media.py          # casts + terminal media
    .venv/bin/python scripts/gen_readme_media.py --gif cli   # re-render one GIF
    .venv/bin/python scripts/gen_readme_media.py --png help  # re-render one PNG
    bash scripts/record_dashboard.sh                     # dashboard gif + stills
    bash scripts/qa_media.sh                             # vision QA of everything
    (deps: pip install pyte; ffmpeg on PATH)
"""
import fcntl
import json
import os
import pty
import random
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
WORK = os.path.join(REPO, "media_work")
IMG = os.path.join(REPO, "docs", "images")
LISTENERS = os.path.join(REPO, "scripts", "demo_listeners.py")

COLS = 80
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


# ── Part 1 — recorder: real pty session → asciinema v2 cast ──────

def _child_env(extra=None):
    """Colors on, sane terminal, no sandbox interference."""
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() not in ("NO_COLOR", "COLORTERM", "TERM", "COLUMNS", "LINES")
    }
    env.update(
        {
            "TERM": "xterm-256color",
            "COLUMNS": str(COLS),
            "LINES": "24",
            # the venv carries the real `wormy` console script (pip install -e .)
            "PATH": os.path.dirname(PY) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/home/z"),
        }
    )
    if extra:
        env.update(extra)
    return env


class Session:
    """Runs a command in a pty and records timestamped output (cast v2).

    merge_stderr=True routes the child's stderr into the pty as well —
    needed for bash (it paints PS1 prompts on stderr). wormy's own
    sessions keep stderr out and rely on WORMY_CONSOLE_LOG_LEVEL to
    stay clean.
    """

    def __init__(self, cmd, rows=24, env_extra=None, cwd=REPO, merge_stderr=False):
        self.rows = rows
        self.cmd = cmd
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, COLS, 0, 0))
        self.env_extra = env_extra
        self.proc = subprocess.Popen(
            cmd,
            stdin=slave,
            stdout=slave,
            stderr=slave if merge_stderr else subprocess.DEVNULL,
            cwd=cwd,
            env=_child_env(env_extra),
            preexec_fn=os.setsid,
        )
        os.close(slave)
        self.events = []  # [dt, "o", text]
        self.t0 = time.monotonic()
        self.deadline = self.t0 + 240
        self.closed = False

    def _drain(self, wait=0.25):
        end = time.time() + wait
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                self._emit(data)
                end = time.time() + wait
        return True

    def _emit(self, data: bytes):
        dt = round(time.monotonic() - self.t0, 6)
        self.events.append([dt, "o", data.decode("utf-8", "replace")])

    def tail(self, n=6):
        return strip_ansi("".join(e[2] for e in self.events[-40:]))[-n:]

    def wait_prompt(self, marker="> ", settle=1.2, timeout=90):
        """Wait until the output tail ends with marker (REPL/bash prompt)."""
        end = time.time() + timeout
        while time.time() < end and time.monotonic() < self.deadline:
            self._drain(0.25)
            if self.proc.poll() is not None:
                self._drain(0.5)
                return False
            if self.tail().endswith(marker) and self._stable(marker, settle):
                return True
        return False

    def _stable(self, marker, settle):
        """Prompt visible and nothing new arrived for `settle` seconds."""
        start = time.time()
        while time.time() - start < settle:
            self._drain(0.1)
            if not self.tail().endswith(marker):
                return False
        return True

    def wait_done(self, timeout=180):
        """Wait for the process to exit; drains output meanwhile."""
        end = time.time() + timeout
        while time.time() < end:
            self._drain(0.25)
            if self.proc.poll() is not None:
                self._drain(0.8)
                return True
        return False

    def type(self, line, cps=None):
        """Type a command like a human, char by char (real echo timing)."""
        delay = 1.0 / cps if cps else random.uniform(0.028, 0.055)
        for ch in line:
            try:
                os.write(self.master, ch.encode())
            except OSError:
                return
            time.sleep(delay)
        time.sleep(random.uniform(0.15, 0.4))
        try:
            os.write(self.master, b"\n")
        except OSError:
            return
        time.sleep(0.05)

    def send(self, line):
        try:
            os.write(self.master, line.encode() + b"\n")
        except OSError:
            pass

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            try:
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except Exception:
                    pass
        try:
            os.close(self.master)
        except OSError:
            pass

    def write_cast(self, path):
        header = {"version": 2, "width": COLS, "height": self.rows, "env": {"TERM": "xterm-256color"}}
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(header) + "\n")
            for dt, kind, data in self.events:
                fh.write(json.dumps([round(dt, 4), kind, data]) + "\n")


def last_seen(sess, marker):  # unused helper kept for API stability
    return 0.0


# ── cast loading ────────────────────────────────────────────────

def load_cast(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        header = json.loads(fh.readline())
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return header, events


# ── Part 2 — renderer: cast → PNG frames (pyte + Pillow) ────────

import pyte  # noqa: E402
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

# GitHub-dark terminal palette — limited colors keep GIF palettes tiny.
BG = (13, 17, 23)          # #0d1117
FG = (230, 237, 243)        # #e6edf3
CHROME = (48, 54, 61)       # #30363d window border
TITLE_FG = (139, 148, 158)  # #8b949e
BAR_BG = (22, 27, 34)       # #161b22
NAMED = {
    "black": (72, 79, 88),
    "red": (255, 123, 114),
    "green": (63, 185, 80),
    "brown": (210, 153, 34),          # xterm "yellow"
    "yellow": (210, 153, 34),
    "blue": (88, 166, 255),
    "magenta": (188, 140, 255),
    "cyan": (57, 197, 207),
    "white": (177, 186, 196),
    "brightblack": (139, 148, 158),
    "brightred": (255, 161, 152),
    "brightgreen": (86, 211, 100),
    "brightbrown": (227, 179, 65),
    "brightyellow": (227, 179, 65),
    "brightblue": (121, 192, 255),
    "brightmagenta": (210, 168, 255),
    "brightcyan": (86, 212, 221),
    "brightwhite": (240, 246, 252),
}
_XTERM_256 = {}


def _build_256():
    base = [NAMED[k] for k in (
        "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")] + [
        (139, 148, 158), (150, 124, 100), (169, 124, 134), (155, 117, 170),
        (176, 137, 116), (113, 122, 96), (79, 119, 136), (190, 98, 93),
        (133, 121, 51), (161, 113, 114), (117, 114, 161), (146, 111, 125),
        (103, 137, 114), (139, 152, 116), (179, 135, 106), (169, 184, 125),
    ]
    steps = [0, 95, 135, 175, 215, 255]
    cube = [(steps[r // 36], steps[(r // 6) % 6], steps[r % 6]) for r in range(216)]
    gray = [(n, n, n) for n in range(8, 248, 10)]
    _XTERM_256.update({i: c for i, c in enumerate(base + cube + gray)})


_build_256()


def _color(value, default):
    if value in (None, "default"):
        return default
    if isinstance(value, (tuple, list)):
        return tuple(value)
    v = str(value).strip().lower()
    if v in NAMED:
        return NAMED[v]
    if re.fullmatch(r"[0-9a-f]{6}", v):
        return (int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16))
    if v.isdigit():
        i = int(v)
        if i < 256:
            return _XTERM_256[i]
    return default


def _blend(fg, bg, ratio):
    return tuple(round(f * ratio + b * (1 - ratio)) for f, b in zip(fg, bg))


class TermRenderer:
    """Replays a cast through pyte and renders frames with Pillow.

    scale=2 renders at 2x so the final GIF/PNG stays crisp when GitHub
    downscales it to ~680 CSS px.
    """

    def __init__(self, cols, rows, title="", scale=2, font_size=15):
        self.cols, self.rows, self.title = cols, rows, title
        self.scale = scale
        fs = font_size * scale
        self.font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", fs
        )
        self.font_bold = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", fs
        )
        oblique = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Oblique.ttf"
        bold_oblique = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-BoldOblique.ttf"
        self.font_italic = (
            ImageFont.truetype(oblique, fs) if os.path.exists(oblique) else self.font
        )
        self.font_bold_italic = (
            ImageFont.truetype(bold_oblique, fs)
            if os.path.exists(bold_oblique)
            else self.font_bold
        )
        self.title_font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10 * scale
        )
        self.cw = round(self.font.getlength("M"))
        ascent, descent = self.font.getmetrics()
        self.lh = round((ascent + descent) * 1.06)
        # window chrome (all at scale px)
        s = scale
        self.pad_x, self.pad_y = 10 * s, 8 * s
        self.bar_h = 26 * s
        self.radius = 9 * s
        self.border = max(1, s)
        self.w = self.cols * self.cw + 2 * self.pad_x + 2 * self.border
        self.h = self.bar_h + self.rows * self.lh + 2 * self.pad_y + 2 * self.border

    def frame(self, screen, show_cursor=True):
        img = Image.new("RGB", (self.w, self.h), BG)
        d = ImageDraw.Draw(img)
        s = self.scale
        # window: rounded rect + title bar separator
        d.rounded_rectangle(
            [0, 0, self.w - 1, self.h - 1], radius=self.radius, outline=CHROME,
            width=self.border, fill=BG,
        )
        d.rounded_rectangle(
            [0, 0, self.w - 1, self.bar_h + self.radius], radius=self.radius, fill=BAR_BG,
        )
        d.rectangle([0, self.bar_h, self.w - 1, self.bar_h], fill=BAR_BG)
        d.line([0, self.bar_h, self.w - 1, self.bar_h], fill=CHROME, width=self.border)
        # traffic lights
        r = 5.5 * s
        cy = self.bar_h // 2
        for i, col in enumerate(((255, 95, 87), (254, 188, 46), (40, 200, 64))):
            cx = 14 * s + i * (2 * r + 5 * s) + r
            d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=col)
        # title
        tw = d.textlength(self.title, font=self.title_font)
        d.text(((self.w - tw) / 2, (self.bar_h - 10 * s) / 2 - 1 * s), self.title,
               font=self.title_font, fill=TITLE_FG)
        # screen buffer → styled runs
        ox = self.border + self.pad_x
        oy = self.border + self.bar_h + self.pad_y
        for y in range(self.rows):
            row = screen.buffer[y]
            x = 0
            while x < self.cols:
                ch = row[x]
                if ch is None:
                    x += 1
                    continue
                style = self._key(ch)
                run = ""
                xx = x
                while xx < self.cols:
                    c2 = row[xx]
                    if c2 is None or self._key(c2) != style:
                        break
                    run += c2.data
                    xx += 1
                fg = _color(ch.fg, FG)
                bg = _color(ch.bg, BG)
                if ch.reverse:
                    fg, bg = bg, fg
                font = self._font(ch.bold, ch.italics)
                px, py = ox + x * self.cw, oy + y * self.lh
                if bg != BG:
                    d.rectangle([px, py, px + (xx - x) * self.cw - 1, py + self.lh - 1], fill=bg)
                if run.strip():
                    d.text((px, py), run, font=font, fill=fg)
                x = xx
        # block cursor
        if show_cursor and 0 <= screen.cursor.y < self.rows:
            cx, cy = screen.cursor.x, screen.cursor.y
            if 0 <= cx < self.cols:
                ch = screen.buffer[cy][cx]
                col = _color(getattr(ch, "fg", None), FG) if ch and ch.fg not in (None, "default") else FG
                px, py = ox + cx * self.cw, oy + cy * self.lh
                d.rectangle([px, py, px + self.cw - 1, py + self.lh - 1], fill=col)
                if ch and ch.data.strip():
                    d.text((px, py), ch.data, font=self._font(ch.bold, ch.italics), fill=BG)
        return img

    def _key(self, ch):
        return (ch.fg, ch.bg, ch.bold, ch.italics, ch.reverse, ch.underscore)

    def _font(self, bold, italic):
        if bold and italic:
            return self.font_bold_italic
        if bold:
            return self.font_bold
        if italic:
            return self.font_italic
        return self.font


def _make_screen(cols, rows):
    screen = pyte.Screen(cols, rows)
    return screen, pyte.ByteStream(screen)


# ── Part 3 — GIF assembly + final-frame PNG ─────────────────────

def _virtual_timeline(events, max_gap):
    """Map real timestamps → virtual time with long gaps capped.

    A 30s pause between prompts stays 30s in the cast but only max_gap
    in the GIF — the boring wait disappears, the typing and the live
    progress bar keep their real cadence.
    """
    out, prev, acc = [], 0.0, 0.0
    for i, e in enumerate(events):
        acc += min(e[0] - prev, max_gap)
        prev = e[0]
        out.append((acc, i))
    return out


def render_gif(cast_path, out_path, title, fps=12, max_gap=0.55, tail_hold=1.4,
               scale=2, target_width=1120, font_size=15):
    header, events = load_cast(cast_path)
    cols, rows = header["width"], header["height"]
    r = TermRenderer(cols, rows, title, scale=scale, font_size=font_size)
    screen, stream = _make_screen(cols, rows)
    vt = _virtual_timeline(events, max_gap)
    total_vt = vt[-1][0] if vt else 0.0
    duration = total_vt + tail_hold
    n_frames = max(1, int(duration * fps))
    frames_dir = os.path.join(WORK, os.path.basename(cast_path) + "_frames")
    os.makedirs(frames_dir, exist_ok=True)
    idx = 0
    for k in range(n_frames):
        t = k / fps
        while idx < len(vt) and vt[idx][0] <= t:
            stream.feed(events[vt[idx][1]][2].encode("utf-8", "replace"))
            idx += 1
        img = r.frame(screen, show_cursor=t < total_vt + tail_hold * 0.7)
        img.save(os.path.join(frames_dir, f"f_{k:04d}.png"))
    vf = (
        f"scale={target_width}:-2:flags=lanczos,"
        f"split[a][b];[a]palettegen=max_colors=128[p];"
        f"[b][p]paletteuse=diff_mode=rectangle:dither=bayer:bayer_scale=4"
    )
    cmd = [
        "ffmpeg", "-y", "-framerate", str(fps), "-i", os.path.join(frames_dir, "f_%04d.png"),
        "-vf", vf, "-loop", "0", out_path,
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    # cleanup frames
    for f in os.listdir(frames_dir):
        os.remove(os.path.join(frames_dir, f))
    os.rmdir(frames_dir)
    size = os.path.getsize(out_path) / 1024 / 1024
    print(f"  {os.path.basename(out_path)}: {n_frames} frames @ {fps}fps, "
          f"{duration:.1f}s, {size:.2f} MB")
    return out_path


def render_png(cast_path, out_path, title, scale=2, font_size=15):
    """Render the FINAL screen state of a cast as a still PNG."""
    header, events = load_cast(cast_path)
    cols, rows = header["width"], header["height"]
    r = TermRenderer(cols, rows, title, scale=scale, font_size=font_size)
    screen, stream = _make_screen(cols, rows)
    for e in events:
        if e[1] == "o":
            stream.feed(e[2].encode("utf-8", "replace"))
    img = r.frame(screen, show_cursor=False)
    img.save(out_path)
    print(f"  {os.path.basename(out_path)}: {img.size[0]}x{img.size[1]}")
    return out_path


# ── Part 4 — sessions (what gets recorded) ──────────────────────

def _bash_cmd():
    return ["/bin/bash", "--noprofile", "--norc", "-i"]


def _engagement_ids():
    import glob

    ids = sorted(
        os.path.basename(p)[13:-5]
        for p in glob.glob(os.path.join(REPO, "reports", "audit_report_*.json"))
    )
    return ids


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
    """Throwaway lab config: geofence opened to loopback + this host only.

    The default production config keeps the geofence on the operator's
    LAN ranges; the demo lab lives on 127.0.0.2/.3/.4, so captures run
    with this config (auto-generated, never committed).
    """
    ip = _outbound_ip()
    path = os.path.join(WORK, "demo_config.yaml")
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
            "  propagation_delay: 1.5\n"
        )
    return path


def _run_engagement(config, target, cap, timeout=180):
    before = set(_engagement_ids())
    sess = Session(
        [PY, "-m", "worm_core", "run", "--dry-run", "--config", config,
         "--target", target, "--max-infections", str(cap)],
        rows=30,
    )
    try:
        sess.wait_done(timeout)
    finally:
        sess.close()
    new = set(_engagement_ids()) - before
    return sorted(new)[-1] if new else None


def record_all():
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(IMG, exist_ok=True)
    config = _write_demo_config()

    # fresh report state: the demo shows a first-run experience
    reports_dir = os.path.join(REPO, "reports")
    if os.path.isdir(reports_dir):
        for f in os.listdir(reports_dir):
            os.remove(os.path.join(reports_dir, f))

    # demo lab up (real banners on 127.0.0.2/.3/.4)
    listeners = subprocess.Popen(
        [PY, LISTENERS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1.0)
    try:
        print("[1/6] two real engagements for report compare…")
        id_a = _run_engagement(config, "127.0.0.1/32", 2)
        id_b = _run_engagement(config, "127.0.0.0/29", 5)
        print(f"    baseline={id_a} candidate={id_b}")
        with open(os.path.join(WORK, "ids.json"), "w") as fh:
            json.dump({"baseline": id_a, "candidate": id_b}, fh)

        # ── cast: cli (bash: doctor + scan) ──
        print("[2/6] recording cli session (doctor + scan)…")
        s = Session(
            _bash_cmd(), rows=24, merge_stderr=True,
            env_extra={"PS1": "$ ", "WORMY_CONSOLE_LOG_LEVEL": "ERROR", "PYTHONWARNINGS": "ignore"},
        )
        try:
            s.wait_prompt("$ ")
            s.type("wormy doctor")
            s.wait_prompt("$ ", timeout=120)
            s.type("wormy scan --target 127.0.0.0/29")
            s.wait_prompt("$ ", timeout=150)
            time.sleep(1.0)
            s.type("exit")
            s.wait_done(10)
        finally:
            s.close()
        s.write_cast(os.path.join(WORK, "cli.cast"))

        # ── cast: shell (REPL session) ──
        print("[3/6] recording shell session (REPL)…")
        s = Session(
            [PY, "-m", "worm_core", "shell", "--dry-run", "--config", config,
             "--target", "127.0.0.0/29", "--max-infections", "2"],
            rows=24,
            env_extra={"WORMY_CONSOLE_LOG_LEVEL": "ERROR"},
        )
        try:
            s.wait_prompt("> ", timeout=90)
            s.type("scan")
            s.wait_prompt("> ", timeout=120)
            s.type("exploit 127.0.0.2")
            s.wait_prompt("> ", timeout=60)
            s.type("report list")
            s.wait_prompt("> ", timeout=60)
            time.sleep(0.6)
            s.type("exit")
            s.wait_done(40)
        finally:
            s.close()
        s.write_cast(os.path.join(WORK, "shell.cast"))

        # ── casts: help + report compare ──
        print("[4/6] recording help session…")
        s = Session(
            _bash_cmd(), rows=32, merge_stderr=True,
            env_extra={"PS1": "$ ", "WORMY_CONSOLE_LOG_LEVEL": "ERROR", "PYTHONWARNINGS": "ignore"},
        )
        try:
            s.wait_prompt("$ ")
            s.type("wormy --help")
            s.wait_prompt("$ ", timeout=30)
        finally:
            s.close()
        s.write_cast(os.path.join(WORK, "help.cast"))

        print("[5/6] recording report compare session…")
        s = Session(
            _bash_cmd(), rows=30, merge_stderr=True,
            env_extra={"PS1": "$ ", "WORMY_CONSOLE_LOG_LEVEL": "ERROR", "PYTHONWARNINGS": "ignore"},
        )
        try:
            s.wait_prompt("$ ")
            s.type(f"wormy report compare {id_a} {id_b}")
            s.wait_prompt("$ ", timeout=30)
            time.sleep(0.8)
        finally:
            s.close()
        s.write_cast(os.path.join(WORK, "compare.cast"))
    finally:
        listeners.terminate()
        listeners.wait(timeout=5)
    print("[6/6] casts ready in media_work/")
    return True


def render_all():
    os.makedirs(IMG, exist_ok=True)
    print("rendering GIFs…")
    render_gif(os.path.join(WORK, "cli.cast"), os.path.join(IMG, "demo-cli.gif"),
               "wormy — doctor + network scan — bash")
    render_gif(os.path.join(WORK, "shell.cast"), os.path.join(IMG, "demo-shell.gif"),
               "wormy shell — dry-run engagement — REPL")
    print("rendering PNGs…")
    render_png(os.path.join(WORK, "help.cast"), os.path.join(IMG, "cli-help.png"),
               "wormy — help")
    render_png(os.path.join(WORK, "compare.cast"), os.path.join(IMG, "report-compare.png"),
               "wormy — report compare")
    return True


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args == ["--record"]:
        record_all()
        render_all()
    elif args == ["--render"]:
        render_all()
    elif args[:2] == ["--gif"]:
        name = args[2] if len(args) > 2 else "cli"
        render_gif(
            os.path.join(WORK, f"{name}.cast"),
            os.path.join(IMG, f"demo-{name}.gif"),
            {"cli": "wormy — doctor + network scan — bash",
             "shell": "wormy shell — dry-run engagement — REPL"}[name],
        )
    elif args[:2] == ["--png"]:
        name = args[2] if len(args) > 2 else "help"
        render_png(
            os.path.join(WORK, f"{name}.cast"),
            os.path.join(IMG, f"{name.replace('compare', 'report-compare')}.png"),
            {"help": "wormy — help", "compare": "wormy — report compare"}[name],
        )
    else:
        print(__doc__)
        sys.exit(2)
