"""E2E: real `wormy shell` in a pty — verify the round-5 UX fixes.

Feeds `help` + `exit` to the actual REPL and asserts:
- startup is quiet (no wall of ~90 INFO lines)
- the prompt carries ANSI colors, never raw rich markup
- exit prints the final report exactly once, no negative duration
"""
import os
import pty
import re
import select
import subprocess
import sys
import time
import fcntl
import termios

REPO = "/home/z/my-project/wormy"
PY = f"{REPO}/.venv/bin/python"
os.chdir(REPO)

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, b"\x00\x28\x64\x00\x00\x00\x00\x00")  # 100x40
proc = None
buf = b""
slave_fd = slave


def read_for(seconds: float, until: bytes = b"") -> bytes:
    """Read the pty for up to `seconds`; exit early once `until` is seen."""
    global buf
    end = time.time() + seconds
    chunk = b""
    while time.time() < end:
        if until and until in buf:
            break
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            chunk += data
            buf += data
    return chunk


try:
    proc = subprocess.Popen(
        [PY, "-m", "worm_core", "shell"],
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        cwd=REPO, close_fds=True,
    )
    os.close(slave_fd)
    slave_fd = -1

    boot = read_for(90, until=b"> ")
    booted = b"> " in buf

    os.write(master, b"help\r")
    read_for(4)

    os.write(master, b"exit\r")
    read_for(30, until=b"Reports written:")
    try:
        rc = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = -1
    read_for(2)
finally:
    if proc and proc.poll() is None:
        proc.kill()
    if slave_fd != -1:
        os.close(slave_fd)
    os.close(master)

out = buf.decode("utf-8", errors="replace")
plain = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", out)

report_lines = plain.count("Final report")
info_lines = len([l for l in plain.splitlines() if l.startswith("INFO -")])
checks = {
    "boot_repl_prompt": booted,
    "no_raw_prompt_markup": "[dim]" not in plain and "[bold cyan]wormy[/]" not in plain,
    "ansi_prompt_present": "\x1b[" in out and "○ IDLE" in plain,
    "info_wall_absent": info_lines <= 3,
    "help_table_rendered": ("Commands" in plain and "new|list|show|compare|html|prune" in plain),
    "final_report_once": report_lines == 1,
    "no_negative_duration": "-1 day" not in plain,
    "no_duplicate_shutdown": plain.count("Shutdown complete") <= 1,
    "reports_footer": "Reports written:" in plain,
    "clean_exit_code": rc == 0,
}
for k, v in checks.items():
    print(f"{'PASS' if v else 'FAIL'}  {k}")
if not all(checks.values()):
    print("\n--- LAST 120 LINES (plain) ---")
    print("\n".join(plain.splitlines()[-120:]))
    sys.exit(1)
print(f"\nE2E OK — {len(plain.splitlines())} total lines, INFO lines: {info_lines}")
