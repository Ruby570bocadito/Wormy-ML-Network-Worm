#!/usr/bin/env bash
# Record the REAL web dashboard during real `wormy run --dry-run --web`
# engagements against the loopback demo lab, then convert to GIF.
#
# Outputs:
#   docs/images/demo-dashboard.gif     (from media_work/dashboard.webm)
#   docs/images/dashboard-overview.png (viewport: KPIs, timeline, topology)
#   docs/images/dashboard-tables.png   (viewport: hosts / vulns / activity)
#
# Empirical timing (127.0.0.0/24, 15 listeners, 3s waves):
#   t=6    flask up, patient zero infected (1)
#   t~15   scan done -> total_discovered=5
#   t=16-26 propagation ticks infected 2 -> 5
#   t~27   engagement ends (process exits with it)
# Two engagements are used: one for the GIF (recorded during live ticks),
# one for the stills (page loaded early; last state persists after exit).
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
VIEW_W=1280
VIEW_H=800
REC_SECS=8

api() {  # api <field>
  curl -sf --max-time 2 "http://127.0.0.1:5000/api/status" 2>/dev/null \
    | $PY -c "import json,sys; print(json.load(sys.stdin).get('$1',0))" 2>/dev/null || echo 0
}

start_engagement() {  # writes PIDs into $LISTENERS / $RUN_PID
  pkill -f demo_listeners.py 2>/dev/null; sleep 0.3
  $PY scripts/demo_listeners.py >/dev/null 2>&1 &
  LISTENERS=$!
  WORMY_CONSOLE_LOG_LEVEL=ERROR $PY -m worm_core run --dry-run \
    --config media_work/dash_config.yaml --target 127.0.0.0/24 \
    --max-infections 5 --web > "$1" 2>&1 &
  RUN_PID=$!
  for i in $(seq 1 40); do
    curl -sf -o /dev/null http://127.0.0.1:5000/ && return 0
    sleep 0.5
  done
  return 1
}

stop_engagement() {
  kill $RUN_PID 2>/dev/null
  kill $LISTENERS 2>/dev/null
  pkill -f demo_listeners.py 2>/dev/null
}

# ══ Run A: the GIF ═══════════════════════════════════════════════
start_engagement media_work/run_web.out || { echo "flask never came up"; exit 1; }
echo "run A: flask up"

# wait until propagation is underway (infected >= 2)
for i in $(seq 1 25); do
  INF=$(api infected_hosts)
  [ "${INF:-0}" -ge 2 ] && break
  sleep 1
done
echo "run A: recording at infected=$INF"

agent-browser close >/dev/null 2>&1
agent-browser set viewport $VIEW_W $VIEW_H
agent-browser open http://127.0.0.1:5000/
agent-browser wait --load networkidle >/dev/null 2>&1

agent-browser record start media_work/dashboard.webm
sleep $REC_SECS                       # live ticking: infected 2 -> 4
agent-browser scroll down 900 >/dev/null 2>&1
sleep 1.5                             # hosts / vulns / activity on screen
agent-browser record stop
agent-browser close >/dev/null 2>&1
stop_engagement
echo "run A done (gif captured)"

# ══ Run B: the stills ════════════════════════════════════════════
start_engagement media_work/run_web2.out || { echo "flask never came up (B)"; exit 1; }
echo "run B: flask up"

agent-browser set viewport $VIEW_W $VIEW_H
agent-browser open http://127.0.0.1:5000/
agent-browser wait --load networkidle >/dev/null 2>&1

# poll the PAGE (not the API): the DOM lags the API by up to one 5s
# refresh cycle, so waiting for the rendered KPI guarantees the shot
for i in $(seq 1 80); do
  KINF=$(agent-browser eval "document.getElementById('k-infected').textContent" 2>/dev/null | tail -1)
  [ "${KINF//[^0-9]/}" = "5" ] && break
  sleep 0.4
done
echo "run B: page shows infected=${KINF//[^0-9]/} — shooting stills"
agent-browser screenshot docs/images/dashboard-overview.png
agent-browser scroll down 900 >/dev/null 2>&1
sleep 0.4
agent-browser screenshot docs/images/dashboard-tables.png
agent-browser close >/dev/null 2>&1
stop_engagement
echo "run B done (stills captured)"

# ══ webm -> GIF ══════════════════════════════════════════════════
ffmpeg -y -i media_work/dashboard.webm \
  -vf "fps=10,scale=960:-2:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=diff_mode=rectangle:dither=bayer:bayer_scale=4" \
  -loop 0 docs/images/demo-dashboard.gif 2>/dev/null
ls -la docs/images/demo-dashboard.gif docs/images/dashboard-overview.png docs/images/dashboard-tables.png
