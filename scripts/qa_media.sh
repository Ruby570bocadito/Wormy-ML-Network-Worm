#!/bin/bash
# Vision QA of README media — is the text readable, is anything broken?
# Run after regenerating assets (scripts/gen_readme_media.py,
# scripts/record_dashboard.sh). Requires the z-ai CLI.
cd "$(dirname "$0")/.."

for img in banner.png cli-help.png report-compare.png \
           dashboard-overview.png dashboard-tables.png; do
  z-ai vision \
    -p "CLI/dashboard screenshot for a README. Check text quality strictly: (1) every character readable? (2) any text cut off/overlapping/mangled/mid-word wrapped? (3) contrast OK? End with verdict line: VERDICT: GOOD or VERDICT: BAD" \
    -i "docs/images/$img" -o "/tmp/qa_$img.json" 2>/dev/null
  verdict=$(python3 -c "
import json
try:
    d=json.load(open('/tmp/qa_$img.json'))
    c=d.get('choices',[{}])[0].get('message',{}).get('content','')
    v=[l for l in c.splitlines() if 'VERDICT' in l.upper()]
    print(v[-1].strip() if v else c[-120:].replace(chr(10),' '))
except Exception:
    print('VERDICT: NO RESPONSE')
")
  printf '%-26s %s\n' "$img" "$verdict"
done

for gif in demo-cli.gif demo-shell.gif demo-dashboard.gif; do
  # first + last frame are the QA proxies for the animation
  python3 - << EOF
from PIL import Image
im = Image.open("docs/images/$gif")
n = im.n_frames
for tag, i in (("first", 0), ("mid", n // 2), ("last", n - 1)):
    im.seek(i)
    im.convert("RGB").save(f"/tmp/qa_${gif%.gif}_{tag}.png")
EOF
  z-ai vision \
    -p "Three frames (first/mid/last) of a README demo GIF. Check: (1) text readable at README scale? (2) any broken table, error toast, or glitch? (3) does content evolve (a real session, not a frozen loop)? End with: VERDICT: GOOD or VERDICT: BAD" \
    -i "/tmp/qa_${gif%.gif}_first.png" -i "/tmp/qa_${gif%.gif}_mid.png" -i "/tmp/qa_${gif%.gif}_last.png" \
    -o "/tmp/qa_$gif.json" 2>/dev/null
  verdict=$(python3 -c "
import json
try:
    d=json.load(open('/tmp/qa_$gif.json'))
    c=d.get('choices',[{}])[0].get('message',{}).get('content','')
    v=[l for l in c.splitlines() if 'VERDICT' in l.upper()]
    print(v[-1].strip() if v else c[-120:].replace(chr(10),' '))
except Exception:
    print('VERDICT: NO RESPONSE')
")
  printf '%-26s %s\n' "$gif" "$verdict"
done
