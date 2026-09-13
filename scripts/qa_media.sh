#!/bin/bash
# Vision QA of README media — is the text readable?
cd /home/z/my-project/wormy
for img in cli-help.png cli-doctor.png dashboard-overview.png dashboard-tables.png dashboard-full.png repl-report-hub.png report-compare.png banner.png; do
  z-ai vision \
    -p "CLI screenshot for a README. Check text quality strictly: (1) every character readable? (2) any text cut off/overlapping/mangled/mid-word wrapped? (3) contrast OK? End with verdict line: VERDICT: GOOD or VERDICT: BAD" \
    -i "docs/images/$img" -o "/tmp/qa_$img.json" 2>/dev/null
  verdict=$(python3 -c "
import json,sys
try:
    d=json.load(open('/tmp/qa_$img.json'))
    c=d.get('choices',[{}])[0].get('message',{}).get('content','')
    v=[l for l in c.splitlines() if 'VERDICT' in l.upper()]
    print(v[-1].strip() if v else c[-120:].replace(chr(10),' '))
except Exception as e:
    print('PARSE_ERROR', e)")
  printf '%-24s %s\n' "$img" "$verdict"
done
