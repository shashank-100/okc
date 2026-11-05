#!/bin/sh
# Run a shell command on the Cloudflare build box: ./bx.sh 'cmd'
python3 -I -c '
import json, sys, urllib.request
tok = open(sys.argv[1]).read().strip()
req = urllib.request.Request("https://okc-cuda-build.shashank-telkhade.workers.dev/exec", data=json.dumps({"cmd": sys.argv[2]}).encode(),
    headers={"authorization": "Bearer " + tok, "content-type": "application/json", "user-agent": "okc-build/1"}, method="POST")
r = json.load(urllib.request.urlopen(req, timeout=1800))
sys.stdout.write(r["stdout"]); sys.stderr.write(r["stderr"]); sys.exit(r["exitCode"] or 0)
' "$(dirname "$0")/.token" "$1"
