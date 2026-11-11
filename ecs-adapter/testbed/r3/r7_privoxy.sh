#!/usr/bin/env bash
# r7_privoxy (round 10, 2026-10-30): Privoxy, Debian 12 (3.0.34) -> Debian 13 (4.0.0), its log file.
# Proxied requests from clients at fixed addresses to a small web server: allowed paths, blocked paths, an
# unreachable host. The event runs (old 3, new B) use paths the samples never do.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_privoxy)
docker build -q --build-arg BASE=debian:12 -t r7-privoxy12 "$HERE/docker/r7privoxy" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-privoxy13 "$HERE/docker/r7privoxy" >/dev/null
docker rm -f r7-web-target >/dev/null 2>&1; docker run -d --cpus 1 --name r7-web-target --network $NET python:3.11-slim python -m http.server 80 >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (host, path, client address)
drive(){
  python3 -c "
import ast, sys
for h, path, ip in ast.literal_eval(sys.argv[1]):
    print(ip, h, path)" "$2" | while read -r ip h path; do
    docker run --rm --cpus 1 --network $NET --ip "$ip" python:3.11-slim python -c "
import urllib.request
op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://$1:8118'}))
try: op.open(urllib.request.Request('http://$h$path', headers={'User-Agent': 'curl/8.5.0'}), timeout=6)
except Exception: pass" >/dev/null 2>&1; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "Request:|Crunch:|Error:"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("r7-web-target","/","172.21.82.11"),("r7-web-target","/admin","172.21.82.11"),("r7-web-target","/reports","172.21.82.12"),("no-such-host.lab","/","172.21.82.13"),("r7-web-target","/.env","172.21.82.201")]'
OLD2='[("r7-web-target","/index.html","172.21.82.14"),("r7-web-target","/wp-login.php","172.21.82.202"),("r7-web-target","/docs/","172.21.82.15")]'
OLD3='[("r7-web-target","/intranet/login","172.21.82.21"),("r7-web-target","/admin/users","172.21.82.203"),("dead.lab","/x","172.21.82.22")]'
NEWA='[("r7-web-target","/","172.21.82.11"),("r7-web-target","/admin","172.21.82.11"),("r7-web-target","/reports","172.21.82.12"),("no-such-host.lab","/","172.21.82.13"),("r7-web-target","/.env","172.21.82.211")]'
NEWB='[("r7-web-target","/finance/q3.csv","172.21.82.31"),("r7-web-target","/admin/config","172.21.82.213"),("ghost.lab","/","172.21.82.32")]'
start r7-pvx-old r7-privoxy12; capture_old r7-pvx-old drive r7-pvx-old
v1=$(docker exec r7-pvx-old privoxy --version 2>&1 | head -1); docker rm -f r7-pvx-old >/dev/null
start r7-pvx-new r7-privoxy13; capture_new r7-pvx-new drive r7-pvx-new
v2=$(docker exec r7-pvx-new privoxy --version 2>&1 | head -1); docker rm -f r7-pvx-new r7-web-target >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (privoxy --no-daemon logs to the console): Request, Crunch and Error lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
