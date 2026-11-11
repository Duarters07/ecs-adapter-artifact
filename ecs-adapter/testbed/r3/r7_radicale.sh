#!/usr/bin/env bash
# r7_radicale (round 10, 2026-10-30): Radicale, Debian 12 (3.1.8) -> Debian 13 (3.5.3), stderr at level info.
# Basic-auth requests (good password, wrong password, unknown user) from clients at fixed addresses. The event runs
# (old 3, new B) use users and paths the samples never do.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_radicale)
docker build -q --build-arg BASE=debian:12 -t r7-radicale12 "$HERE/docker/r7radicale" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-radicale13 "$HERE/docker/r7radicale" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (user, password, method, path, client address)
drive(){
  python3 -c "
import ast, sys
for u, p, m, path, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p, m, path)" "$2" | while read -r ip u p m path; do
    docker run --rm --cpus 1 --network $NET --ip "$ip" python:3.11-slim python -c "
import urllib.request, base64
h = {'Authorization': 'Basic ' + base64.b64encode(b'$u:$p').decode(), 'Depth': '1', 'User-Agent': 'DAVx5/4.3'}
try: urllib.request.urlopen(urllib.request.Request('http://$1:5232$path', method='$m', headers=h), timeout=5)
except Exception: pass" >/dev/null 2>&1; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "login|Login|authentic"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","Ana2026x","PROPFIND","/ana/","172.21.80.11"),("ana","wrong1","PROPFIND","/ana/","172.21.80.11"),("rui","Rui2026x","GET","/rui/","172.21.80.12"),("ghost","x","PROPFIND","/","172.21.80.201"),("monitor","Mon2026x","PROPFIND","/monitor/","172.21.80.13")]'
OLD2='[("rui","Rui2026x","PROPFIND","/rui/","172.21.80.14"),("rui","123456","PROPFIND","/rui/","172.21.80.14"),("admin","admin","PROPFIND","/","172.21.80.202"),("ana","Ana2026x","GET","/ana/calendar/","172.21.80.15")]'
OLD3='[("scanner","scan","PROPFIND","/","172.21.80.21"),("root","toor","PROPFIND","/","172.21.80.203"),("monitor","Mon2026x","GET","/monitor/","172.21.80.22"),("rui","Natal2024","PROPFIND","/rui/","172.21.80.23")]'
NEWA='[("ana","Ana2026x","PROPFIND","/ana/","172.21.80.11"),("ana","Outono24","PROPFIND","/ana/","172.21.80.11"),("rui","Rui2026x","GET","/rui/","172.21.80.12"),("ghost","x","PROPFIND","/","172.21.80.211"),("monitor","Mon2026x","PROPFIND","/monitor/","172.21.80.13")]'
NEWB='[("deploy","deploy","PROPFIND","/","172.21.80.31"),("ana","Ana2026x","GET","/ana/contacts/","172.21.80.32"),("guest","guest","PROPFIND","/","172.21.80.213"),("rui","Rui2026x","PROPFIND","/rui/tasks/","172.21.80.33")]'
start r7-rad-old r7-radicale12; old_extra_loop r7-rad-old 2 drive r7-rad-old; capture_old r7-rad-old drive r7-rad-old
v1=$(docker exec r7-rad-old python3 -c "import radicale; print(radicale.VERSION)"); docker rm -f r7-rad-old >/dev/null
start r7-rad-new r7-radicale13; capture_new r7-rad-new drive r7-rad-new
v2=$(docker exec r7-rad-new python3 -c "import radicale; print(radicale.VERSION)"); docker rm -f r7-rad-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 radicale %s","new":"Debian 13 radicale %s","collected_by":"docker logs (stderr), level info: login and authentication lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
