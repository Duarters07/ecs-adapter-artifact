#!/usr/bin/env bash
# r7_unbound (round 10, 2026-10-30): Unbound, Debian 12 (1.17.1) -> Debian 13 (1.26.x), stderr with log-queries
# and log-replies. Queries for names of the local zone (existing and not) from allowed clients and from refused ones.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_unbound)
docker build -q --build-arg BASE=debian:12 -t r7-unbound12 "$HERE/docker/r7unbound" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-unbound13 "$HERE/docker/r7unbound" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (type, name, client address)
drive(){
  python3 -c "
import ast, sys
for t, n, ip in ast.literal_eval(sys.argv[1]):
    print(ip, t, n)" "$2" | while read -r ip t n; do
    client "$ip" sh -c "dig +tries=1 +time=3 @$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1) $n $t"; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "info: (172|[0-9]+\.)|query:|reply:|refused|REFUSED"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("A","www.lab.example","172.21.86.11"),("A","nope.lab.example","172.21.86.11"),("TXT","lab.example","172.21.86.12"),("A","www.lab.example","172.21.86.201"),("MX","lab.example","172.21.86.13")]'
OLD2='[("A","mail.lab.example","172.21.86.14"),("AAAA","www.lab.example","172.21.86.202"),("A","vpn.lab.example","172.21.86.15")]'
OLD3='[("A","admin.lab.example","172.21.86.21"),("ANY","lab.example","172.21.86.203"),("A","www.lab.example","172.21.86.22")]'
NEWA='[("A","www.lab.example","172.21.86.11"),("A","nope.lab.example","172.21.86.11"),("TXT","lab.example","172.21.86.12"),("A","www.lab.example","172.21.86.211"),("MX","lab.example","172.21.86.13")]'
NEWB='[("A","files.lab.example","172.21.86.31"),("A","mail.lab.example","172.21.86.213"),("AAAA","mail.lab.example","172.21.86.32")]'
start r7-ub-old r7-unbound12; capture_old r7-ub-old drive r7-ub-old
v1=$(docker exec r7-ub-old unbound -V 2>&1 | head -1); docker rm -f r7-ub-old >/dev/null
start r7-ub-new r7-unbound13; capture_new r7-ub-new drive r7-ub-new
v2=$(docker exec r7-ub-new unbound -V 2>&1 | head -1); docker rm -f r7-ub-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (stderr, verbosity 1, log-queries, log-replies): query and reply lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
