#!/usr/bin/env bash
# r7_pdnsrec (round 10, 2026-10-30): PowerDNS Recursor, Debian 12 (4.8.8) -> Debian 13 (5.2.x), console with quiet=no
# (every question and answer). Queries for names of an auth-zone (existing and not) from allowed clients and from refused ones.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_pdnsrec)
docker build -q --build-arg BASE=debian:12 -t r7-pdnsrec12 "$HERE/docker/r7pdnsrec" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-pdnsrec13 "$HERE/docker/r7pdnsrec" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (type, name, client address)
drive(){
  python3 -c "
import ast, sys
for t, n, ip in ast.literal_eval(sys.argv[1]):
    print(ip, t, n)" "$2" | while read -r ip t n; do
    client "$ip" sh -c "dig +tries=1 +time=3 @$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1) $n $t"; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "msg=\"(Question|Answer|Dropping)"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("A","www.lab.example","172.21.89.11"),("A","nope.lab.example","172.21.89.11"),("TXT","lab.example","172.21.89.12"),("A","www.lab.example","172.21.89.201"),("MX","lab.example","172.21.89.13")]'
OLD2='[("A","mail.lab.example","172.21.89.14"),("AAAA","www.lab.example","172.21.89.202"),("A","vpn.lab.example","172.21.89.15")]'
OLD3='[("A","admin.lab.example","172.21.89.21"),("ANY","lab.example","172.21.89.203"),("A","www.lab.example","172.21.89.22")]'
NEWA='[("A","www.lab.example","172.21.89.11"),("A","nope.lab.example","172.21.89.11"),("TXT","lab.example","172.21.89.12"),("A","www.lab.example","172.21.89.211"),("MX","lab.example","172.21.89.13")]'
NEWB='[("A","files.lab.example","172.21.89.31"),("A","mail.lab.example","172.21.89.213"),("AAAA","mail.lab.example","172.21.89.32")]'
start r7-pdr-old r7-pdnsrec12; capture_old r7-pdr-old drive r7-pdr-old
v1=$(docker exec r7-pdr-old pdns_recursor --version 2>&1 | head -1); docker rm -f r7-pdr-old >/dev/null
start r7-pdr-new r7-pdnsrec13; capture_new r7-pdr-new drive r7-pdr-new
v2=$(docker exec r7-pdr-new pdns_recursor --version 2>&1 | head -1); docker rm -f r7-pdr-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (console, quiet=no): Question, Answer and Dropping lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
