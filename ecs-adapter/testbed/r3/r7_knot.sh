#!/usr/bin/env bash
# r7_knot (round 10, 2026-10-30): Knot DNS, Debian 12 (3.2.6) -> Debian 13 (3.4.6), stdout at level info.
# Zone transfers (AXFR, IXFR) of lab.example from the two allowed addresses and from refused ones, and a transfer of a
# zone the server does not serve.
# Event runs (old run 3, new run b) use accounts, certificates, zones or paths the sample runs never use, so their
# lines stay held out once addresses and numbers are masked (testbed/r3/build.py), as r6 did for Tinyproxy.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_knot)
docker build -q --build-arg BASE=debian:12 -t r7-knot12 "$HERE/docker/r7knot" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-knot13 "$HERE/docker/r7knot" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (query type, zone, client address)
drive(){
  python3 -c "
import ast, sys
for t, z, ip in ast.literal_eval(sys.argv[1]):
    print(ip, t, z)" "$2" | while read -r ip t z; do
    client "$ip" sh -c "dig +tries=1 +time=3 @$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1) $z $t"; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "AXFR|IXFR|denied|refused|notify|NOTIFY|transfer"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("AXFR","lab.example","172.21.84.10"),("AXFR","lab.example","172.21.84.201"),("IXFR=2026103000","lab.example","172.21.84.11"),("AXFR","other.example","172.21.84.10"),("AXFR","corp.example","172.21.84.202")]'
OLD2='[("AXFR","corp.example","172.21.84.11"),("AXFR","lab.example","172.21.84.203"),("IXFR=2026103000","corp.example","172.21.84.10"),("AXFR","other.example","172.21.84.204")]'
OLD3='[("AXFR","branch.example","172.21.84.10"),("AXFR","branch.example","172.21.84.205"),("IXFR=2026102900","dmz.example","172.21.84.11"),("AXFR","vault.example","172.21.84.206")]'
NEWA='[("AXFR","lab.example","172.21.84.10"),("AXFR","lab.example","172.21.84.211"),("IXFR=2026103000","lab.example","172.21.84.11"),("AXFR","other.example","172.21.84.10"),("AXFR","corp.example","172.21.84.212"),("AXFR","corp.example","172.21.84.11"),("IXFR=2026103000","corp.example","172.21.84.10")]'
NEWB='[("AXFR","dmz.example","172.21.84.10"),("AXFR","dmz.example","172.21.84.215"),("IXFR=2026102800","branch.example","172.21.84.11"),("AXFR","backup.example","172.21.84.216")]'
start r7-knot-old r7-knot12; capture_old r7-knot-old drive r7-knot-old
v1=$(docker exec r7-knot-old knotd --version 2>&1 | head -1); docker rm -f r7-knot-old >/dev/null
start r7-knot-new r7-knot13; capture_new r7-knot-new drive r7-knot-new
v2=$(docker exec r7-knot-new knotd --version 2>&1 | head -1); docker rm -f r7-knot-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (stdout, level info): transfer, refusal and notify lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
