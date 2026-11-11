#!/usr/bin/env bash
# r7_nsd (round 10, 2026-10-30): NSD, Debian 12 (4.6.1) -> Debian 13 (4.12.0), stderr at verbosity 2.
# Zone transfers (AXFR, IXFR) of lab.example from the two allowed addresses and from refused ones, and a transfer of a
# zone the server does not serve.
# Event runs (old run 3, new run b) use accounts, certificates, zones or paths the sample runs never use, so their
# lines stay held out once addresses and numbers are masked (testbed/r3/build.py), as r6 did for Tinyproxy.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_nsd)
docker build -q --build-arg BASE=debian:12 -t r7-nsd12 "$HERE/docker/r7nsd" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-nsd13 "$HERE/docker/r7nsd" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (query type, zone, client address)
drive(){
  python3 -c "
import ast, sys
for t, z, ip in ast.literal_eval(sys.argv[1]):
    print(ip, t, z)" "$2" | while read -r ip t z; do
    client "$ip" sh -c "dig +tries=1 +time=3 @$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1) $z $t"; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -iE "axfr|ixfr|refused|denied|notify|xfr"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("AXFR","lab.example","172.21.85.10"),("AXFR","lab.example","172.21.85.201"),("IXFR=2026103000","lab.example","172.21.85.11"),("AXFR","other.example","172.21.85.10"),("AXFR","corp.example","172.21.85.202")]'
OLD2='[("AXFR","corp.example","172.21.85.11"),("AXFR","lab.example","172.21.85.203"),("IXFR=2026103000","corp.example","172.21.85.10"),("AXFR","other.example","172.21.85.204")]'
OLD3='[("AXFR","branch.example","172.21.85.10"),("AXFR","branch.example","172.21.85.205"),("IXFR=2026102900","dmz.example","172.21.85.11"),("AXFR","vault.example","172.21.85.206")]'
NEWA='[("AXFR","lab.example","172.21.85.10"),("AXFR","lab.example","172.21.85.211"),("IXFR=2026103000","lab.example","172.21.85.11"),("AXFR","other.example","172.21.85.10"),("AXFR","corp.example","172.21.85.212"),("AXFR","corp.example","172.21.85.11"),("IXFR=2026103000","corp.example","172.21.85.10")]'
NEWB='[("AXFR","dmz.example","172.21.85.10"),("AXFR","dmz.example","172.21.85.215"),("IXFR=2026102800","branch.example","172.21.85.11"),("AXFR","backup.example","172.21.85.216")]'
start r7-nsd-old r7-nsd12; capture_old r7-nsd-old drive r7-nsd-old
v1=$(docker exec r7-nsd-old nsd -v 2>&1 | head -1); docker rm -f r7-nsd-old >/dev/null
start r7-nsd-new r7-nsd13; capture_new r7-nsd-new drive r7-nsd-new
v2=$(docker exec r7-nsd-new nsd -v 2>&1 | head -1); docker rm -f r7-nsd-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (stderr, verbosity 2): transfer and refusal lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
