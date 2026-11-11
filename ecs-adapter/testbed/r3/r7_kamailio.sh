#!/usr/bin/env bash
# r7_kamailio (round 10, 2026-10-30): Kamailio 5.8.4 (official ghcr image), a registrar with digest authentication
# (r7kamailio/kamailio.cfg), the vendor-documented switch of the core log engine on the SAME version and config:
# plain stderr lines (old) -> `--log-engine=json:M` (new: one JSON object per line, log prefix and message as fields).
# SIP REGISTER with digest auth (r7kamailio/sipreg.py: right, wrong password, unknown user) from fixed addresses.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_kamailio)
IMG=ghcr.io/kamailio/kamailio:5.8.4-bookworm
D=$(cd "$(dirname "$0")" && pwd)/r7kamailio
setup(){  # <container> [extra kamailio args]
  docker rm -f $1 >/dev/null 2>&1; local c=$1; shift
  docker run -d --cpus 1 --name $c --hostname sip01 --network $NET -v $D/kamailio.cfg:/etc/kamailio/kamailio.cfg:ro \
    --entrypoint kamailio $IMG -DD -E -m 64 -M 8 "$@" >/dev/null; sleep 3; }
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    client "$ip" python3 -c "$(cat $D/sipreg.py)" $1 "$u" "$p"; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -F "REGISTER "| grep -vF "probe_max"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","AnaSip2026","172.21.91.11"),("ana","wrong1","172.21.91.11"),("rui","RuiSip2026","172.21.91.12"),("ghost","x","172.21.91.201"),("monitor","MonSip2026","172.21.91.13")]'
OLD2='[("rui","123456","172.21.91.14"),("admin","admin","172.21.91.202"),("ana","AnaSip2026","172.21.91.15")]'
OLD3='[("100","1234","172.21.91.203"),("monitor","MonSip2026","172.21.91.21"),("rui","Natal2024","172.21.91.22")]'
NEWA='[("ana","AnaSip2026","172.21.91.11"),("ana","Outono24","172.21.91.11"),("rui","RuiSip2026","172.21.91.12"),("ghost","x","172.21.91.211"),("monitor","MonSip2026","172.21.91.13")]'
NEWB='[("1001","1001","172.21.91.31"),("ana","AnaSip2026","172.21.91.32"),("guest","guest","172.21.91.213")]'
setup r7-kam-old; capture_old r7-kam-old drive r7-kam-old; docker rm -f r7-kam-old >/dev/null
setup r7-kam-new --log-engine=json:M; capture_new r7-kam-new drive r7-kam-new; docker rm -f r7-kam-new >/dev/null
printf '{"captured_utc":"%s","old":"Kamailio 5.8.4, stderr text log","new":"Kamailio 5.8.4, --log-engine=json:M","collected_by":"docker logs (stderr): the registrar script log lines (challenge, accepted, auth failed)"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
