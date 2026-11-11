#!/usr/bin/env bash
# r7_ngircd (round 10, 2026-10-30): ngIRCd, Debian 12 (26.1) -> Debian 13 (27), console log.
# IRC clients at fixed addresses: right and wrong server password, OPER with right and wrong password, then QUIT.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_ngircd)
docker build -q --build-arg BASE=debian:12 -t r7-ngircd12 "$HERE/docker/r7ngircd" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-ngircd13 "$HERE/docker/r7ngircd" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 4; }
# (nick, server password, oper name, oper password or "-", client address)
drive(){
  python3 -c "
import ast, sys
for n, sp, on, op, ip in ast.literal_eval(sys.argv[1]):
    print(ip, n, sp, on, op)" "$2" | while read -r ip n sp on op; do
    docker run --rm --cpus 1 --network $NET --ip "$ip" python:3.11-slim python -c "
import socket, time
s = socket.create_connection(('$1', 6667), timeout=5)
def w(x): s.sendall((x + '\r\n').encode()); time.sleep(0.3)
w('PASS $sp'); w('NICK $n'); w('USER $n 0 * :$n')
time.sleep(0.6)
if '$op' != '-': w('OPER $on $op')
w('QUIT :bye')
try: s.recv(65536)
except Exception: pass
s.close()" >/dev/null 2>&1; sleep 0.3
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -vE "^\[[0-9]+:[0-9] *[0-9.]+\] (Using|Reading|Not|Created|Running|Max|Now|Configuration|Initializing|Listening|Server|IO subsystem|Not running|ngircd)" | grep -E "connection|Connection|password|Password|OPER|oper|Accepted|closed|registered|refused"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","Srv2026x","admin","-","172.21.81.11"),("rui","wrongpw","admin","-","172.21.81.12"),("mon","Srv2026x","admin","Oper2026x","172.21.81.13"),("eve","Srv2026x","admin","guess1","172.21.81.201")]'
OLD2='[("rui","Srv2026x","admin","-","172.21.81.14"),("bot1","letmein","admin","-","172.21.81.202"),("ana","Srv2026x","admin","Oper2026x","172.21.81.15")]'
OLD3='[("scan","123456","admin","-","172.21.81.21"),("evil","Srv2026x","root","toor","172.21.81.203"),("mon","Srv2026x","admin","-","172.21.81.22")]'
NEWA='[("ana","Srv2026x","admin","-","172.21.81.11"),("rui","wrongpw","admin","-","172.21.81.12"),("mon","Srv2026x","admin","Oper2026x","172.21.81.13"),("eve","Srv2026x","admin","guess1","172.21.81.211")]'
NEWB='[("deploy","deploy","admin","-","172.21.81.31"),("ops","Srv2026x","admin","Oper2026x","172.21.81.32"),("mallory","Srv2026x","admin","admin","172.21.81.213")]'
start r7-irc-old r7-ngircd12; capture_old r7-irc-old drive r7-irc-old
v1=$(docker exec r7-irc-old ngircd --version 2>&1 | head -1); docker rm -f r7-irc-old >/dev/null
start r7-irc-new r7-ngircd13; capture_new r7-irc-new drive r7-irc-new
v2=$(docker exec r7-irc-new ngircd --version 2>&1 | head -1); docker rm -f r7-irc-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"docker logs (console, -n): connection, password, OPER and closing lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
