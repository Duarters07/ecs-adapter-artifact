#!/usr/bin/env bash
# r7_inspircd (round 10, 2026-10-30): InspIRCd, Debian 12 (3.x) -> Debian 13 (4.x), its log file.
# The same IRC clients as r7_ngircd: right and wrong connect password, OPER with right and wrong password, QUIT.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_inspircd)
docker build -q --build-arg BASE=debian:12 -t r7-inspircd12 "$HERE/docker/r7inspircd" >/dev/null
docker build -q --build-arg BASE=debian:13 -t r7-inspircd13 "$HERE/docker/r7inspircd" >/dev/null
start(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --network $NET $2 >/dev/null; sleep 5; }
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
time.sleep(0.8)
if '$op' != '-': w('OPER $on $op')
w('QUIT :bye')
try: s.recv(65536)
except Exception: pass
s.close()" >/dev/null 2>&1; sleep 0.3
  done; }
log_lines(){ docker exec "$1" cat /var/log/inspircd/ircd.log 2>/dev/null | grep -E "CONNECT:|OPER:|QUIT:|password|Password|oper|denied|Banned|exiting"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","Srv2026x","admin","-","172.21.83.11"),("rui","wrongpw","admin","-","172.21.83.12"),("mon","Srv2026x","admin","Oper2026x","172.21.83.13"),("eve","Srv2026x","admin","guess1","172.21.83.201")]'
OLD2='[("rui","Srv2026x","admin","-","172.21.83.14"),("bot1","letmein","admin","-","172.21.83.202"),("ana","Srv2026x","admin","Oper2026x","172.21.83.15")]'
OLD3='[("scan","123456","admin","-","172.21.83.21"),("evil","Srv2026x","root","toor","172.21.83.203"),("mon","Srv2026x","admin","-","172.21.83.22")]'
NEWA='[("ana","Srv2026x","admin","-","172.21.83.11"),("rui","wrongpw","admin","-","172.21.83.12"),("mon","Srv2026x","admin","Oper2026x","172.21.83.13"),("eve","Srv2026x","admin","guess1","172.21.83.211")]'
NEWB='[("deploy","deploy","admin","-","172.21.83.31"),("ops","Srv2026x","admin","Oper2026x","172.21.83.32"),("mallory","Srv2026x","admin","admin","172.21.83.213")]'
start r7-insp-old r7-inspircd12; capture_old r7-insp-old drive r7-insp-old
v1=$(docker exec r7-insp-old inspircd --version 2>&1 | head -1); docker rm -f r7-insp-old >/dev/null
start r7-insp-new r7-inspircd13; capture_new r7-insp-new drive r7-insp-new
v2=$(docker exec r7-insp-new inspircd --version 2>&1 | head -1); docker rm -f r7-insp-new >/dev/null
printf '{"captured_utc":"%s","old":"Debian 12 %s","new":"Debian 13 %s","collected_by":"/var/log/inspircd/ircd.log, every type except USERINPUT/USEROUTPUT: connect, password, OPER and quit lines"}\n' "$(date -u +%FT%TZ)" "$v1" "$v2" > $OUT/capture.json
wc -l $OUT/*.log
