#!/usr/bin/env bash
# r7_mumble (round 10, 2026-10-30): Mumble server 1.3.4 (Debian bookworm, murmurd) -> 1.5.735 (Debian trixie,
# mumble-server), same ini (r7mumble/Dockerfile: a server password), log on stderr (foreground). Logins from fixed
# addresses through the control channel (r7mumble/mumclient.py: TLS, Version, Authenticate; held two seconds): the
# server password (success), a wrong one, and the SuperUser account with a wrong password. Kept: the per-session lines
# (`=> <session:user(id)>`).
# Event runs (old run 3, new run b) use accounts, certificates, zones or paths the sample runs never use, so their
# lines stay held out once addresses and numbers are masked (testbed/r3/build.py), as r6 did for Tinyproxy.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_mumble)
D=$(cd "$(dirname "$0")" && pwd)/r7mumble
setup(){ docker rm -f $1 >/dev/null 2>&1; docker run -d --cpus 1 --name $1 --hostname voice01 --network $NET r7-mumble:$2 >/dev/null; sleep 6; }
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    client "$ip" python3 -c "$(cat $D/mumclient.py)" $1 "$u" "$p"; sleep 0.5
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -F "=> <"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
P=LabVoice2026
OLD1="[('ana','$P','172.21.91.11'),('ana','wrong1','172.21.91.11'),('rui','$P','172.21.91.12'),('SuperUser','admin','172.21.91.201'),('monitor','$P','172.21.91.13')]"
OLD2="[('rui','123456','172.21.91.14'),('guest','guest','172.21.91.202'),('ana','$P','172.21.91.15')]"
OLD3="[('eva','$P','172.21.91.203'),('frank','errada','172.21.91.21'),('gil','$P','172.21.91.22'),('helena','x','172.21.91.204')]"
NEWA="[('ana','$P','172.21.91.11'),('ana','Outono24','172.21.91.11'),('rui','$P','172.21.91.12'),('SuperUser','admin','172.21.91.211'),('monitor','$P','172.21.91.13')]"
NEWB="[('ines','$P','172.21.91.31'),('joao','1234','172.21.91.32'),('kika','$P','172.21.91.213'),('luis','pass','172.21.91.33')]"
setup r7-mu-old 1.3; capture_old r7-mu-old drive r7-mu-old; docker rm -f r7-mu-old >/dev/null
setup r7-mu-new 1.5; capture_new r7-mu-new drive r7-mu-new; docker rm -f r7-mu-new >/dev/null
printf '{"captured_utc":"%s","old":"Mumble server 1.3.4 (Debian bookworm)","new":"Mumble server 1.5.735 (Debian trixie)","collected_by":"docker logs (stderr, foreground): per-session lines"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
