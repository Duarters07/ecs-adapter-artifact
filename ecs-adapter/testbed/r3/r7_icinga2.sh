#!/usr/bin/env bash
# r7_icinga2 (round 10, 2026-10-30): Icinga 2 2.13.6 (Debian bookworm) -> 2.14.6 (Debian trixie), same config
# (r7icinga2/Dockerfile: `icinga2 api setup`, three ApiUsers), main log /var/log/icinga2/icinga2.log.
# REST API requests with HTTP basic auth (right, wrong password, unknown user) from fixed addresses; kept: the
# ApiListener/HttpServerConnection lines of those clients (connection, request with user and status, disconnect).
# Event runs (old run 3, new run b) use accounts, certificates, zones or paths the sample runs never use, so their
# lines stay held out once addresses and numbers are masked (testbed/r3/build.py), as r6 did for Tinyproxy.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_icinga2)
D=$(cd "$(dirname "$0")" && pwd)/r7icinga2
docker build -q -t r7-icinga2:2.13 --build-arg DIST=bookworm "$D" >/dev/null
docker build -q -t r7-icinga2:2.14 --build-arg DIST=trixie "$D" >/dev/null
setup(){  # <container> <version>
  docker rm -f $1 >/dev/null 2>&1
  docker run -d --cpus 1 --name $1 --hostname mon01 --network $NET r7-icinga2:$2 >/dev/null; sleep 15; }
UA=("Icinga Web 2" "python-requests/2.31.0" "curl/8.14.1")
drive(){
  python3 -c "
import ast, sys
for t in ast.literal_eval(sys.argv[1]):
    u, p, ip = t[:3]
    print(ip, u, p, t[3] if len(t) > 3 else '-')" "$2" | while read -r ip u p path; do
    local ua="${UA[$(( ${ip##*.} % 3 ))]}"
    if [ "$path" = - ]; then path=/v1/status/IcingaApplication; [ "${ip##*.}" -gt 13 ] && path=/v1/objects/hosts
    else ua="Ansible-icinga2/1.4"; fi
    client "$ip" curl -sk -m 10 -A "$ua" -u "$u:$p" https://$1:5665$path; sleep 0.5
  done; }
log_lines(){ docker exec $1 cat /var/log/icinga2/icinga2.log | grep -F "172.21.91."; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","AnaApi2026","172.21.91.11"),("ana","wrong1","172.21.91.11"),("rui","RuiApi2026","172.21.91.12"),("ghost","x","172.21.91.201"),("monitor","MonApi2026","172.21.91.13")]'
OLD2='[("rui","123456","172.21.91.14"),("admin","admin","172.21.91.202"),("ana","AnaApi2026","172.21.91.15")]'
OLD3='[("ops","OpsApi2026","172.21.91.203","/v1/objects/services"),("backup","Backup01","172.21.91.21","/v1/objects/services"),("svcprint","x","172.21.91.22","/v1/types"),("backup","BackupApi2026","172.21.91.23","/v1/types")]'
NEWA='[("ana","AnaApi2026","172.21.91.11"),("ana","Outono24","172.21.91.11"),("rui","RuiApi2026","172.21.91.12"),("ghost","x","172.21.91.211"),("monitor","MonApi2026","172.21.91.13")]'
NEWB='[("backup","BackupApi2026","172.21.91.31","/v1/objects/services"),("ops","Senha123","172.21.91.32","/v1/objects/services"),("svcscan","scan","172.21.91.213","/v1/types"),("ops","OpsApi2026","172.21.91.33","/v1/types")]'
setup r7-ic-old 2.13; capture_old r7-ic-old drive r7-ic-old; docker rm -f r7-ic-old >/dev/null
setup r7-ic-new 2.14; capture_new r7-ic-new drive r7-ic-new; docker rm -f r7-ic-new >/dev/null
printf '{"captured_utc":"%s","old":"Icinga 2 2.13.6 (Debian bookworm)","new":"Icinga 2 2.14.6 (Debian trixie)","collected_by":"/var/log/icinga2/icinga2.log: API client lines"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
