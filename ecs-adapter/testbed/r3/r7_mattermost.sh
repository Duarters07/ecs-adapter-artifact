#!/usr/bin/env bash
# r7_mattermost (round 10, 2026-10-30): Mattermost Team Edition 10.5.2 (official image), the vendor-documented switch
# of its console log on the SAME version: JSON (the default, old) -> plain text (new, LogSettings.ConsoleJson=false).
# Console level DEBUG: at INFO only a wrong password is logged; DEBUG adds the 401 reason and the request line with
# its status, so success and unknown users are visible. Password logins (right, wrong, unknown user) from clients at fixed addresses through the API.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_mattermost)
IMG=mattermost/mattermost-team-edition:10.5.2
setup(){  # <container> <json: true|false>
  docker rm -f $1 $1-db >/dev/null 2>&1
  docker run -d --cpus 1 --name $1-db --network $NET -e POSTGRES_USER=mm -e POSTGRES_PASSWORD=mm -e POSTGRES_DB=mm postgres:15 >/dev/null; sleep 8
  docker run -d --cpus 2 --name $1 --network $NET -e MM_SQLSETTINGS_DRIVERNAME=postgres \
    -e MM_SQLSETTINGS_DATASOURCE="postgres://mm:mm@$1-db:5432/mm?sslmode=disable" -e MM_SERVICESETTINGS_SITEURL=http://$1:8065 \
    -e MM_SERVICESETTINGS_ENABLELOCALMODE=true -e MM_LOGSETTINGS_CONSOLELEVEL=DEBUG -e MM_LOGSETTINGS_ENABLEDIAGNOSTICS=false -e MM_LOGSETTINGS_CONSOLEJSON=$2 \
    -e MM_LOGSETTINGS_ENABLECONSOLE=true $IMG >/dev/null
  local k; for k in $(seq 1 60); do docker exec $1 mmctl --local system status >/dev/null 2>&1 && break; sleep 3; done
  for u in ana:Ana2026x! rui:Rui2026x! monitor:Mon2026x!; do
    docker exec $1 mmctl --local user create --email ${u%%:*}@lab.example --username ${u%%:*} --password ${u##*:} >/dev/null 2>&1; done; sleep 2; }
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    client "$ip" curl -s -m 8 -XPOST -H 'Content-Type: application/json' -H 'User-Agent: Mattermost-Desktop/5.10' \
      -d "{\"login_id\":\"$u\",\"password\":\"$p\"}" http://$1:8065/api/v4/users/login; sleep 0.5
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -F "/api/v4/users/login"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","Ana2026x!","172.21.91.11"),("ana","wrong1","172.21.91.11"),("rui","Rui2026x!","172.21.91.12"),("ghost","x","172.21.91.201"),("monitor","Mon2026x!","172.21.91.13")]'
OLD2='[("rui","123456","172.21.91.14"),("admin","admin","172.21.91.202"),("ana","Ana2026x!","172.21.91.15")]'
OLD3='[("root","toor","172.21.91.203"),("monitor","Mon2026x!","172.21.91.21"),("rui","Natal2024","172.21.91.22")]'
NEWA='[("ana","Ana2026x!","172.21.91.11"),("ana","Outono24","172.21.91.11"),("rui","Rui2026x!","172.21.91.12"),("ghost","x","172.21.91.211"),("monitor","Mon2026x!","172.21.91.13")]'
NEWB='[("deploy","deploy","172.21.91.31"),("ana","Ana2026x!","172.21.91.32"),("guest","guest","172.21.91.213")]'
setup r7-mm-old true; capture_old r7-mm-old drive r7-mm-old; docker rm -f r7-mm-old r7-mm-old-db >/dev/null
setup r7-mm-new false; capture_new r7-mm-new drive r7-mm-new; docker rm -f r7-mm-new r7-mm-new-db >/dev/null
printf '{"captured_utc":"%s","old":"Mattermost 10.5.2, console log JSON (default)","new":"Mattermost 10.5.2, console log plain (ConsoleJson=false)","collected_by":"docker logs (console, level DEBUG): every line of a /api/v4/users/login request (the auth result with the client address, the request with its status)"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
