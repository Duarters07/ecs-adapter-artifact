#!/usr/bin/env bash
# r7_synapse (round 10, 2026-10-30): Matrix Synapse 1.120.2 (official image), the vendor-documented switch of its log
# output on the SAME version: the default text formatter (old) -> synapse.logging.TerseJsonFormatter (new), console.
# Password logins (right, wrong, unknown user) from clients at fixed addresses through the client API.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_synapse)
IMG=matrixdotorg/synapse:v1.120.2
setup(){  # <container> <formatter: text|json>
  docker rm -f $1 >/dev/null 2>&1; docker volume rm -f $1-data >/dev/null 2>&1; docker volume create $1-data >/dev/null
  docker run --rm -v $1-data:/data -e SYNAPSE_SERVER_NAME=lab.example -e SYNAPSE_REPORT_STATS=no $IMG generate >/dev/null 2>&1
  local fmt='    format: "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s"'
  [ $2 = json ] && fmt='    class: synapse.logging.TerseJsonFormatter'
  printf 'version: 1\nformatters:\n  main:\n%s\nhandlers:\n  console:\n    class: logging.StreamHandler\n    formatter: main\nloggers:\n  synapse.storage.SQL:\n    level: INFO\nroot:\n  level: INFO\n  handlers: [console]\ndisable_existing_loggers: false\n' "$fmt" \
    | docker run --rm -i -v $1-data:/data --entrypoint sh $IMG -c 'cat > /data/lab.example.log.config'
  docker run -d --cpus 2 --name $1 --network $NET -v $1-data:/data $IMG >/dev/null
  local u k
  for u in ana:Ana2026x rui:Rui2026x monitor:Mon2026x; do
    for k in $(seq 1 30); do
      docker exec $1 register_new_matrix_user -u ${u%%:*} -p ${u##*:} --no-admin -c /data/homeserver.yaml http://localhost:8008 >/dev/null 2>&1 && break
      sleep 2; done; done; sleep 2; }
# (user, password, client address)
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    client "$ip" curl -s -m 8 -XPOST -H 'Content-Type: application/json' -H 'User-Agent: Element/1.11' \
      -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"$u\"},\"password\":\"$p\"}" \
      http://$1:8008/_matrix/client/v3/login; sleep 0.5
  done; }
log_lines(){ docker logs "$1" 2>&1 | grep -E "Got login request|Logging in user|Failed password login|Attempted to login|Processed request.*POST /_matrix/client/v3/login"; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","Ana2026x","172.21.90.11"),("ana","wrong1","172.21.90.11"),("rui","Rui2026x","172.21.90.12"),("ghost","x","172.21.90.201"),("monitor","Mon2026x","172.21.90.13")]'
OLD2='[("rui","123456","172.21.90.14"),("admin","admin","172.21.90.202"),("ana","Ana2026x","172.21.90.15")]'
OLD3='[("root","toor","172.21.90.203"),("monitor","Mon2026x","172.21.90.21"),("rui","Natal2024","172.21.90.22")]'
NEWA='[("ana","Ana2026x","172.21.90.11"),("ana","Outono24","172.21.90.11"),("rui","Rui2026x","172.21.90.12"),("ghost","x","172.21.90.211"),("monitor","Mon2026x","172.21.90.13")]'
NEWB='[("deploy","deploy","172.21.90.31"),("ana","Ana2026x","172.21.90.32"),("guest","guest","172.21.90.213")]'
setup r7-syn-old text; capture_old r7-syn-old drive r7-syn-old; docker rm -f r7-syn-old >/dev/null; docker volume rm -f r7-syn-old-data >/dev/null
setup r7-syn-new json; capture_new r7-syn-new drive r7-syn-new; docker rm -f r7-syn-new >/dev/null; docker volume rm -f r7-syn-new-data >/dev/null
printf '{"captured_utc":"%s","old":"Synapse 1.120.2, default text formatter (precise)","new":"Synapse 1.120.2, synapse.logging.TerseJsonFormatter","collected_by":"docker logs (console): login handler and access lines for /login"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
