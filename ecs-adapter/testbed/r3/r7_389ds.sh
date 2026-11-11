#!/usr/bin/env bash
# r7_389ds (round 10, 2026-10-30): 389 Directory Server 2.5.0 -> 3.1.2 (official 389ds/dirsrv:2.4 and :3.1 images; the
# :2.4 tag ships 2.5.0. The candidate list pinned 2.3.1: the official :2.3 image (2.3.2) cannot start, its dscontainer
# lacks the python `cryptography` module, so the oldest working 2.x image is used).
# The access log, the one that records every client's binds: 2.5.0 writes its text format (no other is offered);
# 3.1.2 adds the JSON access log (`nsslapd-accesslog-log-format: json`, 389-ds-base 3.1.2 release notes and the
# accesslog-json design page), which the new capture enables. Buffering off so lines land at once.
# LDAP simple binds (right, wrong password, unknown entry), each followed by a whoami, from fixed addresses; only the
# lines of client connections are kept (the setup's own LDAPI sessions are dropped).
# Event runs (old run 3, new run b) use accounts, certificates, zones or paths the sample runs never use, so their
# lines stay held out once addresses and numbers are masked (testbed/r3/build.py), as r6 did for Tinyproxy.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_389ds)
setup(){  # <container> <tag> <text|json>
  docker rm -f $1 >/dev/null 2>&1
  docker run -d --cpus 1 --name $1 --hostname ldap01 --network $NET -e DS_DM_PASSWORD='DmSecret2026' \
    -e DS_SUFFIX_NAME='dc=lab,dc=example' 389ds/dirsrv:$2 >/dev/null
  local k; for k in $(seq 1 60); do docker exec $1 dsconf localhost config get nsslapd-port >/dev/null 2>&1 && break; sleep 3; done
  # The container may restart the server once after its first setup: retry until the backend exists.
  for k in $(seq 1 20); do docker exec $1 dsconf localhost backend create --suffix dc=lab,dc=example --be-name userroot \
    --create-suffix --create-entries >/dev/null 2>&1; docker exec $1 dsconf localhost backend suffix list 2>/dev/null | \
    grep -q 'dc=lab,dc=example' && break; sleep 3; done
  local u n=1000; for u in ana:AnaLdap2026 rui:RuiLdap2026 monitor:MonLdap2026 ops:OpsLdap2026 backup:BackupLdap2026 \
    carla:CarlaLdap2026 dario:DarioLdap2026; do n=$((n+1))
    docker exec $1 dsidm -b dc=lab,dc=example localhost user create --uid ${u%%:*} --cn ${u%%:*} --displayName ${u%%:*} \
      --uidNumber $n --gidNumber $n --homeDirectory /home/${u%%:*} >/dev/null 2>&1
    docker exec $1 dsidm -b dc=lab,dc=example localhost account reset_password uid=${u%%:*},ou=people,dc=lab,dc=example ${u##*:} >/dev/null 2>&1
  done
  docker exec $1 dsidm -b dc=lab,dc=example localhost user list 2>&1 | tr '\n' ' '; echo
  docker exec $1 dsconf localhost config replace nsslapd-accesslog-logbuffering=off >/dev/null
  [ "$3" = json ] && docker exec $1 dsconf localhost config replace nsslapd-accesslog-log-format=json >/dev/null
  docker exec $1 dsconf localhost config get nsslapd-accesslog-log-format 2>&1 | tail -1; sleep 2; }
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    client "$ip" ldapwhoami -x -H ldap://$1:3389 -D "uid=$u,ou=people,dc=lab,dc=example" -w "$p"; sleep 0.3
  done; }
log_lines(){ docker exec $1 cat /data/logs/access | python3 -c '
import json, re, sys
lines, mine = sys.stdin.read().splitlines(), set()
def conn(l):
    if l.startswith("{"):
        try:
            d = json.loads(l)
        except ValueError:
            return None, False
        return d.get("conn_id"), str(d.get("client_ip", d.get("source_ip", ""))).startswith("172.21.91.")
    m = re.search(r" conn=(\d+) ", l)
    return (int(m.group(1)) if m else None), "connection from 172.21.91." in l
for l in lines:
    c, client = conn(l)
    if client:
        mine.add(c)
for l in lines:
    c, _ = conn(l)
    if c in mine:
        print(l)'; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","AnaLdap2026","172.21.91.11"),("ana","wrong1","172.21.91.11"),("rui","RuiLdap2026","172.21.91.12"),("ghost","x","172.21.91.201"),("monitor","MonLdap2026","172.21.91.13")]'
OLD2='[("rui","123456","172.21.91.14"),("admin","admin","172.21.91.202"),("ana","AnaLdap2026","172.21.91.15")]'
OLD3='[("ops","OpsLdap2026","172.21.91.203"),("backup","Backup01","172.21.91.21"),("svcprint","x","172.21.91.22"),("carla","CarlaLdap2026","172.21.91.23"),("intern","intern","172.21.91.204")]'
NEWA='[("ana","AnaLdap2026","172.21.91.11"),("ana","Outono24","172.21.91.11"),("rui","RuiLdap2026","172.21.91.12"),("ghost","x","172.21.91.211"),("monitor","MonLdap2026","172.21.91.13")]'
NEWB='[("dario","DarioLdap2026","172.21.91.31"),("carla","Senha123","172.21.91.32"),("svcscan","scan","172.21.91.213"),("backup","BackupLdap2026","172.21.91.33"),("trainee","trainee","172.21.91.214")]'
setup r7-ds-old 2.4 text; capture_old r7-ds-old drive r7-ds-old; docker rm -f r7-ds-old >/dev/null
setup r7-ds-new 3.1 json; capture_new r7-ds-new drive r7-ds-new; docker rm -f r7-ds-new >/dev/null
printf '{"captured_utc":"%s","old":"389-DS 2.5.0 (image tag 2.4), access log (text)","new":"389-DS 3.1.2, access log JSON (nsslapd-accesslog-log-format=json)","collected_by":"/data/logs/access, lines of client connections"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
