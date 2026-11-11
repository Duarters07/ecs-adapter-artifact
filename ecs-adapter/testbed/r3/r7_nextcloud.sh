#!/usr/bin/env bash
# r7_nextcloud (round 10, 2026-10-30): Nextcloud 30.0.17 (official image, SQLite), admin_audit app, the vendor-documented
# switch of its audit log on the SAME version: `log_type_audit=file` (old: one JSON object per line in audit.log) ->
# `log_type_audit=syslog` (new: rsyslog's line, header then the same JSON). Log level info (the audit app logs at
# info); brute-force protection off so repeated failures are not delayed. WebDAV logins (right, wrong, unknown user)
# from clients at fixed addresses.
. "$(dirname "$0")/r7_common.sh"
OUT=$(cap r7_nextcloud)
IMG=nextcloud:30-apache
setup(){  # <container> <file|syslog>
  docker rm -f $1 >/dev/null 2>&1
  docker run -d --cpus 2 --name $1 --hostname nc01 --network $NET -e SQLITE_DATABASE=nc -e NEXTCLOUD_ADMIN_USER=admin \
    -e NEXTCLOUD_ADMIN_PASSWORD='AdminSecret2026!' -e NEXTCLOUD_TRUSTED_DOMAINS=$1 $IMG >/dev/null
  local k; for k in $(seq 1 60); do docker exec -u www-data $1 php occ status 2>/dev/null | grep -q 'installed: true' && break; sleep 5; done
  docker exec $1 sh -c 'apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsyslog >/dev/null 2>&1
    sed -i "/imklog/s/^/#/" /etc/rsyslog.conf; rsyslogd'
  local O="docker exec -u www-data $1 php occ"
  $O app:enable admin_audit >/dev/null; $O config:system:set loglevel --value=1 --type=integer >/dev/null
  $O config:system:set auth.bruteforce.protection.enabled --value=false --type=boolean >/dev/null
  $O config:system:set logfile_audit --value=/var/www/html/data/audit.log >/dev/null
  $O config:system:set syslog_tag_audit --value=Nextcloud-audit >/dev/null
  $O config:system:set log_type_audit --value=$2 >/dev/null
  for u in ana:AnaSecret2026! rui:RuiSecret2026! monitor:MonSecret2026!; do
    docker exec -u www-data -e OC_PASS="${u##*:}" $1 php occ user:add --password-from-env ${u%%:*} >/dev/null 2>&1; done; sleep 2; }
drive(){
  python3 -c "
import ast, sys
for u, p, ip in ast.literal_eval(sys.argv[1]):
    print(ip, u, p)" "$2" | while read -r ip u p; do
    client "$ip" curl -s -m 15 -u "$u:$p" -A 'Mozilla/5.0 (Windows NT 10.0) mirall/3.14.1' -X PROPFIND http://$1/remote.php/dav/files/$u/; sleep 0.5
  done; }
log_lines(){ docker exec $1 sh -c 'cat /var/www/html/data/audit.log /var/log/syslog 2>/dev/null' | grep -F '"message":"Login'; }
mark(){ log_lines $1 | wc -l; }
slice(){ log_lines $1 | sed -n "$(($2+1)),$3p"; }
OLD1='[("ana","AnaSecret2026!","172.21.91.11"),("ana","wrong1","172.21.91.11"),("rui","RuiSecret2026!","172.21.91.12"),("ghost","x","172.21.91.201"),("monitor","MonSecret2026!","172.21.91.13")]'
OLD2='[("rui","123456","172.21.91.14"),("admin","admin","172.21.91.202"),("ana","AnaSecret2026!","172.21.91.15")]'
OLD3='[("root","toor","172.21.91.203"),("monitor","MonSecret2026!","172.21.91.21"),("rui","Natal2024","172.21.91.22")]'
NEWA='[("ana","AnaSecret2026!","172.21.91.11"),("ana","Outono24","172.21.91.11"),("rui","RuiSecret2026!","172.21.91.12"),("ghost","x","172.21.91.211"),("monitor","MonSecret2026!","172.21.91.13")]'
NEWB='[("deploy","deploy","172.21.91.31"),("ana","AnaSecret2026!","172.21.91.32"),("guest","guest","172.21.91.213")]'
setup r7-nc-old file; capture_old r7-nc-old drive r7-nc-old; docker rm -f r7-nc-old >/dev/null
setup r7-nc-new syslog; capture_new r7-nc-new drive r7-nc-new; docker rm -f r7-nc-new >/dev/null
printf '{"captured_utc":"%s","old":"Nextcloud 30.0.17 admin_audit, log_type_audit=file (JSON lines)","new":"Nextcloud 30.0.17 admin_audit, log_type_audit=syslog (rsyslog line + JSON)","collected_by":"audit.log / /var/log/syslog: Login attempt/successful/failed lines"}\n' "$(date -u +%FT%TZ)" > $OUT/capture.json
wc -l $OUT/*.log
