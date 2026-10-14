#!/usr/bin/env bash
# End-to-end check of deploy/recoverbull inside the test container (see the
# Containerfile next to this file). Runs as the sudo user `op` in a checkout
# that already holds target/release/recoverbull. Installs, upgrades, rolls
# back, and checks every refusal the script promises. Tor is installed and
# started but the onion is never contacted: a runner cannot wait for it.
set -u
cd "$(dirname "$0")/../.." || exit 1
R=deploy/recoverbull
AK=4cc8f4d609b717356701c57a03e737e5ac8fe885da8c7163d3de47e01849c635
ES=4a1dl1T8cxcP2pnvxwYWDwm/I68vVd9oWMY0nTOmBSNbonEN/mfBjkPWkSNlxjWacsS2lRVzoGUQ4guZArKf415dLvbObReqWNtzmA4vaB9/feJapmgWAssVI9EbhJFf
failed=0

check() {
  if [[ $2 == "$3" ]]; then
    echo "PASS $1"
  else
    echo "FAIL $1: got '$2' want '$3'"
    failed=1
  fi
}
post() { curl -sS -o /dev/null -w '%{http_code}' -H Content-Type:application/json -X POST "http://127.0.0.1:3001/$1" -d "$2"; }
store() { post store "{\"identifier\":\"$1\",\"authentication_key\":\"$AK\",\"encrypted_secret\":\"$ES\"}"; }
fetch() { post fetch "{\"identifier\":\"$1\",\"authentication_key\":\"$AK\"}"; }
perms() { stat -c '%a %n' / /etc /opt /usr /var /var/lib /etc/systemd/system | tr '\n' ' '; }
touch_torrc() { printf '\n# revision %s\n' "$1" >> deploy/tor/recoverbull.torrc; }

echo "### CLI basics"
$R >/dev/null; check "no arguments shows help" $? 0
$R bogus >/dev/null 2>&1; check "unknown command" $? 2
$R install --bogus </dev/null >/tmp/o 2>&1; check "unknown option" $? 1

echo "### first install"
$R install </dev/null >/tmp/o 2>&1; check "no canary, no terminal: refused" $? 1
grep -q -- "--canary" /tmp/o; check "refusal suggests --canary" $? 0
printf 'test & canary \\ 🐦\n' | script -qec "$R install" /dev/null >/tmp/install.log 2>&1
check "install with the canary typed at the prompt" $? 0 || cat /tmp/install.log
check "canary served verbatim" "$(curl -s http://127.0.0.1:3001/info | grep -o '"canary":"[^"]*"')" '"canary":"test & canary \\ 🐦"'
$R install </dev/null >/tmp/o 2>&1; check "second run is a no-op" $? 0
grep -q 'Already up to date' /tmp/o; check "no-op message" $? 0
$R install --canary x </dev/null >/dev/null 2>&1; check "--canary refused once installed" $? 1
sudo stat -c '%U:%G %a' /var/lib/recoverbull/.env | grep -q 'root:recoverbull 640'; check ".env is root:recoverbull 0640" $? 0
PERMS_BEFORE=$(perms)
ID=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); check "store" "$(store "$ID")" 201

echo "### upgrade"
touch_torrc 1
$R install </dev/null >/tmp/o 2>&1; check "upgrade without a terminal needs --yes" $? 1
grep -q -- '--yes' /tmp/o; check "refusal suggests --yes" $? 0
check "server untouched after the refusal" "$(fetch "$ID")" 200
printf 'n\n' | script -qec "$R install" /dev/null >/tmp/o 2>&1; check "upgrade answered no" $? 1
check "server untouched after no" "$(fetch "$ID")" 200
printf 'y\n' | script -qec "$R install" /dev/null >/tmp/o 2>&1; check "upgrade answered yes" $? 0 || cat /tmp/o
check "data kept after the upgrade" "$(fetch "$ID")" 200
sudo test -e /var/lib/recoverbull/previous-version/database.sqlite3; check "pre-upgrade copy kept" $? 0

echo "### check-config before anything stops"
sudo sed -i 's/^RATE_LIMIT_COOLDOWN=.*/RATE_LIMIT_COOLDOWN=99999/' /var/lib/recoverbull/.env
touch_torrc 2
$R install -y </dev/null >/tmp/o 2>&1; check "upgrade refuses an invalid .env" $? 1
grep -q 'RATE_LIMIT_COOLDOWN' /tmp/o; check "refusal names the bad setting" $? 0
sudo systemctl is-active --quiet recoverbull; check "server untouched by the refusal" $? 0
sudo sed -i 's/^RATE_LIMIT_COOLDOWN=.*/RATE_LIMIT_COOLDOWN=1440/' /var/lib/recoverbull/.env
$R install -y </dev/null >/tmp/o 2>&1; check "upgrade passes once .env is fixed" $? 0 || cat /tmp/o

echo "### rollbacks"
cp deploy/nginx/recoverbull.conf /tmp/nginx.ok; echo 'garbage;' >> deploy/nginx/recoverbull.conf
$R install -y </dev/null >/tmp/o 2>&1; check "broken nginx config fails" $? 1
grep -q 'previous version is running again' /tmp/o; check "broken nginx config rolled back" $? 0 || cat /tmp/o
cp /tmp/nginx.ok deploy/nginx/recoverbull.conf
sudo cmp -s /etc/nginx/conf.d/recoverbull.conf deploy/nginx/recoverbull.conf; check "nginx config restored" $? 0
check "data kept after the nginx rollback" "$(fetch "$ID")" 200

cp -p target/release/recoverbull /tmp/recoverbull.ok
printf '#!/bin/sh\nif [ $# -gt 0 ]; then exec /tmp/recoverbull.ok "$@"; fi\necho boom >&2\nexit 1\n' > target/release/recoverbull
$R install -y </dev/null >/tmp/o 2>&1; check "broken binary fails" $? 1
grep -q 'previous version is running again' /tmp/o; check "broken binary rolled back" $? 0 || cat /tmp/o
cp -p /tmp/recoverbull.ok target/release/recoverbull
sudo cmp -s /opt/recoverbull/bin/recoverbull target/release/recoverbull; check "binary restored" $? 0
check "data kept after the binary rollback" "$(fetch "$ID")" 200
sudo sh -c 'ls -d /var/lib/recoverbull/failed-upgrade.* 2>/dev/null | grep -q .'; check "failed upgrades left their state aside" $? 0
check "filesystem permissions untouched" "$(perms)" "$PERMS_BEFORE"

echo "### refusals"
touch src/main.rs
$R install -y </dev/null >/tmp/o 2>&1; check "stale build refused" $? 1
touch target/release/recoverbull
sudo -u recoverbull ln -s /etc/shadow /var/lib/recoverbull/database.sqlite3-journal
touch_torrc 3
$R install -y </dev/null >/tmp/o 2>&1; check "upgrade refuses a planted symlink" $? 1
sudo systemctl is-active --quiet recoverbull; check "server still running after the refusal" $? 0
sudo rm /var/lib/recoverbull/database.sqlite3-journal
$R install -y </dev/null >/tmp/o 2>&1; check "upgrade works once the symlink is gone" $? 0 || cat /tmp/o
sudo systemctl stop recoverbull
$R install </dev/null >/tmp/o 2>&1; check "no-op install asks before restarting a stopped server" $? 1
grep -q 'resets every attempt budget' /tmp/o; check "it says why" $? 0
$R install -y </dev/null >/tmp/o 2>&1; check "no-op install restarts it with --yes" $? 0 || cat /tmp/o
$R install --database /etc/hostname --onion-keys /var/lib/tor/recoverbull </dev/null >/tmp/o 2>&1; check "import refused on an installed host" $? 1
sudo test -s /var/lib/recoverbull/database.sqlite3; check "live database untouched" $? 0

echo "### backup, logs, status"
sudo /opt/recoverbull/bin/recoverbull backup /var/lib/recoverbull/database.sqlite3 /root/rb-test.sqlite3 >/dev/null; check "documented backup command" $? 0
sudo stat -c '%a' /root/rb-test.sqlite3 | grep -qx 600; check "backup is owner-only" $? 0
sudo /opt/recoverbull/bin/recoverbull backup /var/lib/recoverbull/database.sqlite3 /root/rb-test.sqlite3 >/dev/null 2>&1; check "backup refuses to overwrite" $? 1
sudo /opt/recoverbull/bin/recoverbull check-database /root/rb-test.sqlite3 >/dev/null; check "check-database on the copy" $? 0
$R logs -n 20 </dev/null >/tmp/l 2>&1; check "logs" $? 0
grep -q 'recoverbull\[' /tmp/l; check "logs show the server" $? 0
$R status >/tmp/s 2>&1; check "status while the onion is still publishing" $? 0 || cat /tmp/s
grep -qE '^onion +(starting|ok)' /tmp/s; check "status reports the onion as starting or ok" $? 0
grep -q 'kept copies' /tmp/s; check "status counts kept copies" $? 0

exit $failed
