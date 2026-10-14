#!/usr/bin/env python3
"""Fault-injection checks for recovery paths, without root or real services.

Run: python3 deploy/test/test_rollback.py
Only ownership flags and systemctl are simulated; file copies and moves use temporary fixtures and the actual installer function bodies.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "recoverbull"
FUNCTIONS = SCRIPT.read_text().rsplit('main "$@"', 1)[0]
HARNESS = r'''
DATA_DIR=$1
APP_DIR=$1/app
DB=$1/database.sqlite3
PREVIOUS_DIR=$1/previous
FAIL_STAGE=$2
MANAGED_FILES=("unused:$1/managed:0644")
systemctl() {
  printf '%s\n' "$*" >> "$DATA_DIR/commands"
  case "$FAIL_STAGE:$*" in
    'stop:stop '*|'daemon:daemon-reload'|'server:start recoverbull'|\
    'nginx:reload-or-restart nginx'|'tor:start tor@default') return 1 ;;
  esac
}
wait_for_server() { return 0; }
install() {
  local destination=${!#} args=()
  if [[ $FAIL_STAGE == file && $destination == "$DATA_DIR/managed" ]]; then
    return 1
  fi
  if [[ $FAIL_STAGE == archive && $1 == -d && $destination == "$DATA_DIR"/failed-upgrade.* ]]; then
    return 1
  fi
  while (( $# )); do
    case $1 in
      -o|-g) shift 2 ;;
      *) args+=("$1"); shift ;;
    esac
  done
  command install "${args[@]}"
}
mv() {
  if [[ $FAIL_STAGE == move && $1 == "$DB-wal" ]]; then return 1; fi
  command mv "$@"
}
"$3"
'''


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="recoverbull-rollback-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.previous = self.root / "previous"
        (self.root / "app").mkdir()
        self.previous.mkdir()
        self.db = self.root / "database.sqlite3"
        self.db.write_text("new database")
        Path(str(self.db) + "-wal").write_text("new WAL")
        (self.previous / "database.sqlite3").write_text("old database")
        (self.root / "app/VERSION").write_text("new")
        (self.previous / "VERSION").write_text("old")
        managed = self.root / "managed"
        managed.write_text("new config")
        archived = self.previous / "files" / managed.relative_to("/")
        archived.parent.mkdir(parents=True)
        archived.write_text("old config")

    def run_recovery(self, failure, function="roll_back"):
        result = subprocess.run(
            ["bash", "-c", FUNCTIONS + HARNESS, str(SCRIPT),
             str(self.root), failure, function],
            capture_output=True, text=True, timeout=5,
        )
        # Even a successful recovery exits nonzero: the requested upgrade failed.
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.previous / "database.sqlite3").read_text(), "old database")
        commands = (self.root / "commands").read_text().splitlines()
        return result.stderr, commands

    def test_failed_stop_leaves_all_live_files_untouched(self):
        _, commands = self.run_recovery("stop")
        self.assertEqual(self.db.read_text(), "new database")
        self.assertEqual((self.root / "managed").read_text(), "new config")
        self.assertEqual((self.root / "app/VERSION").read_text(), "new")
        self.assertEqual(commands, ["stop tor@default recoverbull"])

    def test_failed_config_restore_never_starts_services(self):
        _, commands = self.run_recovery("file")
        self.assertEqual(self.db.read_text(), "new database")
        self.assertFalse(any(line.startswith("start ") for line in commands))

    def test_failed_archive_creation_leaves_live_database_untouched(self):
        _, commands = self.run_recovery("archive")
        self.assertEqual(self.db.read_text(), "new database")
        self.assertFalse(any(line.startswith("start ") for line in commands))

    def test_failed_sidecar_move_keeps_both_states_and_services_stopped(self):
        _, commands = self.run_recovery("move")
        archives = list(self.root.glob("failed-upgrade.*"))
        self.assertEqual(len(archives), 1)
        self.assertEqual((archives[0] / "database.sqlite3").read_text(), "new database")
        self.assertEqual(Path(str(self.db) + "-wal").read_text(), "new WAL")
        self.assertEqual(Path(str(self.db) + ".restoring").read_text(), "old database")
        self.assertFalse(any(line.startswith("start ") for line in commands))

    def test_failed_server_start_does_not_expose_the_restored_database(self):
        _, commands = self.run_recovery("server")
        self.assertEqual(self.db.read_text(), "old database")
        self.assertNotIn("reload-or-restart nginx", commands)
        self.assertNotIn("start tor@default", commands)

    def test_failed_proxy_does_not_start_tor_or_claim_full_recovery(self):
        error, commands = self.run_recovery("nginx")
        self.assertEqual(self.db.read_text(), "old database")
        self.assertNotIn("start tor@default", commands)
        self.assertNotIn("previous version is running again", error)

    def test_success_restores_database_and_preserves_failed_state(self):
        error, commands = self.run_recovery("")
        self.assertEqual(self.db.read_text(), "old database")
        self.assertEqual((self.root / "managed").read_text(), "old config")
        archives = list(self.root.glob("failed-upgrade.*"))
        self.assertEqual((archives[0] / "database.sqlite3").read_text(), "new database")
        self.assertEqual((archives[0] / "database.sqlite3-wal").read_text(), "new WAL")
        self.assertIn("previous version is running again", error)
        self.assertEqual(commands[-3:], ["start recoverbull", "reload-or-restart nginx", "start tor@default"])

    def test_abort_reports_server_start_failure_before_starting_tor(self):
        _, commands = self.run_recovery("server", "abort_upgrade")
        self.assertEqual(commands, ["start recoverbull"])
        self.assertEqual(self.db.read_text(), "new database")

    def test_abort_reports_tor_failure_without_claiming_full_recovery(self):
        error, _ = self.run_recovery("tor", "abort_upgrade")
        self.assertNotIn("current version is running again", error)


if __name__ == "__main__":
    unittest.main()
