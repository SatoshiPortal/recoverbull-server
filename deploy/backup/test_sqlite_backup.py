#!/usr/bin/env python3
"""Deterministic CI oracle for the SQLite backup procedure."""

import importlib.util
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCHEMA = ROOT.parent.parent / "migrations" / "0001_schema" / "up.sql"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("sqlite_backup", ROOT / "sqlite_backup.py")
assert SPEC and SPEC.loader
backup_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup_tool)


def run_cli(*arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "sqlite_backup.py"), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=10,
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert "encrypted" not in result.stdout + result.stderr
    return result


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sqlite-backup-test-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        source = root / "source ?#.sqlite3"
        backup = root / "backup.sqlite3"
        restored = root / "restored.sqlite3"
        naive = root / "naive.sqlite3"
        permissive = root / "permissive"
        with sqlite3.connect(source) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.executescript(SCHEMA.read_text(encoding="utf-8"))
            connection.executescript(
                "CREATE TABLE __diesel_schema_migrations (version TEXT PRIMARY KEY);"
                "INSERT INTO __diesel_schema_migrations VALUES ('00000000000000');"
            )
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("INSERT INTO secret VALUES ('wal-row', '2026-08-25T00:00:00Z', 'ciphertext')")
            connection.commit()
        assert Path(f"{source}-wal").exists(), "fixture transaction must remain in WAL"

        shutil.copyfile(source, naive)
        with sqlite3.connect(naive) as connection:
            assert connection.execute("SELECT id FROM secret").fetchone() is None

        run_cli("backup", str(source), str(backup))
        run_cli("verify", str(backup))
        with sqlite3.connect(backup) as connection:
            assert connection.execute("SELECT encrypted_secret FROM secret WHERE id='wal-row'").fetchone() == ("ciphertext",)
        assert oct(backup.stat().st_mode & 0o777) == "0o600"

        replace_destination = root / "replace.sqlite3"
        with sqlite3.connect(replace_destination) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.executescript(SCHEMA.read_text(encoding="utf-8"))
            connection.executescript(
                "CREATE TABLE __diesel_schema_migrations (version TEXT PRIMARY KEY);"
                "INSERT INTO __diesel_schema_migrations VALUES ('00000000000000');"
                "INSERT INTO secret VALUES ('old-row', '2026-08-25T00:00:00Z', 'old-ciphertext');"
            )
            connection.commit()
        replace_wal = Path(f"{replace_destination}-wal")
        assert replace_wal.exists(), "destination fixture transaction must remain in WAL"
        replace_paths = (replace_destination, replace_wal, Path(f"{replace_destination}-shm"), Path(f"{replace_destination}-journal"))
        replace_before = {path: path.read_bytes() for path in replace_paths if path.exists()}
        result = run_cli("backup", str(source), str(replace_destination), "--replace", expected=1)
        assert "sidecar" in result.stderr
        assert {path: path.read_bytes() for path in replace_before} == replace_before

        run_cli("backup", str(source), str(backup), expected=1)
        run_cli("backup", str(source), str(root / "timed.sqlite3"), "--timeout", "1")
        run_cli("backup", str(source), str(root / "invalid-timeout.sqlite3"), "--timeout", "0", expected=2)
        run_cli("backup", str(source), str(root / "nan-timeout.sqlite3"), "--timeout", "nan", expected=2)
        run_cli("backup", str(source), str(root / "inf-timeout.sqlite3"), "--timeout", "inf", expected=2)

        permissive.mkdir()
        os.chmod(permissive, 0o755)
        run_cli("backup", str(source), str(permissive / "backup.sqlite3"), expected=1)

        corrupted = root / "corrupted.sqlite3"
        shutil.copyfile(backup, corrupted)
        with corrupted.open("r+b") as stream:
            stream.seek(100)
            stream.write(b"corruption")
        run_cli("verify", str(corrupted), expected=1)

        Path(f"{restored}-wal").touch()
        run_cli("restore", str(backup), str(restored), expected=1)
        Path(f"{restored}-wal").unlink()
        run_cli("restore", str(backup), str(restored))
        run_cli("verify", str(restored))
        with sqlite3.connect(restored) as connection:
            assert connection.execute("SELECT id FROM secret").fetchone() == ("wal-row",)
        assert oct(restored.stat().st_mode & 0o777) == "0o600"
        run_cli("restore", str(backup), str(restored), expected=1)
        assert not list(root.glob(".*.tmp"))
    print("sqlite backup test: ok")


if __name__ == "__main__":
    main()
