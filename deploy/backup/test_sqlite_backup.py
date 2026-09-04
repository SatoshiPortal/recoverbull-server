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


def create_diesel_ledger(connection: sqlite3.Connection, version: str = "0001") -> None:
    connection.executescript(
        "CREATE TABLE __diesel_schema_migrations ("
        "version VARCHAR(50) PRIMARY KEY NOT NULL,"
        "run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
    )
    connection.execute(
        "INSERT INTO __diesel_schema_migrations (version) VALUES (?)", (version,)
    )


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


def run_database_check(
    binary: Path, database: Path, expected: int = 0
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(binary), "check-database", str(database)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert "ciphertext" not in result.stdout + result.stderr
    return result


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_sqlite_backup.py /path/to/keychain")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"keychain binary does not exist: {binary}")
    migration_versions = tuple(
        path.name.split("_", 1)[0]
        for path in sorted((ROOT.parent.parent / "migrations").iterdir())
        if path.is_dir()
    )
    assert backup_tool.EXPECTED_MIGRATION_VERSIONS == migration_versions, (
        "backup validation must track the embedded Rust migrations",
        backup_tool.EXPECTED_MIGRATION_VERSIONS,
        migration_versions,
    )

    with tempfile.TemporaryDirectory(prefix="sqlite-backup-test-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        source = root / "source ?#.sqlite3"
        backup = root / "backup.sqlite3"
        restored = root / "restored.sqlite3"
        naive = root / "naive.sqlite3"
        permissive = root / "permissive"
        source.touch()
        # AUD-05: check-database refuses an uninitialized file rather than
        # creating the schema in it and reporting the empty file as valid.
        run_database_check(binary, source, expected=1)
        with sqlite3.connect(source) as connection:
            connection.executescript(SCHEMA.read_text(encoding="utf-8"))
            create_diesel_ledger(connection)
        run_database_check(binary, source)
        with sqlite3.connect(source) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("INSERT INTO secret VALUES ('wal-row', '2026-08-25T00:00:00Z', 'ciphertext')")
            connection.commit()
        assert Path(f"{source}-wal").exists(), "fixture transaction must remain in WAL"

        shutil.copyfile(source, naive)
        with sqlite3.connect(naive) as connection:
            assert connection.execute("SELECT id FROM secret").fetchone() is None

        run_cli("backup", str(source), str(backup))
        run_cli("verify", str(backup), expected=2)
        with sqlite3.connect(backup) as connection:
            assert connection.execute("SELECT encrypted_secret FROM secret WHERE id='wal-row'").fetchone() == ("ciphertext",)
        assert oct(backup.stat().st_mode & 0o777) == "0o600"

        replace_destination = root / "replace.sqlite3"
        replace_destination.touch()
        with sqlite3.connect(replace_destination) as connection:
            connection.executescript(SCHEMA.read_text(encoding="utf-8"))
            create_diesel_ledger(connection)
        run_database_check(binary, replace_destination)
        with sqlite3.connect(replace_destination) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute(
                "INSERT INTO secret VALUES (?, ?, ?)",
                ("old-row", "2026-08-25T00:00:00Z", "old-ciphertext"),
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
        run_cli("restore", str(corrupted), str(root / "corrupted-restored.sqlite3"), expected=1)
        assert not (root / "corrupted-restored.sqlite3").exists()

        # Restore must compare the secret table with migration 0001, not only
        # check that a table by that name exists: an intact but unusable
        # backup must never be installed.
        for name, ddl in (
            ("missing-columns", "CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, wrong TEXT)"),
            ("renamed-column", "CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created TEXT NOT NULL, encrypted_secret TEXT NOT NULL)"),
            ("nullable-column", "CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created_at TEXT, encrypted_secret TEXT NOT NULL)"),
            ("extra-column", "CREATE TABLE secret (id TEXT PRIMARY KEY NOT NULL, created_at TEXT NOT NULL, encrypted_secret TEXT NOT NULL, extra TEXT)"),
            ("no-primary-key", "CREATE TABLE secret (id TEXT NOT NULL, created_at TEXT NOT NULL, encrypted_secret TEXT NOT NULL)"),
        ):
            incompatible = root / f"{name}.sqlite3"
            with sqlite3.connect(incompatible) as connection:
                connection.executescript(
                    ddl + ";"
                )
                create_diesel_ledger(connection)
            with sqlite3.connect(incompatible) as connection:
                assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            result = run_cli(
                "restore",
                str(incompatible),
                str(root / f"{name}-restored.sqlite3"),
                expected=1,
            )
            assert "schema" in result.stderr, (name, result.stderr)
            assert not (root / f"{name}-restored.sqlite3").exists()

        # The original false positive: an exact secret table beside a table
        # merely named like Diesel's ledger. Python used to accept it while
        # the server failed during migration initialization.
        invalid_ledger = root / "invalid-ledger.sqlite3"
        with sqlite3.connect(invalid_ledger) as connection:
            connection.executescript(SCHEMA.read_text(encoding="utf-8"))
            connection.executescript(
                "CREATE TABLE __diesel_schema_migrations (version TEXT PRIMARY KEY);"
                "INSERT INTO __diesel_schema_migrations VALUES ('00000000000000');"
            )
        result = run_cli(
            "restore",
            str(invalid_ledger),
            str(root / "invalid-ledger-restored.sqlite3"),
            expected=1,
        )
        assert "ledger" in result.stderr
        assert not (root / "invalid-ledger-restored.sqlite3").exists()
        run_database_check(binary, invalid_ledger, expected=1)

        unexpected_migration = root / "unexpected-migration.sqlite3"
        with sqlite3.connect(unexpected_migration) as connection:
            connection.executescript(SCHEMA.read_text(encoding="utf-8"))
            create_diesel_ledger(connection, "9999")
        result = run_cli(
            "restore",
            str(unexpected_migration),
            str(root / "unexpected-migration-restored.sqlite3"),
            expected=1,
        )
        assert "versions" in result.stderr
        assert not (root / "unexpected-migration-restored.sqlite3").exists()

        Path(f"{restored}-wal").touch()
        run_cli("restore", str(backup), str(restored), expected=1)
        Path(f"{restored}-wal").unlink()
        run_cli("restore", str(backup), str(restored))
        run_database_check(binary, restored)
        with sqlite3.connect(restored) as connection:
            assert connection.execute("SELECT id FROM secret").fetchone() == ("wal-row",)
        assert oct(restored.stat().st_mode & 0o777) == "0o600"
        run_cli("restore", str(backup), str(restored), expected=1)
        assert not list(root.glob(".*.tmp"))
    print("sqlite backup test: ok")


if __name__ == "__main__":
    main()
