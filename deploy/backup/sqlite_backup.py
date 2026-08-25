#!/usr/bin/env python3
"""Create and verify SQLite backups without copying WAL sidecar files."""

import argparse
import math
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote


REQUIRED_TABLES = ("secret", "__diesel_schema_migrations")


def _readonly(path: Path) -> sqlite3.Connection:
    encoded_path = quote(str(path.resolve()), safe="/")
    connection = sqlite3.connect(f"file:{encoded_path}?mode=ro", uri=True)
    connection.execute("PRAGMA busy_timeout=1000")
    return connection


def _private_parent(path: Path) -> Path:
    parent = path.parent
    if not parent.is_dir():
        raise RuntimeError(f"destination parent is not a directory: {parent}")
    if parent.stat().st_mode & 0o77:
        raise RuntimeError(f"destination parent must not be group/world accessible: {parent}")
    return parent


def _absent(path: Path) -> bool:
    return not os.path.lexists(path)


def _sidecars(path: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{path}{suffix}") for suffix in ("-wal", "-shm", "-journal"))


def _has_sidecars(path: Path) -> bool:
    return any(os.path.lexists(sidecar) for sidecar in _sidecars(path))


def _integrity_and_schema(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError("SQLite integrity_check did not return ok")
    names = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = [name for name in REQUIRED_TABLES if name not in names]
    if missing:
        raise RuntimeError("backup is missing required schema tables")


def _sync_directory(directory: Path) -> None:
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _remove_temporary(path: Path) -> None:
    for candidate in (path, *_sidecars(path)):
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass


def backup(source: Path, destination: Path, replace: bool = False, timeout: float = 30.0) -> None:
    source = source.resolve()
    destination = destination.resolve()
    if source == destination:
        raise RuntimeError("source and destination must be different paths")
    if not source.is_file():
        raise RuntimeError("source database does not exist or is not a file")
    _private_parent(destination)
    if destination.exists() and not replace:
        raise FileExistsError("destination already exists; use --replace to overwrite it")
    if replace and _has_sidecars(destination):
        raise FileExistsError("destination has an existing SQLite sidecar")

    temporary_name = None
    source_connection = None
    destination_connection = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o600)
        source_connection = _readonly(source)
        destination_connection = sqlite3.connect(temporary)
        destination_connection.execute("PRAGMA busy_timeout=1000")
        deadline = time.monotonic() + timeout

        def progress(_status: int, _remaining: int, _total: int) -> None:
            if time.monotonic() >= deadline:
                raise TimeoutError("SQLite Online Backup exceeded its timeout")

        source_connection.backup(destination_connection, pages=100, progress=progress, sleep=0.1)
        destination_connection.commit()
        _integrity_and_schema(destination_connection)
        destination_connection.close()
        destination_connection = None
        file_descriptor = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(file_descriptor)
        finally:
            os.close(file_descriptor)
        if replace:
            if _has_sidecars(destination):
                raise FileExistsError("destination has an existing SQLite sidecar")
            os.replace(temporary, destination)
        else:
            # link() gives the no-overwrite mode an atomic destination install.
            os.link(temporary, destination)
            temporary.unlink()
        _sync_directory(destination.parent)
    finally:
        if destination_connection is not None:
            destination_connection.close()
        if source_connection is not None:
            source_connection.close()
        if temporary_name is not None:
            _remove_temporary(Path(temporary_name))


def verify(path: Path) -> None:
    path = path.resolve()
    if not path.is_file():
        raise RuntimeError("backup does not exist or is not a file")
    connection = _readonly(path)
    try:
        _integrity_and_schema(connection)
    finally:
        connection.close()


def restore(backup_path: Path, destination: Path) -> None:
    backup_path = backup_path.resolve()
    destination = destination.absolute()
    _private_parent(destination)
    if not backup_path.is_file():
        raise RuntimeError("backup does not exist or is not a file")
    verify(backup_path)
    paths = (destination, *_sidecars(destination))
    if not all(_absent(path) for path in paths):
        raise FileExistsError("restore destination or SQLite sidecar already exists")

    temporary_name = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o600)
        with backup_path.open("rb") as source, temporary.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, destination)
        temporary.unlink()
        _sync_directory(destination.parent)
        try:
            verify(destination)
        except Exception:
            try:
                destination.unlink()
                _sync_directory(destination.parent)
            except FileNotFoundError:
                pass
            raise
    finally:
        if temporary_name is not None:
            _remove_temporary(Path(temporary_name))


def _positive_timeout(value: str) -> float:
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return timeout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SQLite Online Backup utility")
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup", help="create an atomic backup")
    backup_parser.add_argument("source", type=Path)
    backup_parser.add_argument("destination", type=Path)
    backup_parser.add_argument("--replace", action="store_true")
    backup_parser.add_argument("--timeout", type=_positive_timeout, default=30.0)
    verify_parser = subparsers.add_parser("verify", help="check a backup")
    verify_parser.add_argument("backup", type=Path)
    restore_parser = subparsers.add_parser("restore", help="install a verified backup atomically")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "backup":
            backup(arguments.source, arguments.destination, arguments.replace, arguments.timeout)
            print("backup: ok")
        elif arguments.command == "verify":
            verify(arguments.backup)
            print("verify: ok")
        else:
            restore(arguments.backup, arguments.destination)
            print("restore: ok")
    except (OSError, sqlite3.Error, RuntimeError) as error:
        print(f"{arguments.command}: failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
