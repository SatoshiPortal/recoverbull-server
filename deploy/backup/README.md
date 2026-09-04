# SQLite backup and restore example

This is an operator-adapted example, not a complete backup policy. The
operator owns scheduling, encryption, off-host retention, access control,
monitoring, and recurring restore drills. Repository tests cover the script's
behavior at this commit; they do not validate an installed job or storage
provider.

Copying only the main SQLite file while WAL mode is active can omit committed transactions that still reside in `database-wal`; copying `-wal` and `-shm` naively is not a safe substitute. This tool uses SQLite's Online Backup API from a read-only source connection, so the backup is a coherent database without those sidecars. It does not manage Litestream or external encryption.

The database and every backup are confidential: restrict the data directory and backup directory to `0700`, and files to `0600`. Backups must be rotated, encrypted by the operator, and stored off-host. Retention and encryption are mandatory; `/trash` never deletes historical backups.

Ideally, the backup job uses a distinct identity with read access to the source only, while the destination is not writable by the service identity. Off-host and immutable storage limits the impact of a compromise of the external service or host.

## Backup

Run as an account that can read the live database and write the destination directory:

```sh
install -d -m 0700 /var/backups/recoverbull
python3 deploy/backup/sqlite_backup.py backup /var/lib/recoverbull/database.sqlite3 /var/backups/recoverbull/database.sqlite3
```

Use `--replace` only for an intentional rotation target with no existing SQLite sidecars; rotate to a new name or first make sure the destination is inactive and has no `-wal`, `-shm`, or `-journal` file. The command does not print database contents and leaves no temporary file after success or failure.

The Online Backup API has a 30-second deadline by default and a bounded SQLite busy wait; select another positive value with `--timeout` when required by the maintenance window.

## Restore drill and rollback

Before a restore, perform a controlled drill on a new path; do not infer RPO
or RTO unless the operator has configured and measured them. The selected
proxy service is deployment-specific; substitute its actual systemd unit for
`<proxy-service>` below and do not stop an unrelated proxy.

1. Stop the application and selected proxy, then confirm both are stopped: `sudo systemctl stop recoverbull.service <proxy-service>`.
2. Preserve the damaged database and its `-wal`/`-shm`/`-journal` trio unchanged in a private incident directory; never overwrite it. Create the directory with `sudo install -d -m 0700 /var/lib/recoverbull/incident-2026-08-24`, then move only each path that exists—`database.sqlite3`, `database.sqlite3-wal`, `database.sqlite3-shm`, and `database.sqlite3-journal`—to that directory; do not use a wildcard.
3. Restore the selected backup to the now-empty configured path: `python3 deploy/backup/sqlite_backup.py restore /var/backups/recoverbull/database.sqlite3 /var/lib/recoverbull/database.sqlite3`.
4. Set ownership and permissions: `sudo chown recoverbull:recoverbull /var/lib/recoverbull/database.sqlite3 && sudo chmod 0600 /var/lib/recoverbull/database.sqlite3`.
5. As the service identity, run the exact application initialization without binding a listener: `sudo -u recoverbull /opt/recoverbull/bin/keychain check-database /var/lib/recoverbull/database.sqlite3`. This may apply the same pending migrations and WAL setup as normal startup, but only to the restored copy, never to the archived backup.
6. Start the application and selected proxy, then check `/info` and the canary and perform a synthetic store/fetch/trash check. If any check fails, stop them and atomically roll back to the preserved incident copy or another backup that passed the same drill.

Record each restore test, rotation, purge, owner, and result. A backup that has
not passed a restore drill is not a recovery plan. `backup` validates its
output, and `restore` validates its input and installed copy with SQLite's
integrity check plus exact `secret` and Diesel-ledger postconditions. The
`check-database` step is the final compatibility authority because it uses the
server's own embedded migrations and startup checks rather than a second
implementation of them in Python.
