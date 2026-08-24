# Retention and recovery template

There is no universal retention duration. The operator must select and record
durations for application logs, selected reverse-proxy, Tor, and journald logs,
SQLite backups, WAL,
Litestream state, and archived snapshots according to legal, operational, and
recovery requirements.

At minimum:

* keep SQLite database and WAL together for every backup and restore;
* configure and test Litestream or an equivalent replica if used;
* restrict logs and backups to service administrators;
* document restore, rollback, and purge procedures and verify each one;
* never assume `/trash` purges historical backups or replicas;
* record selected periods, owner, last restore test, and purge verification.

Before deleting a copy, verify that it is outside the recovery window and that
the database/WAL pair or replica checkpoint is coherent. Treat a failed restore
or purge verification as an operational alarm, not as permission to continue.
