CREATE TABLE key (
    id TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    secret TEXT NOT NULL,
    backup_key TEXT NOT NULL,
    requested_at TEXT
);
