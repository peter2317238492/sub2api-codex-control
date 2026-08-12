# Local backup staging

Database dumps in this directory are ignored by Git. Production should point
`CONTROL_BACKUP_DIR` at an encrypted, access-controlled path outside the source
checkout and ship completed checksummed dumps to immutable off-host storage.
