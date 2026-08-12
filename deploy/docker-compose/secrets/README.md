# Runtime secrets

This directory must contain exactly these mode-`0600` files before deployment:

- `control_db_password`
- `control_redis_password`
- `control_session_hmac_secret`

Run `../../scripts/generate-secrets.sh` to create new random values. Never commit
the generated files. Provision the PostgreSQL login and Redis ACL with the first
two values before starting Compose. Rotation is an explicit maintenance event;
do not overwrite live values without following the rollback runbook.
