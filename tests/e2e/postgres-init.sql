\set ON_ERROR_STOP on

-- The existing Sub2API database is deliberately private in acceptance. The
-- later Control role provisioner must not gain CONNECT through PUBLIC.
REVOKE CONNECT, TEMPORARY ON DATABASE sub2api FROM PUBLIC;

CREATE TABLE IF NOT EXISTS sub2api_private_sentinel (
    id integer PRIMARY KEY,
    secret_marker text NOT NULL
);

INSERT INTO sub2api_private_sentinel (id, secret_marker)
VALUES (1, 'sub2api-private-data')
ON CONFLICT (id) DO UPDATE SET secret_marker = EXCLUDED.secret_marker;
