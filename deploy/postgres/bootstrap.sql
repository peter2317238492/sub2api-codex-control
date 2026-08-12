\set ON_ERROR_STOP on

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'control_role',
    :'control_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'control_role')
\gexec

SELECT format(
    'ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'control_role',
    :'control_password'
)
\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'control_database', :'control_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'control_database')
\gexec

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'control_database')
\gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', :'control_database', :'control_role')
\gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM %I', :'sub2api_database', :'control_role')
\gexec

\connect :control_database

REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('ALTER SCHEMA public OWNER TO %I', :'control_role')
\gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'control_role')
\gexec

SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC',
    :'control_role'
)
\gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC',
    :'control_role'
)
\gexec
