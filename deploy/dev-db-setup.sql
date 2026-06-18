-- Run once as the postgres superuser to create the dev database and user.
-- Usage (Windows):  psql -U postgres -h 127.0.0.1 -f deploy\dev-db-setup.sql
-- Usage (Linux):    psql -U postgres -f deploy/dev-db-setup.sql
--
-- Uses throwaway dev credentials — never use these in production.

-- Create the app user
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'llavero') THEN
        -- CREATEDB is needed by pytest to create the test_llavero database.
        -- Production llavero user does NOT get CREATEDB.
        CREATE USER llavero WITH PASSWORD 'llavero-dev-password' CREATEDB CONNECTION LIMIT 10;
    END IF;
END
$$;

-- Create the dev database
SELECT 'CREATE DATABASE llavero OWNER llavero ENCODING ''UTF8'''
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'llavero') \gexec

-- Grant connect
GRANT CONNECT ON DATABASE llavero TO llavero;
