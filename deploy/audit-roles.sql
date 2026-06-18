-- Production two-role setup for append-only audit (Annex B 5; Annex G 5).
-- Run once on the production database as the postgres superuser.
--
-- Roles:
--   llavero_owner : owns the schema; runs migrations (DDL). Used ONLY for
--                   `manage.py migrate`.
--   llavero_app   : the runtime application role. Full CRUD on normal tables,
--                   but INSERT/SELECT only on the audit tables — no UPDATE or
--                   DELETE. This is the role Django uses to serve requests.
--
-- The BEFORE UPDATE OR DELETE trigger (migration audit/0002) is defence in
-- depth on top of these grants. The audit/0002 migration also re-applies the
-- audit-table grants to llavero_app when it exists, so re-running migrations
-- keeps them correct.

-- 1. Roles (set real passwords / use peer or cert auth as appropriate)
CREATE ROLE llavero_owner LOGIN PASSWORD 'CHANGE_ME_owner';
CREATE ROLE llavero_app   LOGIN PASSWORD 'CHANGE_ME_app';

-- 2. Database owned by the migration role
ALTER DATABASE llavero OWNER TO llavero_owner;

-- 3. The app role may use the schema and existing/future tables...
GRANT USAGE ON SCHEMA public TO llavero_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO llavero_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO llavero_app;
ALTER DEFAULT PRIVILEGES FOR ROLE llavero_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO llavero_app;
ALTER DEFAULT PRIVILEGES FOR ROLE llavero_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO llavero_app;

-- 4. ...except the audit tables, which are INSERT/SELECT only for the app role.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_entry, audit_checkpoint FROM PUBLIC;
REVOKE ALL ON audit_entry, audit_checkpoint FROM llavero_app;
GRANT INSERT, SELECT ON audit_entry, audit_checkpoint TO llavero_app;

-- Settings:
--   migrations:  DB_USER=llavero_owner   (manage.py migrate only)
--   runtime:     DB_USER=llavero_app     (gunicorn / app server)
