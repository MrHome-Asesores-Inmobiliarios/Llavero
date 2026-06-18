"""Append-only enforcement for the audit tables (Annex B 5; Annex G 5).

Two layers:
1. A BEFORE UPDATE OR DELETE trigger on audit_entry and audit_checkpoint that
   raises. This fires for every role (defence in depth; the dev safeguard).
2. Role grants: REVOKE UPDATE/DELETE/TRUNCATE from PUBLIC, and — when the
   production app role ``llavero_app`` exists — grant it INSERT/SELECT only.
   In dev the single owner role is unaffected by grants (the trigger applies).

A superuser can still bypass both; that residual risk is covered by the signed
external checkpoints (Annex B 2), built in P1-T13/T14.
"""

from django.db import migrations

TRIGGER_SQL = r"""
CREATE OR REPLACE FUNCTION llavero_audit_no_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only: % on % is rejected', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'raise_exception';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_entry_append_only
    BEFORE UPDATE OR DELETE ON audit_entry
    FOR EACH ROW EXECUTE FUNCTION llavero_audit_no_mutate();

CREATE TRIGGER audit_checkpoint_append_only
    BEFORE UPDATE OR DELETE ON audit_checkpoint
    FOR EACH ROW EXECUTE FUNCTION llavero_audit_no_mutate();

-- Access control: no UPDATE/DELETE/TRUNCATE for anyone via PUBLIC.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_entry, audit_checkpoint FROM PUBLIC;

-- Production two-role setup: the app role gets INSERT/SELECT only. Applied only
-- if that role exists, so dev (single owner role) is unaffected.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'llavero_app') THEN
        REVOKE ALL ON audit_entry, audit_checkpoint FROM llavero_app;
        GRANT INSERT, SELECT ON audit_entry, audit_checkpoint TO llavero_app;
    END IF;
END $$;
"""

REVERSE_SQL = r"""
DROP TRIGGER IF EXISTS audit_entry_append_only ON audit_entry;
DROP TRIGGER IF EXISTS audit_checkpoint_append_only ON audit_checkpoint;
DROP FUNCTION IF EXISTS llavero_audit_no_mutate();
"""


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(sql=TRIGGER_SQL, reverse_sql=REVERSE_SQL),
    ]
