"""Management command: verify a freshly restored database (P2-T6, Annex H 8, 9).

Run inside the isolated restore environment after loading a dump. Walks the
audit chain, checks the restored head against the off-box signed checkpoint
under an independently-trusted offline key, reports any daily-dump lag, and
(optionally) runs the recovery-key decrypt drill on one secret.

    manage.py restore_verify \
        --trusted-key-file /path/to/offline-ed25519.pub.hex \
        --anchor-dir /srv/llavero-anchors \
        [--recovery-code-env LLAVERO_DRILL_RECOVERY_CODE --secret-id <uuid>] \
        [--json]

Exit status: 0 if the chain verifies and the anchor was not tampered (a
``behind`` daily-dump lag is still success — it is reported, not failed);
1 otherwise.

The recovery code is read from an environment variable for the drill only and
is NEVER printed, logged, or persisted. The drill reports only that the secret
decrypted and its length — never the value. Do not wire the drill into an
unattended script; it exists for the manual dry run and the periodic drill.
"""

import json
import os
import sys

from django.core.management.base import BaseCommand, CommandError

from apps.audit.anchor import AppendOnlyFileAnchorStore
from apps.backup.restore_verify import recovery_decrypt_drill, verify_restore


class Command(BaseCommand):
    help = "Verify a restored database: chain walk, off-box checkpoint, recovery drill."

    def add_arguments(self, parser):
        parser.add_argument(
            "--trusted-key-file",
            help="File holding the hex-encoded offline checkpoint public key "
            "(the key independently trusted — never one from the restored DB).",
        )
        parser.add_argument(
            "--anchor-dir",
            help="Directory of the append-only off-box checkpoint store (separate host).",
        )
        parser.add_argument(
            "--recovery-code-env",
            help="Name of an env var holding the printed recovery code (drill only). "
            "The code is never printed or stored.",
        )
        parser.add_argument(
            "--secret-id",
            help="UUID of a secret to decrypt via the recovery-key path (drill only).",
        )
        parser.add_argument("--json", action="store_true", help="Emit a JSON report.")

    def handle(self, *args, **options):
        trusted_key = None
        if options.get("trusted_key_file"):
            with open(options["trusted_key_file"]) as fh:
                trusted_key = bytes.fromhex(fh.read().strip())

        anchor_store = None
        if options.get("anchor_dir"):
            anchor_store = AppendOnlyFileAnchorStore(options["anchor_dir"])

        report = verify_restore(trusted_public_key=trusted_key, anchor_store=anchor_store)

        result = {
            "chain_ok": report.chain_ok,
            "chain_reason": report.chain_reason,
            "restored_head_seq": report.restored_head_seq,
            "anchor_ok": report.anchor_ok,
            "anchor_state": report.anchor_state,
            "anchor_reason": report.anchor_reason,
            "offbox_head_seq": report.offbox_head_seq,
            "lag": report.lag,
            "trustworthy": report.trustworthy,
        }

        # Optional recovery-key decrypt drill (manual dry run / periodic drill).
        code_env = options.get("recovery_code_env")
        secret_id = options.get("secret_id")
        if code_env and secret_id:
            from apps.vault.models import Secret

            code = os.environ.get(code_env)
            if not code:
                raise CommandError(f"env var {code_env} is empty; cannot run the recovery drill")
            try:
                secret = Secret.objects.get(id=secret_id)
            except Secret.DoesNotExist as exc:
                raise CommandError(f"no secret with id {secret_id}") from exc
            length = recovery_decrypt_drill(recovery_code=code, secret=secret)
            result["recovery_drill"] = {
                "secret_id": secret_id,
                "decrypted_ok": True,
                "length": length,
            }
        elif code_env or secret_id:
            raise CommandError("the recovery drill needs both --recovery-code-env and --secret-id")

        if options["json"]:
            self.stdout.write(json.dumps(result))
        else:
            self._print_human(result)

        if not report.trustworthy:
            sys.exit(1)

    def _print_human(self, r: dict) -> None:
        self.stdout.write(f"chain verified : {r['chain_ok']} (head seq {r['restored_head_seq']})")
        if r["chain_reason"]:
            self.stdout.write(f"chain reason   : {r['chain_reason']}")
        self.stdout.write(f"anchor state   : {r['anchor_state']} (ok={r['anchor_ok']})")
        if r["lag"] is not None:
            self.stdout.write(
                f"off-box head   : seq {r['offbox_head_seq']} "
                f"(restored is {r['lag']} behind — expected for a daily dump, Annex H 8)"
            )
        if "recovery_drill" in r:
            d = r["recovery_drill"]
            self.stdout.write(
                f"recovery drill : secret {d['secret_id']} decrypted ({d['length']} bytes)"
            )
        self.stdout.write(f"TRUSTWORTHY    : {r['trustworthy']}")
