"""Tests verifying that inventory views produce the correct audit log entries.

Each test uses an admin client (since writes require admin) and checks that
AuditEntry rows are created with the right action.
"""

import uuid

import pytest
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditEntry
from apps.inventory.models import (
    Account,
    AccountType,
    Device,
    DeviceType,
    Office,
    Person,
)
from apps.operators.models import Operator
from apps.relationships.models import AccountOwnership


def _hash(pw: str) -> str:
    import hashlib

    return "argon2:" + hashlib.sha256(pw.encode()).hexdigest()


def _make_operator(role, username=None):
    username = username or f"op_{role}_{uuid.uuid4().hex[:6]}"
    return Operator.objects.create(
        username=username,
        display_name=username,
        role=role,
        password_hash=_hash("test"),
        is_active=True,
    )


def _make_session(client: Client, operator: Operator):
    session = client.session
    session["operator_id"] = str(operator.pk)
    session.save()


def _make_person(admin_op, full_name="Audit Test Person"):
    return Person.objects.create(
        full_name=full_name,
        state="active",
        created_by=admin_op,
        updated_by=admin_op,
    )


def _make_account(admin_op, label="Audit Test Account"):
    return Account.objects.create(
        label=label,
        identifier=f"{uuid.uuid4().hex[:8]}@example.com",
        account_type=AccountType.OTHER,
        state="active",
        created_by=admin_op,
        updated_by=admin_op,
    )


def _make_device(admin_op, hostname="audit-host"):
    return Device.objects.create(
        device_type=DeviceType.LAPTOP,
        state="in_use",
        hostname=hostname,
        created_by=admin_op,
        updated_by=admin_op,
    )


def _make_office(admin_op, name="Audit Office"):
    return Office.objects.create(
        name=name,
        state="active",
        created_by=admin_op,
        updated_by=admin_op,
    )


@pytest.mark.django_db
class TestCreateAudit(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "audit_admin_create")
        self.client = Client()
        _make_session(self.client, self.admin)

    def test_create_person_logs_create(self):
        resp = self.client.post(
            reverse("person-create"),
            {"full_name": "Audit Person Create"},
        )
        self.assertIn(resp.status_code, [200, 302])
        # At least one audit entry should have been created with action=create
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.CREATE,
            target_table="person",
        )
        self.assertGreater(entries.count(), 0)

    def test_create_office_logs_create(self):
        resp = self.client.post(
            reverse("office-create"),
            {"name": "Audit Office Create"},
        )
        self.assertIn(resp.status_code, [200, 302])
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.CREATE,
            target_table="office",
        )
        self.assertGreater(entries.count(), 0)


@pytest.mark.django_db
class TestUpdateAudit(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "audit_admin_update")
        self.client = Client()
        _make_session(self.client, self.admin)

    def test_edit_account_logs_update(self):
        account = _make_account(self.admin)
        resp = self.client.post(
            reverse("account-edit", kwargs={"pk": account.pk}),
            {
                "label": "Updated Label",
                "identifier": account.identifier,
                "account_type": "other",
                "mfa_state": "unknown",
            },
        )
        self.assertIn(resp.status_code, [200, 302])
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.UPDATE,
            target_table="account",
            target_id=account.pk,
        )
        self.assertGreater(entries.count(), 0)


@pytest.mark.django_db
class TestStateChangeAudit(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "audit_admin_state")
        self.client = Client()
        _make_session(self.client, self.admin)

    def test_state_transition_logs_state_change(self):
        person = _make_person(self.admin)
        resp = self.client.post(
            reverse("person-transition", kwargs={"pk": person.pk}),
            {"new_state": "suspended"},
        )
        self.assertIn(resp.status_code, [200, 302])
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.STATE_CHANGE,
            target_table="person",
            target_id=person.pk,
        )
        self.assertGreater(entries.count(), 0)
        # Verify changes field records the transition
        entry = entries.last()
        self.assertEqual(entry.changes.get("old_state"), "active")
        self.assertEqual(entry.changes.get("new_state"), "suspended")


@pytest.mark.django_db
class TestRelationshipAudit(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "audit_admin_rel")
        self.client = Client()
        _make_session(self.client, self.admin)

    def test_link_create_logs_relationship_create(self):
        person = _make_person(self.admin)
        account = _make_account(self.admin)
        resp = self.client.post(
            reverse("link-create"),
            {
                "link_type": "account_ownership",
                "source_pk": str(person.pk),
                "target_pk": str(account.pk),
                "role": "shared",
            },
        )
        self.assertIn(resp.status_code, [200, 201])
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.RELATIONSHIP_CREATE,
            target_table="account_ownership",
        )
        self.assertGreater(entries.count(), 0)

    def test_link_end_logs_relationship_end(self):
        person = _make_person(self.admin)
        account = _make_account(self.admin)
        # Create the link first
        link = AccountOwnership.objects.create(
            person=person,
            account=account,
            role="shared",
            state="active",
            created_by=self.admin,
            updated_by=self.admin,
        )
        resp = self.client.post(
            reverse("link-end", kwargs={"pk": link.pk}),
            {"link_type": "account_ownership"},
        )
        self.assertIn(resp.status_code, [200, 302])
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.RELATIONSHIP_END,
            target_table="account_ownership",
            target_id=link.pk,
        )
        self.assertGreater(entries.count(), 0)


@pytest.mark.django_db
class TestFieldDefinitionAudit(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "audit_admin_fd")
        self.client = Client()
        _make_session(self.client, self.admin)

    def test_create_fielddefinition_logs_change(self):
        resp = self.client.post(
            reverse("fielddefinition-create"),
            {
                "entity_type": "person",
                "key": f"audit_fd_{uuid.uuid4().hex[:6]}",
                "label": "Audit FD",
                "data_type": "string",
                "display_order": 0,
                "required": False,
                "viewer_visible": True,
                "active": True,
            },
        )
        self.assertIn(resp.status_code, [200, 302])
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.FIELD_DEFINITION_CHANGE,
            target_table="field_definition",
        )
        self.assertGreater(entries.count(), 0)


@pytest.mark.django_db
class TestReadAudit(TestCase):
    def setUp(self):
        self.viewer = _make_operator(Operator.Role.VIEWER, "audit_viewer")
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "audit_admin_read")
        self.viewer_client = Client()
        self.admin_client = Client()
        _make_session(self.viewer_client, self.viewer)
        _make_session(self.admin_client, self.admin)

    def test_viewer_detail_logs_record_view(self):
        person = _make_person(self.admin)
        resp = self.viewer_client.get(reverse("person-detail", kwargs={"pk": person.pk}))
        self.assertEqual(resp.status_code, 200)
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.RECORD_VIEW,
            target_table="person",
            target_id=person.pk,
        )
        self.assertGreater(entries.count(), 0)

    def test_list_view_logs_list_view(self):
        resp = self.viewer_client.get(reverse("person-list"))
        self.assertEqual(resp.status_code, 200)
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.LIST_VIEW,
            target_table="person",
        )
        self.assertGreater(entries.count(), 0)

    def test_search_logs_search(self):
        resp = self.viewer_client.get(reverse("person-list") + "?q=Test")
        self.assertEqual(resp.status_code, 200)
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.SEARCH,
            target_table="person",
        )
        self.assertGreater(entries.count(), 0)

    def test_account_detail_logs_record_view(self):
        account = _make_account(self.admin)
        resp = self.viewer_client.get(reverse("account-detail", kwargs={"pk": account.pk}))
        self.assertEqual(resp.status_code, 200)
        entries = AuditEntry.objects.filter(
            action=AuditEntry.Action.RECORD_VIEW,
            target_table="account",
            target_id=account.pk,
        )
        self.assertGreater(entries.count(), 0)
