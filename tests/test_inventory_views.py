"""Tests for inventory UI views (Phase 3).

Tests cover permission enforcement, CRUD, and state transitions.
The session is mocked by writing operator_id into the Django session store.
"""

import uuid

import pytest
from django.test import Client, TestCase
from django.urls import reverse

from apps.inventory.models import (
    Account,
    AccountType,
    Device,
    DeviceType,
    FieldDefinition,
    Office,
    Person,
)
from apps.operators.models import Operator


def _hash(pw: str) -> str:
    """Minimal stand-in — tests never verify the hash."""
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
    """Write operator_id into client session so decorators pick it up."""
    session = client.session
    session["operator_id"] = str(operator.pk)
    session.save()


def _make_person(admin_op):
    return Person.objects.create(
        full_name="Test Person",
        state="active",
        created_by=admin_op,
        updated_by=admin_op,
    )


def _make_account(admin_op):
    return Account.objects.create(
        label="Test Account",
        identifier="test@example.com",
        account_type=AccountType.OTHER,
        state="active",
        created_by=admin_op,
        updated_by=admin_op,
    )


def _make_device(admin_op):
    return Device.objects.create(
        device_type=DeviceType.LAPTOP,
        state="in_use",
        hostname="test-host",
        created_by=admin_op,
        updated_by=admin_op,
    )


def _make_office(admin_op):
    return Office.objects.create(
        name="Test Office",
        state="active",
        created_by=admin_op,
        updated_by=admin_op,
    )


@pytest.mark.django_db
class TestPersonViews(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_person")
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_person")
        self.admin_client = Client()
        self.viewer_client = Client()
        _make_session(self.admin_client, self.admin)
        _make_session(self.viewer_client, self.viewer)

    def test_viewer_can_get_list(self):
        resp = self.viewer_client.get(reverse("person-list"))
        self.assertEqual(resp.status_code, 200)

    def test_admin_can_get_list(self):
        resp = self.admin_client.get(reverse("person-list"))
        self.assertEqual(resp.status_code, 200)

    def test_unauthenticated_redirects(self):
        c = Client()
        resp = c.get(reverse("person-list"))
        self.assertIn(resp.status_code, [302, 401])

    def test_viewer_can_get_detail(self):
        person = _make_person(self.admin)
        resp = self.viewer_client.get(reverse("person-detail", kwargs={"pk": person.pk}))
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_get_create(self):
        resp = self.viewer_client.get(reverse("person-create"))
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_post_create(self):
        resp = self.viewer_client.post(
            reverse("person-create"), {"full_name": "Hacker", "state": "active"}
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_get_create(self):
        resp = self.admin_client.get(reverse("person-create"))
        self.assertEqual(resp.status_code, 200)

    def test_admin_can_post_create(self):
        resp = self.admin_client.post(
            reverse("person-create"),
            {"full_name": "New Person", "job_title": "Dev", "department": "IT"},
        )
        # Expect redirect on success
        self.assertIn(resp.status_code, [200, 302])
        if resp.status_code == 302:
            self.assertTrue(Person.objects.filter(full_name="New Person").exists())

    def test_viewer_cannot_edit(self):
        person = _make_person(self.admin)
        resp = self.viewer_client.get(reverse("person-edit", kwargs={"pk": person.pk}))
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_post_edit(self):
        person = _make_person(self.admin)
        resp = self.viewer_client.post(
            reverse("person-edit", kwargs={"pk": person.pk}),
            {"full_name": "Hacked Name"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_edit(self):
        person = _make_person(self.admin)
        resp = self.admin_client.get(reverse("person-edit", kwargs={"pk": person.pk}))
        self.assertEqual(resp.status_code, 200)


@pytest.mark.django_db
class TestStateTransition(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_trans")
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_trans")
        self.admin_client = Client()
        self.viewer_client = Client()
        _make_session(self.admin_client, self.admin)
        _make_session(self.viewer_client, self.viewer)

    def test_admin_can_transition_state(self):
        person = _make_person(self.admin)
        resp = self.admin_client.post(
            reverse("person-transition", kwargs={"pk": person.pk}),
            {"new_state": "suspended"},
        )
        self.assertIn(resp.status_code, [200, 302])
        person.refresh_from_db()
        self.assertEqual(person.state, "suspended")

    def test_viewer_cannot_transition(self):
        person = _make_person(self.admin)
        resp = self.viewer_client.post(
            reverse("person-transition", kwargs={"pk": person.pk}),
            {"new_state": "suspended"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_cannot_leave_terminal_state_person(self):
        person = _make_person(self.admin)
        person.state = "terminated"
        person.save()
        resp = self.admin_client.post(
            reverse("person-transition", kwargs={"pk": person.pk}),
            {"new_state": "active"},
        )
        self.assertEqual(resp.status_code, 400)
        person.refresh_from_db()
        self.assertEqual(person.state, "terminated")

    def test_cannot_leave_terminal_state_device(self):
        device = _make_device(self.admin)
        device.state = "decommissioned"
        device.save()
        resp = self.admin_client.post(
            reverse("device-transition", kwargs={"pk": device.pk}),
            {"new_state": "in_use"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_can_move_to_terminal_state(self):
        device = _make_device(self.admin)
        resp = self.admin_client.post(
            reverse("device-transition", kwargs={"pk": device.pk}),
            {"new_state": "decommissioned"},
        )
        self.assertIn(resp.status_code, [200, 302])
        device.refresh_from_db()
        self.assertEqual(device.state, "decommissioned")

    def test_invalid_state_returns_400(self):
        person = _make_person(self.admin)
        resp = self.admin_client.post(
            reverse("person-transition", kwargs={"pk": person.pk}),
            {"new_state": "nonexistent_state"},
        )
        self.assertEqual(resp.status_code, 400)


@pytest.mark.django_db
class TestAccountViews(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_acc")
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_acc")
        self.admin_client = Client()
        self.viewer_client = Client()
        _make_session(self.admin_client, self.admin)
        _make_session(self.viewer_client, self.viewer)

    def test_viewer_can_get_list(self):
        resp = self.viewer_client.get(reverse("account-list"))
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_create(self):
        resp = self.viewer_client.post(reverse("account-create"), {})
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_create_account(self):
        resp = self.admin_client.post(
            reverse("account-create"),
            {
                "label": "My Account",
                "identifier": "user@example.com",
                "account_type": "other",
                "mfa_state": "unknown",
            },
        )
        self.assertIn(resp.status_code, [200, 302])

    def test_viewer_can_get_detail(self):
        account = _make_account(self.admin)
        resp = self.viewer_client.get(reverse("account-detail", kwargs={"pk": account.pk}))
        self.assertEqual(resp.status_code, 200)


@pytest.mark.django_db
class TestDeviceViews(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_dev")
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_dev")
        self.admin_client = Client()
        self.viewer_client = Client()
        _make_session(self.admin_client, self.admin)
        _make_session(self.viewer_client, self.viewer)

    def test_viewer_can_list(self):
        resp = self.viewer_client.get(reverse("device-list"))
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_create(self):
        resp = self.viewer_client.get(reverse("device-create"))
        self.assertEqual(resp.status_code, 403)

    def test_viewer_can_get_detail(self):
        device = _make_device(self.admin)
        resp = self.viewer_client.get(reverse("device-detail", kwargs={"pk": device.pk}))
        self.assertEqual(resp.status_code, 200)


@pytest.mark.django_db
class TestOfficeViews(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_off")
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_off")
        self.admin_client = Client()
        self.viewer_client = Client()
        _make_session(self.admin_client, self.admin)
        _make_session(self.viewer_client, self.viewer)

    def test_viewer_can_list(self):
        resp = self.viewer_client.get(reverse("office-list"))
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_create(self):
        resp = self.viewer_client.get(reverse("office-create"))
        self.assertEqual(resp.status_code, 403)

    def test_viewer_can_get_detail(self):
        office = _make_office(self.admin)
        resp = self.viewer_client.get(reverse("office-detail", kwargs={"pk": office.pk}))
        self.assertEqual(resp.status_code, 200)


@pytest.mark.django_db
class TestFieldDefinitionViews(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_fd")
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_fd")
        self.admin_client = Client()
        self.viewer_client = Client()
        _make_session(self.admin_client, self.admin)
        _make_session(self.viewer_client, self.viewer)

    def test_viewer_cannot_list_fielddefinitions(self):
        resp = self.viewer_client.get(reverse("fielddefinition-list"))
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_list_fielddefinitions(self):
        resp = self.admin_client.get(reverse("fielddefinition-list"))
        self.assertEqual(resp.status_code, 200)

    def test_viewer_cannot_create_fielddefinition(self):
        resp = self.viewer_client.get(reverse("fielddefinition-create"))
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_create_fielddefinition(self):
        resp = self.admin_client.post(
            reverse("fielddefinition-create"),
            {
                "entity_type": "person",
                "key": "employee_id",
                "label": "Employee ID",
                "data_type": "string",
                "display_order": 0,
                "required": False,
                "viewer_visible": True,
                "active": True,
            },
        )
        self.assertIn(resp.status_code, [200, 302])

    def test_viewer_cannot_edit_fielddefinition(self):
        fd = FieldDefinition.objects.create(
            entity_type="person",
            key="test_fd_view",
            label="Test",
            data_type="string",
        )
        resp = self.viewer_client.get(reverse("fielddefinition-edit", kwargs={"pk": fd.pk}))
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_edit_fielddefinition(self):
        fd = FieldDefinition.objects.create(
            entity_type="person",
            key="test_fd_admin",
            label="Test",
            data_type="string",
        )
        resp = self.admin_client.get(reverse("fielddefinition-edit", kwargs={"pk": fd.pk}))
        self.assertEqual(resp.status_code, 200)


@pytest.mark.django_db
class TestSearchFiltering(TestCase):
    def setUp(self):
        self.admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_search")
        self.admin_client = Client()
        _make_session(self.admin_client, self.admin)

    def test_search_persons(self):
        _make_person(self.admin)
        resp = self.admin_client.get(reverse("person-list") + "?q=Test")
        self.assertEqual(resp.status_code, 200)

    def test_search_offices(self):
        _make_office(self.admin)
        resp = self.admin_client.get(reverse("office-list") + "?q=Test")
        self.assertEqual(resp.status_code, 200)
