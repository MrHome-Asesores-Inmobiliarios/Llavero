"""P1-T3 acceptance tests (Annex C 5, 6).

Brief acceptance criteria:
- a second active primary owner insert fails on the partial unique
- ending a link sets state=former and valid_to without deleting the row

Plus: the other partial uniques (holder, location, responsible), the a<>b
CHECKs (account_recovery, device_dependency), and that former links free the
slot for a new active one.
"""

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.common.models import LinkState
from apps.inventory.models import Account, Device, Office, Person
from apps.operators.models import Operator
from apps.relationships.models import (
    AccountOwnership,
    AccountRecovery,
    DeviceAssignment,
    DeviceDependency,
    DeviceLocation,
    OfficeMembership,
    OwnershipRole,
)


@pytest.fixture
def operator(db):
    return Operator.objects.create(
        username="admin",
        display_name="Admin",
        role=Operator.Role.ADMINISTRATOR,
        password_hash="placeholder",
    )


@pytest.fixture
def people(operator):
    return [
        Person.objects.create(full_name=f"P{i}", created_by=operator, updated_by=operator)
        for i in range(3)
    ]


@pytest.fixture
def account(operator):
    return Account.objects.create(
        account_type=Account.Type.O365,
        label="Shared mailbox",
        identifier="ops@example.com",
        created_by=operator,
        updated_by=operator,
    )


@pytest.fixture
def device(operator):
    return Device.objects.create(
        device_type=Device.Type.LAPTOP,
        hostname="lt-01",
        created_by=operator,
        updated_by=operator,
    )


@pytest.fixture
def office(operator):
    return Office.objects.create(name="HQ", created_by=operator, updated_by=operator)


def _own(person, account, operator, role=OwnershipRole.PRIMARY, state=LinkState.ACTIVE):
    return AccountOwnership.objects.create(
        person=person,
        account=account,
        role=role,
        state=state,
        created_by=operator,
        updated_by=operator,
    )


# --- partial unique: one active primary owner per account -----------------


@pytest.mark.django_db
def test_second_active_primary_owner_fails(people, account, operator):
    _own(people[0], account, operator)
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            _own(people[1], account, operator)


@pytest.mark.django_db
def test_shared_owner_allowed_alongside_primary(people, account, operator):
    _own(people[0], account, operator, role=OwnershipRole.PRIMARY)
    # A shared owner does not trip the primary-only partial unique.
    shared = _own(people[1], account, operator, role=OwnershipRole.SHARED)
    assert shared.pk is not None


@pytest.mark.django_db
def test_former_primary_frees_the_slot(people, account, operator):
    first = _own(people[0], account, operator)
    first.end(by=operator)
    # With the first now 'former', a new active primary is allowed.
    second = _own(people[1], account, operator)
    assert second.state == LinkState.ACTIVE


# --- ending a link is a state change, not a delete ------------------------


@pytest.mark.django_db
def test_ending_a_link_sets_former_and_valid_to_without_delete(people, account, operator):
    link = _own(people[0], account, operator)
    pk = link.pk
    assert link.valid_to is None

    before = timezone.now()
    link.end(by=operator)

    assert link.state == LinkState.FORMER
    assert link.valid_to is not None
    assert link.valid_to >= before
    # Row still exists in the table.
    assert AccountOwnership.objects.filter(pk=pk).exists()
    reloaded = AccountOwnership.objects.get(pk=pk)
    assert reloaded.state == LinkState.FORMER


# --- other partial uniques ------------------------------------------------


@pytest.mark.django_db
def test_one_active_device_holder(people, device, operator):
    DeviceAssignment.objects.create(
        person=people[0], device=device, created_by=operator, updated_by=operator
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DeviceAssignment.objects.create(
                person=people[1], device=device, created_by=operator, updated_by=operator
            )


@pytest.mark.django_db
def test_one_active_device_location(device, office, operator):
    DeviceLocation.objects.create(
        device=device, office=office, created_by=operator, updated_by=operator
    )
    office2 = Office.objects.create(name="Branch", created_by=operator, updated_by=operator)
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DeviceLocation.objects.create(
                device=device, office=office2, created_by=operator, updated_by=operator
            )


@pytest.mark.django_db
def test_one_active_responsible_per_office(people, office, operator):
    OfficeMembership.objects.create(
        person=people[0],
        office=office,
        role=OfficeMembership.Role.RESPONSIBLE,
        created_by=operator,
        updated_by=operator,
    )
    # A second staff membership is fine; a second responsible is not.
    staff = OfficeMembership.objects.create(
        person=people[1],
        office=office,
        role=OfficeMembership.Role.STAFF,
        created_by=operator,
        updated_by=operator,
    )
    assert staff.pk is not None
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            OfficeMembership.objects.create(
                person=people[2],
                office=office,
                role=OfficeMembership.Role.RESPONSIBLE,
                created_by=operator,
                updated_by=operator,
            )


# --- a<>b CHECK constraints -----------------------------------------------


@pytest.mark.django_db
def test_account_recovery_cannot_self_reference(account, operator):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            AccountRecovery.objects.create(
                recovery_account=account,
                target_account=account,
                created_by=operator,
                updated_by=operator,
            )


@pytest.mark.django_db
def test_device_dependency_cannot_self_reference(device, operator):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DeviceDependency.objects.create(
                dependent_device=device,
                depends_on_device=device,
                created_by=operator,
                updated_by=operator,
            )


@pytest.mark.django_db
def test_account_recovery_between_distinct_accounts_ok(account, operator):
    other = Account.objects.create(
        account_type=Account.Type.GOOGLE,
        label="Recovery mailbox",
        identifier="recover@example.com",
        created_by=operator,
        updated_by=operator,
    )
    link = AccountRecovery.objects.create(
        recovery_account=other,
        target_account=account,
        priority=1,
        created_by=operator,
        updated_by=operator,
    )
    assert link.pk is not None
