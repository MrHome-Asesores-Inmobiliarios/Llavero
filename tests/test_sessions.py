"""P1-T4 acceptance tests (Annex C 4.3, 4.3b).

Brief acceptance criteria:
- only the token hash is stored (never the raw token)
- a new login can set revoked_at on a prior session

Plus: session_request state CHECK and a pending -> granted transition.
"""

import hashlib
from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.operators.models import (
    Operator,
    OperatorSession,
    SessionRequest,
    SessionRequestState,
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
def viewer(db):
    return Operator.objects.create(
        username="viewer",
        display_name="Viewer",
        role=Operator.Role.VIEWER,
        password_hash="placeholder",
    )


def _session(operator, ip="127.0.0.1"):
    raw_token = "super-secret-session-token"
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return (
        OperatorSession.objects.create(operator=operator, token_hash=token_hash, ip=ip),
        raw_token,
        token_hash,
    )


# --- only the token hash is stored ----------------------------------------


def test_session_model_has_no_raw_token_column():
    field_names = {f.name for f in OperatorSession._meta.get_fields()}
    assert "token_hash" in field_names
    # There must be no column that could hold the raw token.
    assert "token" not in field_names
    assert "session_token" not in field_names


@pytest.mark.django_db
def test_only_token_hash_persisted(operator):
    session, raw_token, token_hash = _session(operator)
    session.refresh_from_db()
    assert session.token_hash == token_hash
    # The stored value is the hash, not the token.
    assert session.token_hash != raw_token


# --- a new login revokes a prior session ----------------------------------


@pytest.mark.django_db
def test_new_login_revokes_prior_session(operator):
    first, _, _ = _session(operator)
    assert first.is_active
    assert first.revoked_at is None

    # A new privileged login arrives: revoke the prior session, create a new one.
    first.revoke()
    second, _, _ = _session(operator, ip="127.0.0.2")

    first.refresh_from_db()
    assert first.revoked_at is not None
    assert not first.is_active
    # The revoked row is not deleted (history preserved).
    assert OperatorSession.objects.filter(pk=first.pk).exists()
    assert second.is_active


@pytest.mark.django_db
def test_touch_updates_last_activity(operator):
    session, _, _ = _session(operator)
    original = session.last_activity_at
    later = original + timedelta(minutes=5)
    session.touch(when=later)
    session.refresh_from_db()
    assert session.last_activity_at == later


# --- session_request state machine ----------------------------------------


@pytest.mark.django_db
def test_session_request_invalid_state_rejected(operator):
    session, _, _ = _session(operator)
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            SessionRequest.objects.create(
                requested_by=operator,
                current_session=session,
                state="bogus",
                expires_at=timezone.now() + timedelta(minutes=2),
            )


@pytest.mark.django_db
def test_session_request_pending_to_granted(operator, viewer):
    session, _, _ = _session(operator)
    req = SessionRequest.objects.create(
        requested_by=viewer,
        current_session=session,
        expires_at=timezone.now() + timedelta(minutes=2),
    )
    assert req.state == SessionRequestState.PENDING

    req.state = SessionRequestState.GRANTED
    req.resolved_at = timezone.now()
    req.resolved_by = operator
    req.save()

    req.refresh_from_db()
    assert req.state == SessionRequestState.GRANTED
    assert req.resolved_by_id == operator.id
