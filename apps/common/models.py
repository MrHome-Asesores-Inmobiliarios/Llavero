"""Shared abstract base models (Annex C 1, 2).

Design principles enforced here:
- Primary keys are UUID v4 (non-enumerable).
- All timestamps are timestamptz (USE_TZ=True) in UTC.
- created_by / updated_by always reference Operator, never Person.
- on_delete=PROTECT everywhere: the model layer never hard-deletes
  (Annex C 1 "no hard deletes"); lifecycle is expressed via ``state``.

Note: ``state`` is part of the common field set in Annex C 2 but its enum
differs per entity, so each concrete entity declares its own ``state`` field
with a per-entity TextChoices + CHECK constraint.
"""

import uuid

from django.db import models
from django.utils import timezone


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class TimestampedModel(UUIDModel):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class AuditedModel(TimestampedModel):
    """UUID PK + timestamps + audit authorship.

    ``related_name="+"`` disables the reverse accessor so the same FK can be
    inherited by many concrete models without reverse-name clashes.
    """

    created_by = models.ForeignKey(
        "operators.Operator",
        on_delete=models.PROTECT,
        related_name="+",
        editable=False,
    )
    updated_by = models.ForeignKey(
        "operators.Operator",
        on_delete=models.PROTECT,
        related_name="+",
    )

    class Meta:
        abstract = True


class BaseEntity(AuditedModel):
    """Full base mixin for the four core inventory entities
    (Person, Account, Device, Office) per Annex C 2."""

    notes = models.TextField(blank=True, default="")
    custom_fields = models.JSONField(default=dict)

    class Meta:
        abstract = True


class LinkState(models.TextChoices):
    ACTIVE = "active", "Active"
    FORMER = "former", "Former"


def link_state_check(name):
    """Return a CHECK constraint restricting ``state`` to LinkState values.

    Each concrete join table needs its own uniquely-named constraint, so this
    helper keeps the nine declarations DRY while names stay distinct.
    """
    return models.CheckConstraint(
        condition=models.Q(state__in=LinkState.values),
        name=name,
    )


class LinkBase(AuditedModel):
    """Shared base for the relationship join tables (Annex C 5).

    Carries the lighter shared set: id + state (link_state) + valid_from +
    valid_to + the four audit columns. Ending a relationship sets
    ``state=former`` and ``valid_to`` and never deletes the row, preserving
    history for the audit chain.
    """

    state = models.TextField(choices=LinkState.choices, default=LinkState.ACTIVE)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_to = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True

    def end(self, *, by, when=None):
        """End this link without deleting it (Annex C 5)."""
        self.state = LinkState.FORMER
        self.valid_to = when or timezone.now()
        self.updated_by = by
        self.save(update_fields=["state", "valid_to", "updated_by", "updated_at"])
