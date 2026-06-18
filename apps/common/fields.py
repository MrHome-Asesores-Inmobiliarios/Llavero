"""Custom model fields that map to native PostgreSQL types."""

from django.db import models


class MACAddressField(models.Field):
    """A field backed by the native PostgreSQL ``macaddr`` type.

    Stored and returned as a string (psycopg renders ``macaddr`` as text).
    Used as the ``base_field`` of an ``ArrayField`` to produce ``macaddr[]``
    per Annex C 4.6 (device.mac_addresses).
    """

    description = "PostgreSQL macaddr"

    def db_type(self, connection):
        return "macaddr"
