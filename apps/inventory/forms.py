"""ModelForms for the core inventory entities (Annex C 4.4-4.10).

Notes:
- id, created_at, updated_at, created_by, updated_by are always excluded.
- state is excluded from create/edit forms; transitions go via StateTransitionView.
- custom_fields is excluded from forms; handled by view code.
- ArrayField columns (mfa_types, mac_addresses, ip_addresses) use plain text
  inputs with comma-splitting in clean().
"""

from django import forms

from apps.inventory.models import (
    Account,
    Device,
    FieldDefinition,
    MfaType,
    NetworkDeviceDetail,
    Office,
    Person,
)

_EXCLUDED_BASE = ["id", "created_at", "updated_at", "created_by", "updated_by", "custom_fields"]


class PersonForm(forms.ModelForm):
    class Meta:
        model = Person
        exclude = _EXCLUDED_BASE + ["state", "operator"]
        widgets = {
            "hire_date": forms.DateInput(attrs={"type": "date"}),
            "exit_date": forms.DateInput(attrs={"type": "date"}),
        }


class AccountForm(forms.ModelForm):
    """Account form with mfa_types as a comma-separated text field."""

    mfa_types_text = forms.CharField(
        required=False,
        label="MFA types",
        help_text=("Comma-separated list. Valid values: " + ", ".join(MfaType.values)),
    )

    class Meta:
        model = Account
        exclude = _EXCLUDED_BASE + ["state", "mfa_types"]
        widgets = {
            "last_password_change": forms.DateInput(attrs={"type": "date"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Populate mfa_types_text from existing instance
        if self.instance and self.instance.pk and self.instance.mfa_types:
            self.fields["mfa_types_text"].initial = ", ".join(self.instance.mfa_types)

    def clean_mfa_types_text(self):
        raw = self.cleaned_data.get("mfa_types_text", "")
        if not raw.strip():
            return None
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        valid = set(MfaType.values)
        bad = [p for p in parts if p not in valid]
        if bad:
            raise forms.ValidationError(
                f"Invalid MFA type(s): {', '.join(bad)}. Valid: {', '.join(valid)}"
            )
        return parts or None

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.mfa_types = self.cleaned_data.get("mfa_types_text")
        if commit:
            instance.save()
        return instance


class _ArrayTextMixin:
    """Mixin for forms with ArrayField columns stored as comma-separated text."""

    _array_fields = []  # list of (model_field_name, form_field_name)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for model_field, form_field in self._array_fields:
            val = (
                getattr(self.instance, model_field, None)
                if self.instance and self.instance.pk
                else None
            )
            if val:
                self.fields[form_field].initial = ", ".join(str(v) for v in val)

    def _clean_array_field(self, form_field_name):
        raw = self.cleaned_data.get(form_field_name, "")
        if not raw or not raw.strip():
            return None
        return [p.strip() for p in raw.split(",") if p.strip()] or None


class DeviceForm(_ArrayTextMixin, forms.ModelForm):
    _array_fields = [("mac_addresses", "mac_addresses_text"), ("ip_addresses", "ip_addresses_text")]

    mac_addresses_text = forms.CharField(
        required=False,
        label="MAC addresses",
        help_text="Comma-separated MAC addresses (e.g. AA:BB:CC:DD:EE:FF)",
    )
    ip_addresses_text = forms.CharField(
        required=False,
        label="IP addresses",
        help_text="Comma-separated IP addresses",
    )

    class Meta:
        model = Device
        exclude = _EXCLUDED_BASE + ["state", "mac_addresses", "ip_addresses"]
        widgets = {
            "purchase_date": forms.DateInput(attrs={"type": "date"}),
            "warranty_expiry": forms.DateInput(attrs={"type": "date"}),
        }

    def clean_mac_addresses_text(self):
        return self._clean_array_field("mac_addresses_text")

    def clean_ip_addresses_text(self):
        return self._clean_array_field("ip_addresses_text")

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.mac_addresses = self.cleaned_data.get("mac_addresses_text")
        instance.ip_addresses = self.cleaned_data.get("ip_addresses_text")
        if commit:
            instance.save()
        return instance


class NetworkDeviceDetailForm(forms.ModelForm):
    class Meta:
        model = NetworkDeviceDetail
        exclude = ["device"]
        widgets = {
            "last_firmware_update": forms.DateInput(attrs={"type": "date"}),
            "last_seen_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }


class OfficeForm(forms.ModelForm):
    class Meta:
        model = Office
        exclude = _EXCLUDED_BASE + ["state"]


class FieldDefinitionForm(forms.ModelForm):
    class Meta:
        model = FieldDefinition
        exclude = ["id"]
