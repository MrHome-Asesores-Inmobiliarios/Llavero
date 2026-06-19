"""Forms for the integrations dashboard (P5-T5)."""

from django import forms

from apps.integrations.models import Integration
from apps.vault.models import Secret, SecretOwnerType


class IntegrationForm(forms.ModelForm):
    """Create/edit an Integration row.

    Credential is chosen from a dropdown of existing vault Secrets whose
    owner_type is 'integration'. The dropdown shows label + kind, never
    the secret plaintext.
    """

    class Meta:
        model = Integration
        fields = [
            "name",
            "integration_type",
            "enabled",
            "run_interval_minutes",
            "credential",
            "config",
        ]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control"}),
            "integration_type": forms.Select(attrs={"class": "form-control"}),
            "run_interval_minutes": forms.NumberInput(attrs={"class": "form-control", "min": 1}),
            "config": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 6,
                    "placeholder": '{"tenant_id": "...", "client_id": "..."}',
                }
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Credential queryset: active secrets with owner_type = integration
        self.fields["credential"].queryset = Secret.objects.filter(
            owner_type=SecretOwnerType.INTEGRATION,
            state="active",
        ).order_by("label", "kind")
        self.fields["credential"].required = False
        self.fields["credential"].empty_label = "— sin credencial —"

    def clean_config(self):
        """Validate that config is valid JSON (stored as a dict)."""
        import json

        value = self.cleaned_data.get("config")
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if not isinstance(parsed, dict):
                    raise forms.ValidationError("Config debe ser un objeto JSON.")
                return parsed
            except (json.JSONDecodeError, ValueError) as exc:
                raise forms.ValidationError(f"JSON inválido: {exc}") from exc
        return value or {}


class IntegrationToggleForm(forms.Form):
    """Simple enable/disable toggle for an integration."""

    enabled = forms.BooleanField(required=False)
