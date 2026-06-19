"""Forms for the alerts app (P6-T5, P6-T7)."""

from django import forms

from apps.alerts.models import AlertSetting


class AcknowledgeAlertForm(forms.Form):
    """Acknowledge an alert with a mandatory note (P6-T5)."""

    note = forms.CharField(
        label="Nota de reconocimiento",
        widget=forms.Textarea(attrs={"rows": 3}),
        min_length=5,
        error_messages={"min_length": "La nota debe tener al menos 5 caracteres."},
    )


class AlertSettingForm(forms.ModelForm):
    """Edit a single AlertSetting row (P6-T7)."""

    class Meta:
        model = AlertSetting
        fields = ["enabled", "threshold_json"]
        widgets = {
            "threshold_json": forms.Textarea(attrs={"rows": 4}),
        }

    def clean_threshold_json(self):
        import json

        value = self.cleaned_data["threshold_json"]
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise forms.ValidationError(f"JSON inválido: {exc}") from exc
        return value
