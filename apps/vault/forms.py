"""Vault forms — secret create/edit metadata (P4-T1).

The plaintext field is a PasswordInput: it is never re-displayed or logged.
The form never touches the cipher side; that is crypto.seal()'s job.
"""

from django import forms

from apps.vault.models import SecretKind


class SecretForm(forms.Form):
    """Create or update secret metadata + plaintext.

    ``owner_type`` and ``owner_id`` are set from the URL, not submitted by the
    user, so they are not included here (to avoid parameter-tampering attacks).
    The view validates and passes them explicitly.
    """

    kind = forms.ChoiceField(
        choices=SecretKind.choices,
        label="Kind",
    )
    label = forms.CharField(
        required=False,
        max_length=255,
        label="Label",
        help_text="Optional short description (e.g. 'O365 admin')",
    )
    plaintext = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="Secret value",
        strip=False,
    )

    def clean_plaintext(self):
        value = self.cleaned_data.get("plaintext", "")
        if not value:
            raise forms.ValidationError("Secret value must not be empty.")
        return value.encode("utf-8")


class SecretMetadataForm(forms.Form):
    """Edit non-secret metadata only (label). Used by the edit view.

    No plaintext field — metadata changes don't touch the ciphertext.
    """

    label = forms.CharField(
        required=False,
        max_length=255,
        label="Label",
    )


class SecretStateForm(forms.Form):
    """Archive / restore a secret."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    STATE_CHOICES = [
        (ACTIVE, "Active"),
        (ARCHIVED, "Archived"),
    ]
    new_state = forms.ChoiceField(choices=STATE_CHOICES, label="State")


class RevealReasonForm(forms.Form):
    """The reason a secret is being revealed — logged, but the plaintext is not."""

    reason = forms.CharField(
        required=False,
        max_length=500,
        label="Reason for reveal",
        help_text="Optional — recorded in the audit log.",
    )


class RotateConfirmForm(forms.Form):
    """New plaintext for a rotation (replaces ciphertext, logs secret_rotate)."""

    new_plaintext = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="New secret value",
        strip=False,
    )

    def clean_new_plaintext(self):
        value = self.cleaned_data.get("new_plaintext", "")
        if not value:
            raise forms.ValidationError("New secret value must not be empty.")
        return value.encode("utf-8")
