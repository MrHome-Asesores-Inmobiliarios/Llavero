"""Operator auth URL configuration."""

from django.urls import path

from apps.operators import views

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("vault/install/", views.VaultInstallView.as_view(), name="vault-install"),
    path("vault/passphrase/", views.VaultPassphraseView.as_view(), name="vault-passphrase"),
    path("logout/", views.logout_view, name="logout"),
]
