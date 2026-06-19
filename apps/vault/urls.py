"""Vault URL configuration (P4)."""

from django.urls import path

from apps.vault import views

urlpatterns = [
    path("", views.SecretListView.as_view(), name="secret-list"),
    path("new/", views.SecretCreateView.as_view(), name="secret-create"),
    path("stepup/", views.StepUpView.as_view(), name="vault-stepup"),
    path("<uuid:pk>/", views.SecretDetailView.as_view(), name="secret-detail"),
    path("<uuid:pk>/edit/", views.SecretEditView.as_view(), name="secret-edit"),
    path("<uuid:pk>/reveal/", views.SecretRevealView.as_view(), name="secret-reveal"),
    path("<uuid:pk>/rotate/", views.SecretRotateView.as_view(), name="secret-rotate"),
    path("<uuid:pk>/state/", views.SecretStateChangeView.as_view(), name="secret-state"),
]
