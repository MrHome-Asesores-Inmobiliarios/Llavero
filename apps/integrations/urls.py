"""URL routing for the integrations dashboard (P5-T5)."""

from django.urls import path

from apps.integrations import views

app_name = "integrations"

urlpatterns = [
    path("", views.integration_list, name="list"),
    path("new/", views.integration_create, name="create"),
    path("<uuid:pk>/", views.integration_detail, name="detail"),
    path("<uuid:pk>/edit/", views.integration_edit, name="edit"),
    path("<uuid:pk>/toggle/", views.integration_toggle, name="toggle"),
    path("<uuid:pk>/run/", views.integration_run, name="run"),
]
