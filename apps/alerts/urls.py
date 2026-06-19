"""URL patterns for the alerts app (P6-T5)."""

from django.urls import path

from apps.alerts import views

app_name = "alerts"

urlpatterns = [
    # Dashboard at root
    path("", views.dashboard, name="dashboard"),
    # Alert actions
    path("alerts/<uuid:alert_id>/acknowledge/", views.acknowledge_alert, name="acknowledge"),
    path("alerts/evaluate/", views.trigger_evaluate, name="evaluate"),
    # Settings
    path("alerts/settings/", views.settings_list, name="settings"),
    path("alerts/settings/<str:rule_id>/", views.settings_edit, name="settings-edit"),
]
