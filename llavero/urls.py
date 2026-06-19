"""URL configuration for llavero project."""

from django.http import HttpResponse
from django.urls import include, path


def health(request):
    return HttpResponse("ok", content_type="text/plain")


urlpatterns = [
    path("health/", health, name="health"),
    path("auth/", include("apps.operators.urls")),
    # Alerts dashboard at root (P6-T5); also exposes /alerts/settings/
    path("", include("apps.alerts.urls")),
    path("inventory/", include("apps.inventory.urls")),
    path("relationships/", include("apps.relationships.urls")),
    path("vault/", include("apps.vault.urls")),
    path("integrations/", include("apps.integrations.urls")),
]
