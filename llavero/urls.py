"""
URL configuration for llavero project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.http import HttpResponse
from django.urls import include, path


def health(request):
    return HttpResponse("ok", content_type="text/plain")


urlpatterns = [
    path("health/", health, name="health"),
    # Alerts dashboard at root (P6-T5); also exposes /alerts/settings/
    path("", include("apps.alerts.urls")),
    path("inventory/", include("apps.inventory.urls")),
    path("relationships/", include("apps.relationships.urls")),
    path("vault/", include("apps.vault.urls")),
    path("integrations/", include("apps.integrations.urls")),
]
