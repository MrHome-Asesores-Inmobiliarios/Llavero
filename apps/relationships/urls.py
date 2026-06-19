"""Relationships URL configuration (Phase 3)."""

from django.urls import path

from apps.relationships import views

urlpatterns = [
    path("links/create/", views.LinkCreateView.as_view(), name="link-create"),
    path("links/<uuid:pk>/end/", views.LinkEndView.as_view(), name="link-end"),
]
