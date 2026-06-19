"""Inventory URL configuration (Phase 3)."""

from django.urls import path

from apps.inventory import views

urlpatterns = [
    # Person
    path("persons/", views.PersonListView.as_view(), name="person-list"),
    path("persons/new/", views.PersonCreateView.as_view(), name="person-create"),
    path("persons/<uuid:pk>/", views.PersonDetailView.as_view(), name="person-detail"),
    path("persons/<uuid:pk>/edit/", views.PersonEditView.as_view(), name="person-edit"),
    path(
        "persons/<uuid:pk>/transition/",
        views.StateTransitionView.as_view(),
        {"model": "person"},
        name="person-transition",
    ),
    # Account
    path("accounts/", views.AccountListView.as_view(), name="account-list"),
    path("accounts/new/", views.AccountCreateView.as_view(), name="account-create"),
    path("accounts/<uuid:pk>/", views.AccountDetailView.as_view(), name="account-detail"),
    path("accounts/<uuid:pk>/edit/", views.AccountEditView.as_view(), name="account-edit"),
    path(
        "accounts/<uuid:pk>/transition/",
        views.StateTransitionView.as_view(),
        {"model": "account"},
        name="account-transition",
    ),
    # Device
    path("devices/", views.DeviceListView.as_view(), name="device-list"),
    path("devices/new/", views.DeviceCreateView.as_view(), name="device-create"),
    path("devices/<uuid:pk>/", views.DeviceDetailView.as_view(), name="device-detail"),
    path("devices/<uuid:pk>/edit/", views.DeviceEditView.as_view(), name="device-edit"),
    path(
        "devices/<uuid:pk>/transition/",
        views.StateTransitionView.as_view(),
        {"model": "device"},
        name="device-transition",
    ),
    # Office
    path("offices/", views.OfficeListView.as_view(), name="office-list"),
    path("offices/new/", views.OfficeCreateView.as_view(), name="office-create"),
    path("offices/<uuid:pk>/", views.OfficeDetailView.as_view(), name="office-detail"),
    path("offices/<uuid:pk>/edit/", views.OfficeEditView.as_view(), name="office-edit"),
    path(
        "offices/<uuid:pk>/transition/",
        views.StateTransitionView.as_view(),
        {"model": "office"},
        name="office-transition",
    ),
    # FieldDefinition
    path(
        "field-definitions/", views.FieldDefinitionListView.as_view(), name="fielddefinition-list"
    ),
    path(
        "field-definitions/new/",
        views.FieldDefinitionCreateView.as_view(),
        name="fielddefinition-create",
    ),
    path(
        "field-definitions/<uuid:pk>/edit/",
        views.FieldDefinitionEditView.as_view(),
        name="fielddefinition-edit",
    ),
]
