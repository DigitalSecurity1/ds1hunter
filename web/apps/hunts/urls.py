"""
DS1 Hunter - Hunts App URL Configuration
DigitalSecurity1 - "Hunt. Chain. Prove."
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AuthConfigViewSet, HuntViewSet, VulnDocsView,
    VulnerabilityUpdateView, HuntVerifyFindingView,
    SpiderListView, SpiderDetailView, SpiderClearView, SpiderExportView,
    GraphQLListView, GraphQLDetailView,
    MobileProcessListView, MobileProcessDetailView,
    MobileDeviceView, MobileDeviceAnalysisDetailView,
)

router = DefaultRouter()
router.register(r"", HuntViewSet, basename="hunt")

auth_router = DefaultRouter()
auth_router.register(r"", AuthConfigViewSet, basename="authconfig")

urlpatterns = [
    # Specific paths MUST come before include(router.urls).
    # The DRF DefaultRouter registered on "" generates a detail pattern
    # "^(?P<pk>[^/.]+)/$" that greedily matches anything - "spider/",
    # "graphql/", etc. - before Django ever reaches the views below.
    path("spider/",                              SpiderListView.as_view()),
    path("spider/clear/",                        SpiderClearView.as_view()),
    path("spider/<str:session_id>/export/",      SpiderExportView.as_view()),
    path("spider/<str:session_id>/",             SpiderDetailView.as_view()),
    path("graphql/",                  GraphQLListView.as_view()),
    path("graphql/<str:session_id>/", GraphQLDetailView.as_view()),
    path("mobile/processes/",                      MobileProcessListView.as_view()),
    path("mobile/processes/<str:process_id>/",     MobileProcessDetailView.as_view()),
    path("mobile/device/",                         MobileDeviceView.as_view()),
    path("mobile/device/<str:session_id>/",        MobileDeviceAnalysisDetailView.as_view()),
    path("<uuid:hunt_id>/vulnerabilities/<uuid:vuln_id>/", VulnerabilityUpdateView.as_view()),
    path("<uuid:hunt_id>/verify-finding/",                HuntVerifyFindingView.as_view()),
    path("", include(router.urls)),
]
