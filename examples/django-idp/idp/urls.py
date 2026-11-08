from django.urls import path

from . import views, slo

app_name = "idp"

urlpatterns = [
    path("", views.index, name="index"),
    path("metadata", views.metadata, name="metadata"),
    path("sso/", views.sso, name="sso"),
    path("error", views.error, name="error"),
    path("login/", views.login_view, name="login"),
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("logout/", slo.local_logout, name="logout"),
    path("slo/", slo.service, name="slo"),
    path("logout/status/", slo.status, name="logout_status"),
]
