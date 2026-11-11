from django.urls import path
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetCompleteView
from django.views.decorators.cache import never_cache

from . import views, slo
from .recovery import RecoveryView, RecoveryConfirmView

app_name = "idp"

urlpatterns = [
    path("", views.index, name="index"),
    path("metadata", views.metadata, name="metadata"),
    path("sso/", views.sso, name="sso"),
    path("error", views.error, name="error"),
    path("login/", views.login_view, name="login"),
    path("password-reset/", RecoveryView.as_view(), name="password_reset"),
    path("password-reset/sent/", never_cache(PasswordResetDoneView.as_view(
        template_name="idp/password_reset_done.html")), name="password_reset_done"),
    path("password-reset/complete/", never_cache(PasswordResetCompleteView.as_view(
        template_name="idp/password_reset_complete.html")), name="password_reset_complete"),
    path("password-reset/<uidb64>/<token>/", RecoveryConfirmView.as_view(),
         name="password_reset_confirm"),
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("logout/", slo.local_logout, name="logout"),
    path("slo/", slo.service, name="slo"),
    path("logout/status/", slo.status, name="logout_status"),
]
