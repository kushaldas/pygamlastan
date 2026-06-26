from django.urls import path

from . import views

app_name = "sp"

urlpatterns = [
    path("", views.index, name="index"),
    path("metadata", views.metadata, name="metadata"),
    path("login/", views.login_view, name="login"),
    path("disco/", views.disco, name="disco"),
    path("acs/", views.acs, name="acs"),
    path("logout/", views.logout_view, name="logout"),
]
