from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path("idp/", include("idp.urls")),
    path("", RedirectView.as_view(pattern_name="idp:index", permanent=False)),
]
