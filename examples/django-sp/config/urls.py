from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path("sp/", include("sp.urls")),
    path("", RedirectView.as_view(pattern_name="sp:index", permanent=False)),
]
