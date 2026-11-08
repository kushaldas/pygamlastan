from django.urls import include, path

urlpatterns = [path("idp/", include("idp.urls")), path("sp/", include("sp.urls"))]
