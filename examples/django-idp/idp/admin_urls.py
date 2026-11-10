from django.urls import path

from . import admin_views

app_name = "idp_admin"

urlpatterns = [
    path("", admin_views.user_list, name="users"),
    path("blocked-emails/", admin_views.blocked_emails, name="blocked_emails"),
    path("blocked-emails/<int:pk>/remove/", admin_views.blocked_email_remove,
         name="blocked_email_remove"),
    path("users/new/", admin_views.user_edit, name="user_create"),
    path("users/<int:pk>/", admin_views.user_edit, name="user_edit"),
    path("users/<int:pk>/reset-password/", admin_views.user_action,
         {"action": "reset"}, name="user_reset"),
    path("users/<int:pk>/delete/", admin_views.user_action,
         {"action": "delete"}, name="user_delete"),
]
