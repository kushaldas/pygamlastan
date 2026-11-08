"""Durable SAML logout associations, correlation and replay protection."""
from django.db import models


class SamlLogin(models.Model):
    session_key = models.CharField(max_length=40, db_index=True)
    issuer = models.TextField()
    name_id = models.JSONField()
    session_index = models.CharField(max_length=128, null=True, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    ended = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(
            fields=["session_key"], condition=models.Q(ended=False),
            name="sp_one_active_login_per_session",
        )]


class LogoutTransaction(models.Model):
    token = models.CharField(max_length=64, primary_key=True)
    issuer = models.TextField()
    request_id = models.CharField(max_length=128)
    expires_at = models.DateTimeField(db_index=True)


class LogoutReplay(models.Model):
    digest = models.CharField(max_length=64, primary_key=True)
    expires_at = models.DateTimeField(db_index=True)
