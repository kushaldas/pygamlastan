"""Account identity and invariants shared by HTTP and management commands."""
import unicodedata
import uuid

from django.contrib.auth.models import AbstractUser, UserManager as DjangoUserManager
from django.core.exceptions import ValidationError
from django.db import models, router, transaction
from django.db.models import Q
from django.db.models.functions import Lower


def normalize_identifier(value):
    return unicodedata.normalize("NFKC", value).strip().casefold()


class UserManager(DjangoUserManager):
    @classmethod
    def normalize_email(cls, email):
        return normalize_identifier(email or "")


class User(AbstractUser):
    identity = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=255, blank=True)
    scoped_affiliation = models.CharField(max_length=255, blank=True)

    objects = UserManager()
    REQUIRED_FIELDS = ["email"]

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower("username"), name="idp_username_ci_unique"),
            models.UniqueConstraint(Lower("email"), name="idp_email_ci_unique"),
        ]

    def clean(self):
        super().clean()
        self.username = normalize_identifier(self.username)
        self.email = normalize_identifier(self.email)
        using = self._state.db or router.db_for_write(type(self), instance=self)
        others = type(self).objects.using(using).exclude(pk=self.pk)
        identifiers = (self.username, self.email)
        if others.filter(Q(username__in=identifiers) | Q(email__in=identifiers)).exists():
            raise ValidationError("Username or email is already used by another account.")

    def _protect_existing(self, using, *, deleting=False):
        old = type(self).objects.using(using).filter(pk=self.pk).first()
        if old is None:
            return
        if self.identity != old.identity:
            raise ValidationError("An account's identity UUID cannot be changed.")
        if old.is_active and old.is_staff and (
            deleting or not self.is_active or not self.is_staff
        ):
            if not type(self).objects.using(using).filter(
                is_active=True, is_staff=True
            ).exclude(pk=self.pk).exists():
                raise ValidationError("The final active administrator must be retained.")

    def save(self, *args, **kwargs):
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        # IMMEDIATE mode acquires SQLite's write lock before reading invariants.
        # select_for_update() alone provides no protection on SQLite.
        with transaction.atomic(using=using):
            self._protect_existing(using)
            # Normalize before field validators and uniqueness checks run.
            self.username = normalize_identifier(self.username)
            self.email = normalize_identifier(self.email)
            self.full_clean()
            return super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        using = using or router.db_for_write(type(self), instance=self)
        with transaction.atomic(using=using):
            self._protect_existing(using, deleting=True)
            return super().delete(using=using, keep_parents=keep_parents)


class SamlParticipant(models.Model):
    """Exact subject/session issued to one SP, tied to one browser session."""
    session_key = models.CharField(max_length=40, db_index=True)
    entity_id = models.TextField()
    name_id = models.JSONField()
    session_index = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField(db_index=True)


class LogoutReplay(models.Model):
    digest = models.CharField(max_length=64, primary_key=True)
    expires_at = models.DateTimeField(db_index=True)


class RecoveryRateLimit(models.Model):
    """Shared recovery quotas; keys are HMACs rather than email/IP addresses."""
    key = models.CharField(max_length=64, primary_key=True)
    count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)


class BlockedRecoveryEmail(models.Model):
    """Addresses that must not receive password recovery messages."""
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["email"]

    def save(self, *args, **kwargs):
        self.email = normalize_identifier(self.email)
        self.full_clean()
        return super().save(*args, **kwargs)


class LogoutFlow(models.Model):
    token = models.CharField(max_length=64, primary_key=True)
    origin = models.JSONField(null=True)
    queue = models.JSONField(default=list)
    partial = models.BooleanField(default=False)
    expires_at = models.DateTimeField(db_index=True)
