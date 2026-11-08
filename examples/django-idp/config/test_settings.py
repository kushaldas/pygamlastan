"""Isolated, on-disk SQLite tests, including competing writer connections."""
import tempfile
from pathlib import Path

from .settings import *  # noqa: F403

_test_directory = tempfile.TemporaryDirectory(prefix="django-idp-tests-")
DATABASES["default"]["TEST"] = {"NAME": str(Path(_test_directory.name) / "db.sqlite3")}  # noqa: F405
STATIC_ROOT = str(Path(_test_directory.name) / "static")
Path(STATIC_ROOT).mkdir()
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
