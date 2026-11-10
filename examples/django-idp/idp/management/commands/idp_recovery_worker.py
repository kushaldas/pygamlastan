"""Deliver queued recovery requests without blocking HTTP responses."""
import logging
import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from idp.recovery import process_recovery_request

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Run the SQLite recovery consumer, or drain the available queue once."""

    help = "Deliver queued recovery emails; --once drains currently available requests."

    def add_arguments(self, parser):
        """Expose a finite drain mode for local tests and manual operations."""
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        """Poll for jobs while keeping mail I/O outside database transactions."""
        while True:
            try:
                processed = process_recovery_request()
            except Exception:
                # Do not put addresses or reset tokens into the worker error log.
                logger.exception("Recovery queue processing failed")
                if options["once"]:
                    raise
                processed = False
            finally:
                close_old_connections()
            if not processed:
                if options["once"]:
                    return
                time.sleep(1)
