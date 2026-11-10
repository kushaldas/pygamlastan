"""Explicit worker execution for recovery tests; HTTP requests never send mail."""
from idp.recovery import process_recovery_request


def drain_recovery_queue():
    """Process available jobs synchronously after the HTTP response under test."""
    processed = 0
    while process_recovery_request():
        processed += 1
    return processed
