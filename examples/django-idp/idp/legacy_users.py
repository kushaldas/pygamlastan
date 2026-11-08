"""Explicit profile import; legacy credentials and privilege flags are ignored."""
import json

from django.core.exceptions import ValidationError

from .accounts import prepare_user


FIELDS = {
    "username": ("username", "name"),
    "email": ("email", "mail"),
    "display_name": ("display_name", "common_name", "displayName", "cn"),
    "first_name": ("given_name", "givenName", "first_name"),
    "last_name": ("surname", "family_name", "last_name", "sn"),
    "scoped_affiliation": ("scoped_affiliation", "eduPersonScopedAffiliation"),
}


def prepare_import(text):
    records = json.loads(text)
    if isinstance(records, dict):
        records = records.get("users")
    if not isinstance(records, list):
        raise ValidationError('Expected an array of users or an object containing a "users" array.')
    prepared, seen = [], set()
    for number, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise ValidationError(f"Record {number}: expected a user object.")
        values = {}
        for field, aliases in FIELDS.items():
            supplied = [record[key] for key in aliases if key in record]
            if any(not isinstance(value, str) for value in supplied):
                raise ValidationError(f"Record {number}: {field} must be a string.")
            if len(set(supplied)) > 1:
                raise ValidationError(f"Record {number}: conflicting aliases for {field}.")
            values[field] = supplied[0] if supplied else ""
        if not values["username"] or not values["email"]:
            raise ValidationError(f"Record {number}: username/name and email are required.")
        try:
            item = prepare_user(**values, groups=record.get("groups", []))
        except ValidationError as exc:
            raise ValidationError([f"Record {number}: {message}" for message in exc.messages]) from exc
        identifiers = {item[0].username, item[0].email}
        if seen & identifiers:
            raise ValidationError(f"Record {number}: duplicate or ambiguous username/email in import.")
        seen.update(identifiers)
        prepared.append(item)
    return prepared
