"""Typing shims matching ``saml2.typing``."""

from collections.abc import Mapping
from typing import Any

# pysaml2 returns an "http_info" dict from prepare_for_authenticate / apply
# binding. Callers read ``http_info["headers"]`` (a list of (name, value) pairs,
# with a ("Location", url) entry for the redirect binding). We model it loosely
# as a string-keyed mapping, exactly as pysaml2's own typing does.
SAMLHttpArgs = Mapping[str, Any]
