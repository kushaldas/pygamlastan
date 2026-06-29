"""``saml2.server`` placeholder.

The IdP-side adapter is Phase 2 of the eduID migration. SP code imports
``from saml2 import server`` at module load time (via shared ``utils``), so this
module must exist and import cleanly, but constructing a ``Server`` is not yet
supported here.
"""

from __future__ import annotations

from typing import Any


class Server:
    """Not implemented yet - the IdP adapter lands in Phase 2."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "pygamlastan.compat.saml2.server.Server is not implemented yet "
            "(IdP adapter is Phase 2 of the eduID migration)"
        )
