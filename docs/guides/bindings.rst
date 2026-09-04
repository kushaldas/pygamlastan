Protocol bindings
=================

The :doc:`../api/bindings` module encodes and decodes SAML messages for the
HTTP-Redirect, HTTP-POST, and Artifact bindings. The functions work on plain
Python data (bytes, strings, and name/value pairs), so they fit any web framework: you do the
HTTP I/O, pygamlastan does the SAML encoding.

HTTP-Redirect
-------------

Encode a message into a redirect URL (DEFLATE + base64 + URL-encoding), then
issue a 302:

.. code-block:: python

   from pygamlastan import bindings

   url = bindings.redirect_encode(
       message_xml.encode(),
       is_request=True,                       # SAMLRequest vs SAMLResponse
       destination="https://idp.example.org/sso",
       relay_state="opaque-state",
   )

To decode, pass the **raw** query string exactly as received. Do not URL-decode
it first: gamlastan decodes internally, and for signed redirects the signature
is computed over the raw encoded parameters.

.. code-block:: python

   from urllib.parse import urlparse

   query = urlparse(request_url).query          # "SAMLRequest=...&RelayState=..."
   decoded = bindings.redirect_decode(query)
   decoded.is_request        # bool
   decoded.saml_xml          # the message bytes - parse/verify THESE
   decoded.saml_text         # lossy text projection (invalid UTF-8 becomes
                             # U+FFFD): display/logging only, never security
   decoded.relay_state       # echoed RelayState
   decoded.sig_alg           # signature algorithm, if signed
   decoded.signature         # raw signature bytes, if signed

Signed redirects
~~~~~~~~~~~~~~~~~

Pass a signer and algorithm URI to sign the outgoing query, and verify an
incoming one with the detached-signature verifier:

.. code-block:: python

   url = bindings.redirect_encode(
       message_xml.encode(), is_request=True,
       destination="https://idp.example.org/sso",
       relay_state="state",
       signer=saml_signer,
       sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
   )

HTTP-POST
---------

Encode a self-submitting HTML form; render it in the browser to auto-post:

.. code-block:: python

   html = bindings.post_encode(
       message_xml.encode(), is_request=False,
       destination="https://sp.example.org/acs",
       relay_state="state",
   )

Decode from duplicate-preserving, already form-decoded POST parameters (POST
fields are plain base64, not DEFLATE-compressed):

.. code-block:: python

   decoded = bindings.post_decode([
       ("SAMLResponse", form["SAMLResponse"]),
       ("RelayState", form.get("RelayState", "")),
   ])

RelayState
----------

RelayState is limited to 80 bytes by the SAML profile. Validate it before use:

.. code-block:: python

   bindings.validate_relay_state(value)   # raises SamlBindingError if too long/unsafe

Artifact
--------

:class:`pygamlastan.bindings.SamlArtifact` builds and parses type ``0x0004``
artifacts. Prefer :meth:`~pygamlastan.bindings.SamlArtifact.generate`, which
uses Python's operating-system-backed ``secrets`` generator for the 20-byte
message handle:

.. code-block:: python

   artifact = bindings.SamlArtifact.generate(0, "https://idp.example.org")
   token = artifact.encode()                 # base64 to put in the URL

   decoded = bindings.SamlArtifact.decode(token)
   decoded.matches_entity("https://idp.example.org")   # True

The artifact identifies its source, but an artifact-resolution service must
also bind the stored message to the SP for which it was issued. Gamlastan 0.9's
:class:`pygamlastan.bindings.ArtifactStoreProtocol` makes that ownership check
explicit:

.. code-block:: python

   from threading import Lock

   class ArtifactStore:
       def __init__(self):
           self._messages: dict[str, tuple[str, bytes]] = {}
           self._lock = Lock()

       def store_for_recipient(
           self, artifact: str, recipient_entity_id: str, message_xml: bytes
       ) -> None:
           with self._lock:
               self._messages[artifact] = (recipient_entity_id, message_xml)

       def resolve_and_consume_for_requester(
           self, artifact: str, requester_entity_id: str
       ) -> bytes | None:
           with self._lock:
               stored = self._messages.get(artifact)
               if stored is None or stored[0] != requester_entity_id:
                   return None       # a mismatch must not consume another SP's message
               return self._messages.pop(artifact)[1]

       # Legacy unbound operations, if older integration code still needs them.
       def store(self, artifact: str, message_xml: bytes) -> None:
           raise NotImplementedError("recipient_entity_id is required")

       def resolve_and_consume(self, artifact: str) -> bytes | None:
           raise NotImplementedError("requester_entity_id is required")

The protocol is structural: no base class is required. Production stores
should make the requester comparison and one-time consumption atomic in a
shared database or cache. In particular, do not remove a message when the
authenticated requester does not match its ``recipient_entity_id``; the real
recipient must still be able to resolve it later.
