pygamlastan.bindings
====================

.. py:module:: pygamlastan.bindings

HTTP-Redirect, HTTP-POST, and Artifact encode/decode over plain Python data.
See the :doc:`../guides/bindings` guide. Errors raise
:class:`pygamlastan.SamlBindingError`.

.. py:data:: RELAY_STATE_MAX_BYTES
   :type: int

   The SAML limit on RelayState size (80 bytes).

Redirect
--------

.. py:function:: redirect_encode(saml_xml: bytes, is_request: bool, destination: str, relay_state: str | None = None, signer=None, sig_alg: str | None = None) -> str

   Build a HTTP-Redirect URL carrying ``saml_xml``. ``is_request`` selects
   ``SAMLRequest`` vs ``SAMLResponse``. Provide ``signer``
   (:class:`pygamlastan.crypto.SamlSigner`) and ``sig_alg`` to sign the query.

.. py:function:: redirect_decode(query: str, base_url: str = "") -> RedirectDecoded

   Decode a redirect from its **raw** (still URL-encoded) query string. Do not
   URL-decode it first. ``base_url`` is the request URL without the query, used
   only for signature-input reconstruction.

.. py:class:: RedirectDecoded

   ``saml_xml`` (bytes), ``saml_text`` (str), ``is_request`` (bool),
   ``relay_state``, ``sig_alg``, ``signature`` (bytes | None),
   ``signature_input``.

POST
----

.. py:function:: post_encode(saml_xml: bytes, is_request: bool, destination: str, relay_state: str | None = None) -> str

   Build a self-submitting HTML form for the HTTP-POST binding.

.. py:function:: post_decode(form_params: dict[str, str], url: str = "") -> PostDecoded

   Decode from already form-decoded POST parameters.

.. py:class:: PostDecoded

   ``saml_xml`` (bytes), ``saml_text`` (str), ``is_request`` (bool),
   ``relay_state``.

RelayState
----------

.. py:function:: validate_relay_state(value: str) -> None

   Raise :class:`pygamlastan.SamlBindingError` if ``value`` exceeds the size
   limit or is unsafe.

Artifact
--------

.. py:class:: SamlArtifact(endpoint_index: int, entity_id: str, random_handle: bytes)

   A type ``0x0004`` SAML artifact. ``random_handle`` is 20 bytes.

   .. py:staticmethod:: decode(encoded: str) -> SamlArtifact
   .. py:method:: encode() -> str
   .. py:method:: matches_entity(entity_id: str) -> bool
   .. py:attribute:: endpoint_index
      :type: int
   .. py:attribute:: source_id
      :type: bytes
   .. py:attribute:: message_handle
      :type: bytes
