Migrating from pysaml2 (the ``saml2`` compatibility shim)
=========================================================

``pygamlastan.compat.saml2`` is a drop-in subset of the `pysaml2
<https://github.com/IdentityPython/pysaml2>`_ API, backed entirely by
pygamlastan. It exists so an existing pysaml2 **Service Provider** can move to
pygamlastan's memory-safe, ``xmlsec1``-free, XXE-hardened SAML stack by changing
import lines only, leaving the surrounding web-framework and session code
untouched.

The design rationale and the security mapping are recorded in ADR 0007
(``docs/adr/0007-pysaml2-compat-shim.md`` in the source tree). This guide is the
user-facing reference for what the shim provides and how to migrate onto it.

.. important::

   The shim is a faithful but **partial** facade: it implements the SP-side Web
   Browser SSO and Single Logout flow. The IdP ``server`` adapter, ECP/PAOS,
   artifact resolution, virtual organisations, and pysaml2's on-disk
   attribute-map files are not provided. See `What is and is not covered`_ before
   you migrate, and read the :doc:`security guide <security>` first - the shim
   routes attacker-controlled XML into authentication decisions just like the
   library it replaces.

What you gain
-------------

* **No ``xmlsec1`` subprocess and no ``pyXMLSecurity``.** Signing and signature
  verification happen in-process in Rust (via gamlastan/bergshamra). The
  ``saml2.sigver.get_xmlsec_binary`` shim returns ``None`` because there is no
  external binary to locate.
* **Hardened XML parsing by default.** Every untrusted document the shim parses
  (responses, logout messages, metadata) goes through gamlastan's
  ``parse_secure``: ``<!DOCTYPE>``/DTD rejection (closing the XXE / external- and
  internal-entity vectors) plus fail-closed resource limits. See
  :ref:`xml-hardening`.
* **The safe verify-internally entry point.** When signatures are required the
  shim verifies the XML-DSig over the exact received bytes and feeds only the
  cryptographically verified IDs into validation - it never trusts a "is this
  signed?" flag supplied by the caller.

Where it lives and how to import it
-----------------------------------

The shim ships inside the pygamlastan wheel, so installing pygamlastan is enough.
Migrate by repointing imports:

.. code-block:: python

   # before
   from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
   from saml2.client import Saml2Client
   from saml2.config import SPConfig
   from saml2.ident import code, decode
   from saml2.response import AuthnResponse, StatusError, UnsolicitedResponse
   from saml2.saml import NameID, Subject

   # after
   from pygamlastan.compat.saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
   from pygamlastan.compat.saml2.client import Saml2Client
   from pygamlastan.compat.saml2.config import SPConfig
   from pygamlastan.compat.saml2.ident import code, decode
   from pygamlastan.compat.saml2.response import AuthnResponse, StatusError, UnsolicitedResponse
   from pygamlastan.compat.saml2.saml import NameID, Subject

Module map
----------

The shim mirrors the pysaml2 module layout. Each module reproduces only the
names an SP consumer touches:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Module
     - What it provides
   * - ``pygamlastan.compat.saml2``
     - The binding-URI constants ``BINDING_HTTP_POST`` / ``BINDING_HTTP_REDIRECT``
       / ``BINDING_SOAP`` / ... (identical values to pysaml2).
   * - ``...saml2.client``
     - ``Saml2Client`` - the SP client (see `The SP flow`_).
   * - ``...saml2.config``
     - ``SPConfig().load(dict)`` over your existing ``saml2_settings.py``.
   * - ``...saml2.ident``
     - ``code`` / ``decode`` - a NameID to and from a session-storable string.
   * - ``...saml2.saml``
     - ``NameID`` / ``Subject`` value objects and the ``NAMEID_FORMAT_*`` /
       ``NAME_FORMAT_URI`` constants.
   * - ``...saml2.response``
     - ``AuthnResponse`` / ``LogoutResponse`` wrappers and the status,
       signature, lifetime, and unsolicited-response exceptions used by
       djangosaml2.
   * - ``...saml2.mdstore``
     - ``MetadataStore`` / ``MetaDataMDX`` / ``SourceNotFound`` and the
       ``name`` / ``service`` / descriptor queries used by discovery views.
   * - ``...saml2.metadata``
     - ``entity_descriptor(config)`` - build this SP's own metadata document.
   * - ``...saml2.cache``
     - ``Cache`` - a dict-backed identity cache faithful to pysaml2's
       per-(subject, entity) storage and expiry semantics.
   * - ``...saml2.s_utils``
     - ``deflate_and_base64_encode`` (and its inverse) for the Redirect binding.
   * - ``...saml2.sigver``
     - ``get_xmlsec_binary`` (returns ``None``) and ``MissingKey``.
   * - ``...saml2.samlp``
     - Mutable ``AuthnRequest`` / ``Scoping`` / ``IDPList`` / ``IDPEntry``
       compatibility values for custom POST and IdP-scoping flows.
   * - ``...saml2.client_base`` / ``...saml2.validate``
     - The logout and response-validation exception types imported by
       djangosaml2.
   * - ``...saml2.md`` / ``...saml2.xmldsig`` / ``...saml2.xmlenc``
     - Namespace and algorithm constants used by metadata serialization.
   * - ``...saml2.server``
     - Placeholder ``Server`` (IdP adapter is a later phase); imports cleanly,
       raises ``NotImplementedError`` if constructed.

Configuration: ``SPConfig``
---------------------------

``SPConfig().load(conf)`` reads the same settings dict pysaml2 uses. Only the
keys an SP needs are interpreted; everything else (``xmlsec_binary``,
``attribute_map_dir``, ``contact_person``, ``organization``, ``debug`` ...) is
accepted and ignored.

.. code-block:: python

   from pygamlastan.compat.saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
   from pygamlastan.compat.saml2.config import SPConfig

   conf = {
       "entityid": "https://sp.example.org/saml2-metadata",
       "service": {
           "sp": {
               "endpoints": {
                   "assertion_consumer_service": [
                       ("https://sp.example.org/saml2-acs", BINDING_HTTP_POST),
                   ],
                   "single_logout_service": [
                       ("https://sp.example.org/saml2-ls", BINDING_HTTP_REDIRECT),
                   ],
               },
               "want_response_signed": True,
               "idp": {
                   "https://idp.example.com/metadata": {
                       "single_sign_on_service": {
                           BINDING_HTTP_REDIRECT: "https://idp.example.com/sso",
                       },
                       "single_logout_service": {
                           BINDING_HTTP_REDIRECT: "https://idp.example.com/slo",
                       },
                   },
               },
           },
       },
       "metadata": {"local": ["/etc/sp/idp_metadata.xml"]},
       "key_file": "/etc/sp/sp.key",
       "cert_file": "/etc/sp/sp.crt",
   }
   config = SPConfig().load(conf)

The relevant keys:

* ``entityid`` - this SP's entity ID.
* ``service.sp.endpoints.assertion_consumer_service`` /
  ``single_logout_service`` - lists of ``(url, binding)``.
* ``service.sp.idp`` - per-IdP SSO/SLO endpoints by binding. With exactly one IdP
  configured (or exactly one in metadata) the shim can resolve "the IdP"
  automatically.
* ``service.sp.want_response_signed`` - the security switch (see
  `Security model`_); defaults to ``True``.
* ``service.sp.authn_requests_signed`` / ``logout_requests_signed`` /
  ``logout_responses_signed`` - independent outbound signing switches.
* ``service.sp.want_assertions_signed`` /
  ``want_logout_response_signed`` - independent inbound requirements. In
  particular, requiring signed AuthnResponses does not implicitly require
  signed LogoutResponses.
* ``metadata.local`` - local metadata files (single entity or a federation
  aggregate). The IdP's signing certificate and, as a fallback, its SSO/SLO
  endpoints are read from here.
* ``key_file`` / ``cert_file`` - this SP's signing key and certificate (used for
  signed AuthnRequests/LogoutRequests and embedded in generated metadata).

The SP flow
-----------

The ``Saml2Client`` reproduces the SP methods an eduID-style integration calls.

Sending an AuthnRequest
~~~~~~~~~~~~~~~~~~~~~~~~~

``prepare_for_authenticate`` returns ``(session_id, http_info)``. ``session_id``
is the AuthnRequest's ID - store it in your outstanding-requests cache so you can
match the eventual response's ``InResponseTo``. ``http_info`` is the pysaml2
redirect dict: its ``headers`` list contains a ``("Location", url)`` pair.

.. code-block:: python

   from pygamlastan.compat.saml2 import BINDING_HTTP_REDIRECT
   from pygamlastan.compat.saml2.client import Saml2Client

   client = Saml2Client(config)
   session_id, info = client.prepare_for_authenticate(
       entityid="https://idp.example.com/metadata",
       relay_state="/after-login",
       binding=BINDING_HTTP_REDIRECT,
       force_authn="false",
       requested_authn_context={
           "authn_context_class_ref": [
               "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
           ],
           "comparison": "exact",
       },
   )
   location = dict(info["headers"])["Location"]   # 302/303 redirect target
   outstanding_cache[session_id] = "my-authn-ref"

``binding`` selects how the request is delivered: ``BINDING_HTTP_REDIRECT``
returns a ``Location`` URL; ``BINDING_HTTP_POST`` returns ``method="POST"`` with
an auto-submit form in ``data``. Set ``authn_requests_signed=True`` (and provide
``key_file``) to produce the binding-appropriate detached Redirect signature or
enveloped POST XML signature. Merely configuring a key does not advertise or
enable request signing.

Processing the Response
~~~~~~~~~~~~~~~~~~~~~~~~~

``parse_authn_request_response(raw, binding, outstanding)`` decodes the
``SAMLResponse`` (base64 for HTTP-POST), enforces that its ``InResponseTo`` is in
your ``outstanding`` set, verifies/validates it, and returns an ``AuthnResponse``.

.. code-block:: python

   from pygamlastan.compat.saml2 import BINDING_HTTP_POST
   from pygamlastan.compat.saml2.response import StatusError, UnsolicitedResponse

   try:
       response = client.parse_authn_request_response(
           form["SAMLResponse"], BINDING_HTTP_POST, outstanding_cache
       )
   except UnsolicitedResponse:
       ...   # InResponseTo not in the outstanding set
   except StatusError:
       ...   # the IdP returned a non-Success status
   except AssertionError:
       ...   # signature verification / validation failed

   session_id = response.session_id()          # echoes the request ID
   info = response.session_info()

``session_info()`` returns the same dict pysaml2 produces:

.. code-block:: python

   {
       "ava": {"eduPersonPrincipalName": ["user@eduid.se"], "mail": [...]},
       "name_id": <NameID>,            # a saml.NameID value object
       "came_from": None,
       "issuer": "https://idp.example.com/metadata",
       "not_on_or_after": 1750000000,  # epoch seconds, or None
       "authn_info": [("urn:...:PasswordProtectedTransport", [], "2026-06-28T...")],
       "session_index": "id-...",
   }

The wire attribute names (OIDs/URIs) are converted to friendly local names
through :doc:`attribute_map <../api/attribute_map>`
(``AttributeConverterSet.with_default_maps()``), exactly as pysaml2's attribute
converters do - so ``urn:oid:1.3.6.1.4.1.5923.1.1.1.6`` arrives in ``ava`` as
``eduPersonPrincipalName``.

Storing the subject: ``code`` / ``decode``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To remember who is logged in (for later Single Logout) store the NameID as an
opaque string and decode it back when needed:

.. code-block:: python

   from pygamlastan.compat.saml2.ident import code, decode

   session["name_id"] = code(info["name_id"])   # opaque, session-storable str
   ...
   subject = decode(session["name_id"])         # back to a NameID

New values use the shim's own ``pgc1:``-prefixed encoding. ``decode`` also reads
pysaml2's legacy comma-index encoding and djangosaml2's historical bare
``NameID.text`` value, so existing login sessions survive a rolling migration.
A malformed ``pgc1:`` payload still raises ``ValueError`` rather than silently
turning corrupted state into a blank subject.

Single Logout
~~~~~~~~~~~~~~

The three SLO methods mirror pysaml2:

.. code-block:: python

   # SP-initiated: build LogoutRequests for each federated IdP that has an SLO.
   logouts = client.global_logout(decode(session["name_id"]))
   for idp_entity_id, (binding, http_info) in logouts.items():
       if binding == BINDING_HTTP_REDIRECT:
           location = dict(http_info["headers"])["Location"]
           ...   # redirect to location
       elif binding == BINDING_HTTP_POST:
           post_form = http_info["data"]
           ...   # return the auto-submitting HTML form

   # We started the logout: parse the IdP's correlated LogoutResponse. Construct
   # the client with djangosaml2's StateCache so the outgoing request ID survives
   # across web requests.
   incoming_params = request.POST if request.method == "POST" else request.GET
   response_binding = (
       BINDING_HTTP_POST
       if request.method == "POST"
       else BINDING_HTTP_REDIRECT
   )
   resp = client.parse_logout_request_response(
       incoming_params["SAMLResponse"], response_binding,
       # For a signed Redirect response also forward sig_alg, signature, and
       # the exact signed_query, as shown for LogoutRequest below.
   )
   if resp.status_ok():
       ...   # logout confirmed

   # IdP-initiated: respond to an incoming LogoutRequest. The request is
   # cryptographically verified against the IdP's metadata signing
   # certificates before any session state is touched, so for the Redirect
   # binding the handler must forward the detached-signature material from
   # the RAW query string it received (still percent-encoded): signed_query
   # is the exact SAMLRequest[&RelayState]&SigAlg portion the IdP signed.
   from urllib.parse import parse_qsl

   raw_query = request.META["QUERY_STRING"]            # framework-specific
   signed_query = raw_query.split("&Signature=", 1)[0] # Signature is last
   params = dict(parse_qsl(raw_query))
   http_info = client.handle_logout_request(
       params["SAMLRequest"], decode(session["name_id"]),
       BINDING_HTTP_REDIRECT, relay_state=params.get("RelayState"),
       sig_alg=params.get("SigAlg"), signature=params.get("Signature"),
       signed_query=signed_query,
       # expected_idp="https://idp.example.org/metadata"  # if several IdPs
   )
   location = dict(http_info["headers"])["Location"]   # redirect to IdP SLO

   # The verified RelayState from the signed query must match the relay_state
   # you echo, and the request is one-time use (replay-cached). If the IdP
   # publishes no signing certificate at all, handle_logout_request fails
   # closed unless the SP settings explicitly opt in with
   # ``"allow_unsigned_logout_requests": True`` (development only).
   # When Destination is present, it must match an SLO endpoint configured for
   # the received binding. Register the same URL for both bindings if both are
   # accepted there.

.. warning::

   Detached Redirect signatures cannot be reconstructed from the decoded
   ``SAMLRequest`` or ``SAMLResponse`` value. A framework adapter—including
   djangosaml2's logout view—must forward ``SigAlg``, ``Signature``, and the
   exact percent-encoded signed query substring to the shim. Dropping those
   fields cannot be repaired inside a SAML library and correctly fails closed.

Generating SP metadata
~~~~~~~~~~~~~~~~~~~~~~~~

``entity_descriptor(config)`` renders this SP's ``<md:EntityDescriptor>`` (entity
ID, ACS/SLO endpoints, and the signing certificate from ``cert_file``) and
returns an object with ``.to_string()`` / ``.to_xml()``:

.. code-block:: python

   from pygamlastan.compat.saml2.metadata import entity_descriptor

   xml = entity_descriptor(config).to_string()   # bytes, for the metadata view

Security model
--------------

The shim's trust posture follows the ``want_response_signed`` setting, mapping
onto pygamlastan's :doc:`safe entry points <security>`:

* **``want_response_signed=True`` (production).** The shim calls
  ``profiles.process_response_verified``, the safe-by-construction entry point
  that verifies the XML-DSig over the exact received bytes *internally* (with a
  ``SamlVerifier`` built from the IdP's signing certificates read from the parsed
  metadata - every published certificate is tried, so a key rollover that
  publishes the old and new certificates simultaneously keeps verifying) and
  feeds only the cryptographically verified reference IDs into
  validation - so the shim never threads ``verified_signed_ids`` by hand and
  cannot mis-wire it. Because verification runs first, an unsigned or
  invalidly-signed Response cannot use the status path to bypass the
  signatures-required policy: a missing/invalid signature (``SamlCryptoError``) is
  raised as ``AssertionError`` (the exception pysaml2 SP code already catches as
  "response is not verified"), while a *verified* Response carrying a non-Success
  status is raised as ``StatusError`` for pysaml2 parity. The validation profile
  uses production defaults with ``require_signed_responses=True`` and
  ``require_signed_assertions=False``: this matches pysaml2's
  ``want_response_signed`` switch, where a signed Response envelope is enough
  unless the deployment separately requires direct Assertion signatures.

* **``want_response_signed=False`` (development/testing only).** Responses are
  processed with ``profiles.process_response`` under
  ``SecurityConfig.permissive()``. This path - which accepts unsigned responses -
  is reachable **only** when the settings explicitly opt out of signatures. Never
  set this in production.

With several configured IdPs, the claimed issuer may select only an already
configured metadata entity. In signed mode the exact response must then verify
against that entity's trusted certificates before the claim is used. Callers
that record the selected IdP with the outstanding request can instead pass
``expected_idp=<entity id>`` explicitly.

Replay / solicited-response protection is two-layered. The response's
``InResponseTo`` must be present in the ``outstanding`` set you pass in (an
unknown one raises ``UnsolicitedResponse``), and you remove it once consumed -
mirroring pysaml2's SP model. Independently, gamlastan's assertion-replay check
(check 20) runs against a replay cache with process lifetime that is shared by
every ``Saml2Client`` instance, so rebuilding the client per request does not
reset replay state. A multi-process deployment should inject a shared
implementation via ``Saml2Client(config, replay_cache=...)`` (any object with
``check_and_insert(id, expiry) -> bool`` and ``cleanup()``). The shim calls
``cleanup()`` periodically (throttled) from its processing paths, so expired
entries are evicted and the cache stays bounded in a long-running SP. Keys sent
to that backend are stable ASCII strings namespaced by message kind, local SP
entity ID, and trusted expected IdP, so one trust context cannot reserve a raw
SAML ID and make another context fail as a replay.
Deployments that
need cross-request ``persistent`` NameID uniqueness can layer a persistent-id
store separately.

What is and is not covered
--------------------------

**Covered (SP flow):** ``Saml2Client.prepare_for_authenticate`` (Redirect and
POST, including signed requests), lower-level ``sso_location`` /
``create_authn_request``, ``parse_authn_request_response`` with the full
``session_info`` and assertion-confirmation object graph,
``global_logout`` and the POST/enveloped or adapter-assisted Redirect forms of
``parse_logout_request_response`` / ``handle_logout_request``,
``SPConfig.load``, ``MetadataStore``, ``ident.code`` / ``decode``, the schema
namespace/value and exception modules imported by djangosaml2,
``metadata.entity_descriptor``, persistent ``cache.Cache`` population methods,
and the ``s_utils`` Redirect helpers.

**Not covered (yet):** unmodified djangosaml2 handling of signed Redirect SLO
messages (its view discards the exact signed query required for detached-signature
verification), the IdP ``server.Server`` (a later phase - the placeholder imports
but raises ``NotImplementedError``), ECP/PAOS, artifact resolution, virtual
organisations, and pysaml2's on-disk attribute-map files (attribute conversion
uses :doc:`attribute_map <../api/attribute_map>` instead). If your integration
depends on any of these, address it before migrating.

**Deliberate divergences from pysaml2:** malformed native ``pgc1:`` session
values fail closed; verified response processing is selected independently by
``want_response_signed`` or ``want_assertions_signed`` and enforces the selected
envelope/assertion requirements; assertion and IdP-initiated logout replay is
enforced through a process-lifetime replay cache; and SP-initiated
LogoutResponses are correlated against the state cache. Test fixtures must
therefore use fresh SAML IDs and echo the actual outgoing request ID. These rules
are pinned by the shim's test suite (``tests/test_compat_saml2.py``).
