pygamlastan.xml
===============

.. py:module:: pygamlastan.xml

Parse SAML XML into the owned types from :doc:`core`. Each function parses the
document, converts the borrowed view to an owned object, and returns it; the
XML document does not outlive the call. On malformed or unexpected input these
raise :class:`pygamlastan.SamlXmlError`.

.. _xml-hardening:

Input hardening (XXE and resource limits)
-----------------------------------------

Every function in this module parses **attacker-controlled** XML, so they all go
through gamlastan's hardened ``parse_secure`` entry point rather than the raw
underlying parser. There is no API that exposes the unhardened parser, so this
protection cannot be bypassed from Python. ``parse_secure`` layers two defenses
on top of a well-formedness parse:

* **DTD / ``<!DOCTYPE>`` rejection.** Any document carrying a DTD is refused with
  :class:`pygamlastan.SamlXmlError`. Legitimate SAML messages never contain a
  DTD, so this categorically removes the **XXE / external-entity /
  entity-smuggling** entry point — no external entity is ever resolved, no
  internal entity is ever expanded into a parsed SAML tree.

* **Fail-closed resource limits** (from ``uppsala`` 0.5): a maximum element
  nesting depth (128), an entity-expansion byte budget (1 MiB), and a maximum
  entity nesting depth (256). These bound **billion-laughs / quadratic-blowup**
  amplification and **deep-nesting stack exhaustion** before any SAML-level
  processing runs. Exceeding a limit raises :class:`pygamlastan.SamlXmlError`.

The same hardening applies to :func:`pygamlastan.metadata.parse_entity` /
:func:`~pygamlastan.metadata.parse_entities` (remote/published metadata is
attacker-influenced) and to the parse performed inside
:func:`pygamlastan.profiles.process_response_verified`.

.. code-block:: python

   from pygamlastan import xml

   # A DTD-bearing payload (classic XXE vector) is rejected outright:
   try:
       xml.parse_response(
           '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
           '&x;</samlp:Response>'
       )
   except pygamlastan.SamlXmlError:
       pass   # refused before any entity is resolved

.. py:function:: parse_response(xml: str) -> pygamlastan.core.Response

   Parse a ``<samlp:Response>`` document.

.. py:function:: parse_authn_request(xml: str) -> pygamlastan.core.AuthnRequest

   Parse a ``<samlp:AuthnRequest>`` document.

.. py:function:: parse_assertion(xml: str) -> pygamlastan.core.Assertion

   Parse a standalone ``<saml:Assertion>`` document.

.. py:function:: parse_logout_request(xml: str) -> pygamlastan.core.LogoutRequest

   Parse a ``<samlp:LogoutRequest>`` document.

.. py:function:: parse_logout_response(xml: str) -> pygamlastan.core.LogoutResponse

   Parse a ``<samlp:LogoutResponse>`` document.
