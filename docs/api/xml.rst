pygamlastan.xml
===============

.. py:module:: pygamlastan.xml

Parse SAML XML into the owned types from :doc:`core`. Each function parses the
document, converts the borrowed view to an owned object, and returns it; the
XML document does not outlive the call. On malformed or unexpected input these
raise :class:`pygamlastan.SamlXmlError`.

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
