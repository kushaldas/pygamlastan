pygamlastan.idp
===============

.. py:module:: pygamlastan.idp

IdP-side infrastructure: eduPersonTargetedID generation, the authentication
broker, NameID storage coding, and an issued-assertion store.

eduPersonTargetedID
-------------------

.. py:class:: Eptid(secret: str)

   Derives stable, per-SP opaque identifiers from a server-side ``secret``. The
   same user gets a consistent id at one SP but an unlinkable id at another.

   .. py:method:: get(idp_entity_id: str, sp_entity_id: str, user_id: str) -> str
   .. py:method:: name_id(idp_entity_id: str, sp_entity_id: str, user_id: str) -> pygamlastan.core.NameId
   .. py:method:: attribute(idp_entity_id: str, sp_entity_id: str, user_id: str) -> pygamlastan.core.Attribute

Authentication broker
---------------------

.. py:class:: AuthnBroker()

   Registers authentication methods and selects them by authentication context.

   .. py:method:: add(class_ref: str, method: str, level: int, authn_authority: str | None = None) -> str

      Register a method; returns its reference id.

   .. py:method:: get_by_class_ref(class_ref: str) -> AuthnMethod | None
   .. py:method:: pick(requested: pygamlastan.core.RequestedAuthnContext | None = None) -> list[AuthnMethod]

      Methods matching a requested context (best first); with ``None``, performs
      the unspecified-context lookup.

.. py:class:: AuthnMethod

   ``class_ref``, ``method``, ``level`` (int), ``authn_authority`` (str | None),
   ``reference``.

Assertion store
---------------

.. py:class:: InMemoryAssertionStore()

   Retains issued assertions to answer later queries.

   .. py:method:: store_assertion(assertion: pygamlastan.core.Assertion) -> None
   .. py:method:: get_assertion(assertion_id: str) -> pygamlastan.core.Assertion | None
   .. py:method:: assertions_for_subject(name_id_value: str) -> list[pygamlastan.core.Assertion]
   .. py:method:: remove_assertion(assertion_id: str) -> None

NameID storage coding
---------------------

.. py:function:: code_name_id(name_id: pygamlastan.core.NameId) -> str

   Serialize a NameID to an opaque storage string.

.. py:function:: decode_name_id(coded: str) -> pygamlastan.core.NameId

   Parse a NameID from its storage string.
