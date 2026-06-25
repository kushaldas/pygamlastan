pygamlastan.crypto
==================

.. py:module:: pygamlastan.crypto

Cryptographic operations: key management, signing, verification, encryption,
decryption, canonicalization, and PKCS#11/HSM signing. See the
:doc:`../guides/signing` guide for worked examples. Errors raise
:class:`pygamlastan.SamlCryptoError`.

Keys
----

.. py:class:: KeysManager()

   Holds private/public keys and trusted certificates.

   .. py:staticmethod:: build_sp(private_key_pem: bytes, idp_certificate_pem: bytes) -> KeysManager

      SP setup: the SP signing key plus the trusted IdP certificate.

   .. py:staticmethod:: build_idp(private_key_pem: bytes) -> KeysManager

      IdP setup: the IdP signing key.

   .. py:method:: add_key_pem(pem: bytes, usage: str = "sign", password: str | None = None) -> None

      Load a PEM private key and add it. ``usage`` is one of ``"sign"``,
      ``"verify"``, ``"encrypt"``, ``"decrypt"``, ``"any"``.

   .. py:method:: add_trusted_cert(cert: bytes) -> None

      Add a trusted certificate (PEM or DER) used to verify signatures.

   .. py:method:: is_empty() -> bool

Signing
-------

.. py:class:: SamlSigner(keys: KeysManager)

   Sign with file-based keys from a :class:`KeysManager`.

   .. py:staticmethod:: from_pem(private_key_pem: bytes, password: str | None = None) -> SamlSigner

      Build a signer directly from a signing private key PEM.

   .. py:staticmethod:: with_pkcs11(signer: Pkcs11Signer, keys: KeysManager | None = None) -> SamlSigner

      Build an HSM-backed signer. ``keys`` may be omitted: the certificate is
      taken from the signature template.

   .. py:method:: sign_enveloped(xml_with_template: str) -> str

      Apply an enveloped XML-DSig signature to a document that already carries a
      ``<ds:Signature>`` template.

   .. py:method:: sign_redirect_query(query_string: bytes, algorithm_uri: str, unsafe_allow_weak_sha1: bool = False) -> bytes

      Sign a HTTP-Redirect query string; returns the raw signature bytes.
      SHA-1 algorithms are rejected unless ``unsafe_allow_weak_sha1=True`` is
      explicit.

   .. py:method:: signature_method_uri() -> str
   .. py:method:: is_hsm_backed() -> bool

Verification
------------

.. py:class:: SamlVerifier(keys: KeysManager)

   Verify signatures against keys/trusted certs in a :class:`KeysManager`.

   .. py:staticmethod:: from_cert(cert: bytes) -> SamlVerifier

      Build a verifier trusting a single certificate (PEM or DER). The
      certificate's public key is registered as a verification key and as a
      trust anchor.

   .. py:method:: verify_enveloped(signed_xml: str) -> VerifyResult
   .. py:method:: verify_redirect_query(query_string: bytes, signature: bytes, algorithm_uri: str, unsafe_allow_weak_sha1: bool = False) -> bool

      Verify a HTTP-Redirect query signature. SHA-1 algorithms are rejected
      unless ``unsafe_allow_weak_sha1=True`` is explicit.
   .. py:method:: set_skip_time_checks(skip: bool, unsafe_allow_skip_time_checks: bool = False) -> None

      ``skip=True`` raises unless ``unsafe_allow_skip_time_checks=True`` is
      explicit.

   .. py:method:: set_trusted_keys_only(trusted: bool, unsafe_allow_untrusted_keys: bool = False) -> None

      ``trusted=False`` raises unless ``unsafe_allow_untrusted_keys=True`` is
      explicit.

   .. py:method:: set_strict_verification(strict: bool, unsafe_allow_non_strict: bool = False) -> None

      ``strict=False`` raises unless ``unsafe_allow_non_strict=True`` is
      explicit.
   .. py:method:: set_hmac_min_out_len(bits: int) -> None

.. py:class:: VerifyResult

   The outcome of :py:meth:`SamlVerifier.verify_enveloped`. Truthy when valid.

   .. py:method:: is_valid() -> bool
   .. py:attribute:: reason
      :type: str | None

      The failure reason when invalid, else ``None``.

   .. py:method:: signed_reference_ids() -> list[str]

      The reference ids whose digest was actually verified (with a leading
      ``#`` stripped). Pass these to
      :func:`pygamlastan.profiles.process_response` as ``verified_signed_ids``.

   .. py:method:: signing_cert_chain() -> list[bytes]

      The DER X.509 chain (leaf first) of the signing key, when valid.

Encryption
----------

.. py:class:: SamlEncryptor(keys: KeysManager)

   .. py:staticmethod:: for_certificate(cert_der: bytes) -> SamlEncryptor

      Encrypt to a recipient certificate (the per-request PEFIM flow).

   .. py:method:: encrypt(template_xml: str, plaintext: bytes) -> str

.. py:class:: SamlDecryptor(keys: KeysManager)

   .. py:method:: decrypt(encrypted_xml: str) -> str
   .. py:method:: decrypt_to_bytes(encrypted_xml: str) -> bytes

Canonicalization
----------------

.. py:function:: canonicalize(xml: str, mode: str = "exclusive", inclusive_prefixes: list[str] | None = None) -> bytes

   Canonicalize ``xml``. ``mode`` is ``"exclusive"``, ``"inclusive"``,
   ``"exclusive-with-comments"`` or ``"inclusive-with-comments"``.

.. py:function:: exc_c14n(xml: str, inclusive_prefixes: list[str] | None = None) -> bytes

   Exclusive C14N shorthand.

PKCS#11 / HSM
-------------

.. py:class:: Pkcs11Provider(module_path: str)

   Load a PKCS#11 module (a shared library, e.g. SoftHSM2 or kryoptic).

   .. py:method:: open_session(pin: str) -> Pkcs11Session

      Open and log in to a session with the given user PIN.

.. py:class:: Pkcs11Session

   .. py:method:: signer(key_label: str, algorithm: str) -> Pkcs11Signer

      Create a signer bound to the private key identified by ``key_label``.
      ``algorithm`` is a name such as ``"rsa-sha256"`` or
      ``"ecdsa-p256-sha256"``.

.. py:class:: Pkcs11Signer(session: Pkcs11Session, key_label: str, algorithm: str)

   A signer whose private key stays on the token. Pass it to
   :py:meth:`SamlSigner.with_pkcs11`.
