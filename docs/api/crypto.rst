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

.. py:class:: AlgorithmPolicy()

   The gamlastan 0.9 signature and Reference-digest allowlist. The secure
   default accepts RSA/ECDSA signature methods with SHA-256/384/512 and
   SHA-256/384/512 digests.

   .. py:staticmethod:: allow_only(signature_algorithms: list[str], digest_algorithms: list[str]) -> AlgorithmPolicy

      Build an exact allowlist. Empty lists deliberately deny every algorithm.

   .. py:staticmethod:: permissive() -> AlgorithmPolicy

      Accept every backend-supported algorithm. This warns and is intended only
      for deliberate legacy/non-SAML interoperability.

   .. py:method:: with_signature_algorithms(algorithms: list[str]) -> AlgorithmPolicy
   .. py:method:: with_digest_algorithms(algorithms: list[str]) -> AlgorithmPolicy
   .. py:attribute:: allowed_signature_algorithms
      :type: list[str] | None
   .. py:attribute:: allowed_digest_algorithms
      :type: list[str] | None
   .. py:method:: allows_signature_algorithm(uri: str) -> bool
   .. py:method:: allows_digest_algorithm(uri: str) -> bool

.. py:class:: SamlVerifier(keys: KeysManager)

   Verify signatures against keys/trusted certs in a :class:`KeysManager`.

   .. py:staticmethod:: from_cert(cert: bytes) -> SamlVerifier

      Build a verifier trusting a single certificate (PEM or DER). The
      certificate's public key is registered as a verification key and as a
      trust anchor.

   .. py:method:: set_algorithm_policy(policy: AlgorithmPolicy) -> None
   .. py:method:: with_algorithm_policy(policy: AlgorithmPolicy) -> SamlVerifier
   .. py:attribute:: algorithm_policy
      :type: AlgorithmPolicy

      Configure or inspect the policy applied before cryptographic dispatch.
      ``with_algorithm_policy`` returns a verifier copy and preserves every
      certificate configured for key rollover.

   .. py:method:: verify_enveloped(signed_xml: str) -> VerifyResult

      Verify the first enveloped XML-DSig signature in ``signed_xml``.

   .. py:method:: verify_all_enveloped(signed_xml: str) -> list[VerifyResult]

      Verify every enveloped XML-DSig signature in document order. Use this when
      a message may carry both Response-level and Assertion-level signatures and
      you need all digest-verified reference IDs.

   .. py:method:: verify_redirect_query(query_string: bytes, signature: bytes, algorithm_uri: str, unsafe_allow_weak_sha1: bool = False) -> bool

      Verify a HTTP-Redirect query signature. SHA-1 algorithms are rejected
      unless ``unsafe_allow_weak_sha1=True`` is explicit.

   .. py:method:: set_skip_time_checks(skip: bool, unsafe_allow_skip_time_checks: bool = False) -> None

      ``skip=True`` raises unless ``unsafe_allow_skip_time_checks=True`` is
      explicit. Disabling this check skips X.509 ``NotBefore``/``NotAfter``
      enforcement.

   .. py:method:: set_trusted_keys_only(trusted: bool, unsafe_allow_untrusted_keys: bool = False) -> None

      ``trusted=False`` raises unless ``unsafe_allow_untrusted_keys=True`` is
      explicit. Keep this enabled for SAML so attacker-supplied ``KeyInfo``
      certificates are not blindly trusted.

   .. py:method:: set_strict_verification(strict: bool, unsafe_allow_non_strict: bool = False) -> None

      ``strict=False`` raises unless ``unsafe_allow_non_strict=True`` is
      explicit. Keep this enabled to enforce XML Signature Wrapping reference
      position checks.

   .. py:method:: set_hmac_min_out_len(bits: int, unsafe_allow_short_hmac: bool = False) -> None

      Set the minimum accepted HMAC output length in bits. Values below 160
      raise unless ``unsafe_allow_short_hmac=True`` is explicit.

   .. py:method:: set_require_reference_digests(require: bool, unsafe_allow_missing_reference_digests: bool = False) -> None

      Require every XML-DSig reference digest to be verified locally. Setting
      ``require=False`` raises unless
      ``unsafe_allow_missing_reference_digests=True`` is explicit. Keep this
      enabled for SAML.

   .. py:method:: set_allow_raw_inline_keyinfo_with_trust_anchors(allow: bool, unsafe_allow_raw_inline_keyinfo: bool = False) -> None

      Allow raw inline ``KeyValue`` / ``DEREncodedKeyValue`` signatures to
      satisfy verification even when trust anchors are configured. Setting
      ``allow=True`` raises unless ``unsafe_allow_raw_inline_keyinfo=True`` is
      explicit. Keep this disabled for SAML.

   .. py:method:: set_reject_hmac_signatures(reject: bool, unsafe_allow_hmac: bool = False) -> None

      Keep the independent HMAC guard enabled for SAML. Disabling it requires
      ``unsafe_allow_hmac=True`` and still requires the active
      :class:`AlgorithmPolicy` to allow the chosen HMAC method.

   Example: hardened verifier setup with all default-on policy controls made
   explicit:

   .. code-block:: python

      verifier = crypto.SamlVerifier.from_cert(idp_signing_cert_pem)
      verifier.set_algorithm_policy(crypto.AlgorithmPolicy())
      verifier.set_skip_time_checks(False)
      verifier.set_trusted_keys_only(True)
      verifier.set_strict_verification(True)
      verifier.set_hmac_min_out_len(160)
      verifier.set_require_reference_digests(True)
      verifier.set_allow_raw_inline_keyinfo_with_trust_anchors(False)
      verifier.set_reject_hmac_signatures(True)

      results = verifier.verify_all_enveloped(response_xml)
      if not results or any(not result for result in results):
          raise ValueError("SAML signature verification failed")
      signed_ids = [
          signed_id
          for result in results
          for signed_id in result.signed_reference_ids()
      ]

.. py:class:: VerifyResult

   The outcome of :py:meth:`SamlVerifier.verify_enveloped`. Truthy when valid.

   .. py:method:: is_valid() -> bool
   .. py:attribute:: reason
      :type: str | None

      The failure reason when invalid, else ``None``.

   .. py:method:: signed_reference_ids() -> list[str]

      The reference ids whose digest was actually verified (with a leading
      ``#`` stripped). For a single-signature document, pass these to
      :func:`pygamlastan.profiles.process_response` as ``verified_signed_ids``.
      For multi-signature documents, collect IDs from
      :py:meth:`SamlVerifier.verify_all_enveloped`.

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
