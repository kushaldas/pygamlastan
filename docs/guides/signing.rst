Signing, verification, and encryption
=====================================

pygamlastan supports XML-DSig signing with either file-based private keys or a
private key held on a PKCS#11 token (HSM), plus signature verification, XML
encryption/decryption, and canonicalization. These live in
:doc:`../api/crypto`.

Key management
--------------

:class:`pygamlastan.crypto.KeysManager` holds keys and trusted certificates.
The convenience builders cover the common SP and IdP setups:

.. code-block:: python

   from pygamlastan import crypto

   # SP: own signing key plus the trusted IdP certificate.
   sp_keys = crypto.KeysManager.build_sp(sp_private_key_pem, idp_certificate_pem)

   # IdP: own signing key.
   idp_keys = crypto.KeysManager.build_idp(idp_private_key_pem)

   # Or build one up by hand.
   km = crypto.KeysManager()
   km.add_key_pem(private_key_pem, usage="sign")
   km.add_trusted_cert(peer_certificate)   # PEM or DER bytes

Enveloped signatures
--------------------

gamlastan signs a *template*: the document to be signed must already contain a
``<ds:Signature>`` element with an empty ``DigestValue``/``SignatureValue`` and
the signing certificate in ``<ds:KeyInfo>``. The signer fills in the digest and
signature:

.. code-block:: python

   signer = crypto.SamlSigner.from_pem(private_key_pem)
   signed_xml = signer.sign_enveloped(xml_with_signature_template)

The IdP profiles produce documents ready to be signed this way; embed your
certificate in the template and sign the serialized message.

Verifying signatures
--------------------

Verify with a :class:`pygamlastan.crypto.SamlVerifier`. Build one trusting a
single certificate, or from a fully populated :class:`~pygamlastan.crypto.KeysManager`:

.. code-block:: python

   verifier = crypto.SamlVerifier.from_cert(idp_certificate_pem)

   # These are the secure defaults, shown explicitly for production config:
   verifier.set_skip_time_checks(False)
   verifier.set_trusted_keys_only(True)
   verifier.set_strict_verification(True)
   verifier.set_hmac_min_out_len(160)
   verifier.set_require_reference_digests(True)
   verifier.set_allow_raw_inline_keyinfo_with_trust_anchors(False)

   result = verifier.verify_enveloped(signed_xml)

   if result.is_valid():
       signed_ids = result.signed_reference_ids()   # ids whose digest was checked

:meth:`~pygamlastan.crypto.SamlVerifier.from_cert` registers the certificate both
as a verification key and as a trust anchor. By default the verifier runs in
``trusted_keys_only`` mode, so a certificate embedded in the message's
``<KeyInfo>`` is not blindly trusted. ``signed_reference_ids()`` is exactly what
you feed to :func:`pygamlastan.profiles.process_response` as
``verified_signed_ids``.

When a SAML message can contain more than one signature (for example a Response
signature plus an Assertion signature), verify all signatures and collect all
digest-verified IDs:

.. code-block:: python

   from pygamlastan import profiles, security, xml

   results = verifier.verify_all_enveloped(response_xml)
   signed_ids = []
   for result in results:
       if not result:
           raise ValueError(result.reason)
       signed_ids.extend(result.signed_reference_ids())

   parsed = xml.parse_response(response_xml)
   authn = profiles.process_response(
       parsed, security.SecurityConfig(),
       sp_entity_id=SP, acs_url=ACS, expected_idp_entity_id=IDP,
       verified_signed_ids=signed_ids,
       replay_cache=security.InMemoryReplayCache(),
   )

Prefer :func:`pygamlastan.profiles.process_response_verified` for normal SP
flows; it performs this all-signature verification internally over the exact
bytes it then validates.

Algorithm allowlists
--------------------

Gamlastan 0.9 checks the XML-DSig ``SignatureMethod`` and every Reference
``DigestMethod`` against an :class:`pygamlastan.crypto.AlgorithmPolicy` before
cryptographic dispatch. The default policy accepts RSA and ECDSA signatures
with SHA-256, SHA-384, or SHA-512, and Reference digests with SHA-256,
SHA-384, or SHA-512. It rejects SHA-1 and other backend-supported legacy
algorithms.

Inspect the active policy or replace it with an exact federation policy:

.. code-block:: python

   RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
   SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"

   policy = crypto.AlgorithmPolicy.allow_only([RSA_SHA256], [SHA256])
   verifier.set_algorithm_policy(policy)

   assert verifier.algorithm_policy == policy
   assert verifier.algorithm_policy.allows_signature_algorithm(RSA_SHA256)
   assert verifier.algorithm_policy.allowed_digest_algorithms == [SHA256]

``with_signature_algorithms`` and ``with_digest_algorithms`` return new policy
objects; they do not mutate the original. Likewise,
``verifier.with_algorithm_policy(policy)`` returns a verifier copy while
preserving all configured certificates, including rollover certificates:

.. code-block:: python

   rsa_only = crypto.AlgorithmPolicy().with_signature_algorithms([RSA_SHA256])
   restricted_verifier = verifier.with_algorithm_policy(rsa_only)

An empty allowlist intentionally denies every algorithm of that kind. In
contrast, :meth:`~pygamlastan.crypto.AlgorithmPolicy.permissive` returns
``None`` allowlists and accepts every algorithm supported by the backend; it
emits a warning and should be confined to deliberate legacy or non-SAML
interoperability.

HMAC has a second, independent defence. Even if an algorithm policy allows an
HMAC URI, the verifier rejects HMAC signatures until
``set_reject_hmac_signatures(False, unsafe_allow_hmac=True)`` is called. SAML
federations normally use asymmetric certificates, so leave this guard enabled.
For a narrowly scoped legacy SHA-1 peer, prefer an exact custom allowlist over
``permissive()`` and isolate that verifier from normal SAML traffic.

PKCS#11 / HSM signing
---------------------

To keep the private key on a hardware token, load the PKCS#11 module, open a
session, and create a token-backed signer. The private key never leaves the
token; the certificate comes from the signature template, so the
:class:`~pygamlastan.crypto.KeysManager` may be empty.

.. code-block:: python

   from pygamlastan import crypto

   provider = crypto.Pkcs11Provider("/usr/lib/softhsm/libsofthsm2.so")
   session = provider.open_session("1234")           # user PIN
   hsm_signer = session.signer("saml-signing-key", "rsa-sha256")

   signer = crypto.SamlSigner.with_pkcs11(hsm_signer)
   signed_xml = signer.sign_enveloped(xml_with_signature_template)

Supported algorithm names include ``rsa-sha256``, ``rsa-sha384``,
``rsa-sha512``, ``rsa-pss-sha256``, ``ecdsa-p256-sha256``,
``ecdsa-p384-sha384``, ``ecdsa-p521-sha512``, and ``ed25519``.

.. tip:: Build the wheel in your target environment for HSM deployments

   The published ``manylinux`` wheel targets a broad compatibility baseline. For
   a PKCS#11/HSM deployment, prefer building the wheel **in - or against - the
   environment where it will run**. The compiled extension links the host C and
   crypto stack, and the PKCS#11 module (SoftHSM2, kryoptic, or a vendor HSM
   driver) is ``dlopen``-ed at runtime from that same host. Building where your
   token tooling and system libraries live - for example ``maturin build
   --release`` on the target host, or inside a container that matches production
   - avoids glibc/loader and provider-ABI mismatches and lets you exercise the
   signing path against the real module before shipping. The generic prebuilt
   wheel is fine for development and for the file-key signing paths.

Redirect (detached) signatures
------------------------------

For the HTTP-Redirect binding the signature is detached and computed over the
query string. The :doc:`bindings <bindings>` apply this for you when you pass a
signer to :func:`pygamlastan.bindings.redirect_encode`; the lower-level
:meth:`~pygamlastan.crypto.SamlSigner.sign_redirect_query` and
:meth:`~pygamlastan.crypto.SamlVerifier.verify_redirect_query` are available when
you need them directly.

Encryption and decryption
-------------------------

:class:`pygamlastan.crypto.SamlEncryptor` and
:class:`pygamlastan.crypto.SamlDecryptor` handle XML encryption (for example
EncryptedAssertion). ``SamlEncryptor.for_certificate`` encrypts to a recipient
certificate (the per-request PEFIM flow):

.. code-block:: python

   encryptor = crypto.SamlEncryptor.for_certificate(recipient_cert_der)
   encrypted = encryptor.encrypt(template_xml, plaintext_bytes)

   decryptor = crypto.SamlDecryptor(km)
   plaintext = decryptor.decrypt(encrypted)

Canonicalization
----------------

:func:`pygamlastan.crypto.exc_c14n` and :func:`pygamlastan.crypto.canonicalize`
expose Exclusive and Inclusive C14N, returning the canonical bytes:

.. code-block:: python

   canonical = crypto.exc_c14n('<a xmlns:b="urn:x"><b:c>hi</b:c></a>')
