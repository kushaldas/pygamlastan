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
   result = verifier.verify_enveloped(signed_xml)

   if result.is_valid():
       signed_ids = result.signed_reference_ids()   # ids whose digest was checked

:meth:`~pygamlastan.crypto.SamlVerifier.from_cert` registers the certificate both
as a verification key and as a trust anchor. By default the verifier runs in
``trusted_keys_only`` mode, so a certificate embedded in the message's
``<KeyInfo>`` is not blindly trusted. ``signed_reference_ids()`` is exactly what
you feed to :func:`pygamlastan.profiles.process_response` as
``verified_signed_ids``.

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
