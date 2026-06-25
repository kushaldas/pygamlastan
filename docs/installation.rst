Installation
============

Requirements
------------

* Python 3.10 or newer (the wheels are built against the stable ABI, ``abi3``).
* For the PKCS#11/HSM signing path at runtime: a PKCS#11 module (for example
  SoftHSM2 or kryoptic). The module is loaded with ``dlopen`` at runtime, so it
  is not needed to install or import pygamlastan, only to use a token.

From a wheel
------------

.. code-block:: console

   uv pip install pygamlastan

Prebuilt ``manylinux``, macOS, and Windows wheels include the compiled
extension and PEP 561 type information, so no Rust toolchain is required.

.. tip:: HSM / PKCS#11 deployments

   If you will use the PKCS#11/HSM signing path in production, prefer building
   the wheel **in - or against - your target environment** rather than relying
   on the generic prebuilt wheel. The compiled extension links the host C and
   crypto stack, and your PKCS#11 module is loaded at runtime from that same
   host; building where the token tooling and system libraries live (``maturin
   build --release`` on the target host, or a container matching production)
   avoids glibc/loader and provider-ABI mismatches and lets you validate signing
   against the real module before shipping. See :doc:`guides/signing`.

From source
-----------

Building from source needs a Rust toolchain (1.75+) and `maturin
<https://www.maturin.rs>`_. The project uses `uv <https://docs.astral.sh/uv/>`_:

.. code-block:: console

   uv venv
   uv pip install --python .venv/bin/python maturin
   VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --uv
   .venv/bin/python -m pytest

Type checking
-------------

The package ships ``py.typed`` and a ``.pyi`` stub per submodule, so mypy and
pyright pick up types automatically with no extra configuration:

.. code-block:: python

   from pygamlastan import core
   nid = core.NameId("alice", format=core.NAMEID_TRANSIENT)
   reveal_type(nid.value)  # str
