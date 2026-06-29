"""Placeholder ``saml2.attributemaps`` package.

The real pysaml2 ships attribute-map modules in this package and config files
read ``saml2.attributemaps.__file__`` to derive ``attribute_map_dir``.
pygamlastan does attribute name<->OID mapping in Rust
(``pygamlastan.attribute_map.AttributeConverterSet.with_default_maps``), so no
on-disk maps are needed; this empty package exists only so that
``attribute_map_dir`` style config keeps importing. The resulting directory path
is accepted and ignored by :class:`pygamlastan.compat.saml2.config.SPConfig`.
"""
