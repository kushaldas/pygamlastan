"""Attribute maps whose inbound and outbound directions differ.

A pysaml2 attribute map has independent ``fro`` (wire -> local) and ``to``
(local -> wire) dicts, and real maps are asymmetric. ``add_mapping`` sets both
directions at once, so it cannot load one without inventing entries.
"""

from pygamlastan import attribute_map, core, idp

URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
MAIL = "urn:oid:0.9.2342.19200300.100.1.3"
DISPLAY = "urn:oid:2.16.840.1.113730.3.1.241"
SP = "https://sp.example.org/sp"


def _asymmetric():
    """`displayName` can be sent but is not recognised on the way in."""
    return attribute_map.AttributeConverter.from_directions(
        URI,
        fro=[(MAIL, "mail")],
        to=[("mail", MAIL), ("displayName", DISPLAY)],
    )


def test_the_directions_are_independent():
    conv = _asymmetric()
    assert conv.to_local_name(MAIL) == "mail"
    assert conv.to_wire_name("mail") == MAIL
    assert conv.to_wire_name("displayName") == DISPLAY
    # Outbound-only: an SP-supplied name must not start resolving to a local
    # attribute it did not before.
    assert conv.to_local_name(DISPLAY) is None
    # Keys are case-insensitive, as in pysaml2.
    assert conv.to_wire_name("DISPLAYNAME") == DISPLAY
    assert conv.to_local_name(MAIL.upper()) == "mail"


def test_add_mapping_mirrors_both_directions_which_a_real_map_cannot_use():
    mirrored = attribute_map.AttributeConverter(URI)
    mirrored.add_mapping(DISPLAY, "displayName")
    assert mirrored.to_local_name(DISPLAY) == "displayName"  # the invented inbound entry


def test_entries_can_be_added_one_direction_at_a_time():
    conv = attribute_map.AttributeConverter(URI)
    conv.add_wire_to_local("urn:example:in", "x")
    assert conv.to_local_name("urn:example:in") == "x"
    assert conv.to_wire_name("x") is None  # not sent unless an outbound entry says so
    conv.add_local_to_wire("x", "urn:example:out")
    assert conv.to_wire_name("x") == "urn:example:out"
    assert conv.to_local_name("urn:example:out") is None


def test_the_outbound_name_does_not_depend_on_inbound_order():
    for fro in (
        [("urn:example:a", "l"), ("urn:example:b", "l")],
        [("urn:example:b", "l"), ("urn:example:a", "l")],
    ):
        conv = attribute_map.AttributeConverter.from_directions(
            URI, fro=fro, to=[("l", "urn:example:b")]
        )
        assert conv.to_wire_name("l") == "urn:example:b"
        assert conv.to_local_name("urn:example:a") == "l"


def test_a_converter_set_built_from_your_own_maps():
    converters = attribute_map.AttributeConverterSet([_asymmetric()])
    local = converters.to_local(
        [core.Attribute(MAIL, values=["a@example.org"]), core.Attribute(DISPLAY, values=["Alice"])]
    )
    # The outbound-only name is not recognised inbound, so it is dropped.
    assert [(a.name, a.values) for a in local] == [("mail", ["a@example.org"])]

    wire = converters.from_local([attribute_map.LocalAttribute("displayName", ["Alice"])], URI)
    assert [a.name for a in wire] == [DISPLAY]


def test_a_release_policy_resolves_names_through_your_converters():
    attr = core.Attribute("urn:example:mail-x", values=["a@example.org"])
    restrict_mail = idp.PolicyEntry(attribute_restrictions=[("mail", None)])

    # The shipped maps do not know this name, so the restriction on `mail`
    # does not release it.
    assert idp.ReleasePolicy(default=restrict_mail).filter([attr], SP) == []

    custom = attribute_map.AttributeConverterSet(
        [attribute_map.AttributeConverter.from_directions(URI, fro=[("urn:example:mail-x", "mail")])]
    )
    released = idp.ReleasePolicy(default=restrict_mail, converters=custom).filter([attr], SP)
    assert [a.name for a in released] == ["urn:example:mail-x"]
