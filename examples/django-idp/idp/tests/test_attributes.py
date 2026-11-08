from types import SimpleNamespace

from django.test import TestCase

from idp.accounts import create_user
from idp.saml_logic import _user_attributes


class AttributeTests(TestCase):
    def attributes(self, user, scope="example.org"):
        return {
            attribute.friendly_name: attribute.string_values
            for attribute in _user_attributes(user, SimpleNamespace(scope=scope))
        }

    def test_imported_profiles_and_multivalued_groups(self):
        user, _ = create_user(
            username="alice", email="alice@example.org", first_name="Alice",
            last_name="Andersson", display_name="Alice Example",
            scoped_affiliation="student@university.example", groups=["Students", "Readers"],
        )
        attributes = self.attributes(user)
        self.assertEqual(attributes["displayName"], ["Alice Example"])
        self.assertEqual(attributes["givenName"], ["Alice"])
        self.assertEqual(attributes["sn"], ["Andersson"])
        self.assertEqual(attributes["memberOf"], ["Readers", "Students"])
        self.assertEqual(attributes["eduPersonScopedAffiliation"], ["student@university.example"])
        self.assertEqual(attributes["eduPersonPrincipalName"], ["alice@example.org"])
        self.assertEqual(self.attributes(user, "")["eduPersonScopedAffiliation"],
                         ["student@university.example"])
        user.is_staff = True
        user.save()
        self.assertEqual(self.attributes(user), attributes)

    def test_optional_profile_fallbacks(self):
        user, _ = create_user(username="alice", email="alice@example.org")
        attributes = self.attributes(user)
        self.assertEqual(attributes["displayName"], ["alice"])
        self.assertEqual(attributes["eduPersonScopedAffiliation"], ["member@example.org"])
        self.assertNotIn("memberOf", attributes)
        self.assertNotIn("eduPersonScopedAffiliation", self.attributes(user, ""))
        user.first_name, user.last_name = "Alice", "Andersson"
        user.save()
        self.assertEqual(self.attributes(user)["displayName"], ["Alice Andersson"])
