"""Explicitly allowlisted fields for IdP account administration."""
from django import forms
from django.contrib.auth.models import Group

from .models import User, normalize_identifier


class AccountForm(forms.ModelForm):
    """Allow only administrator-editable profile, role, and membership fields."""
    required_css_class = "required"

    group_names = forms.CharField(
        required=False, label="Groups",
        help_text="Comma-separated group names. New groups are created automatically.",
    )

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "display_name",
                  "scoped_affiliation", "is_active", "is_staff"]
        labels = {"is_staff": "Administrator"}
        help_texts = {"is_staff": "Can manage all IdP accounts."}

    def __init__(self, *args, **kwargs):
        """Initialize account fields and populate the current group memberships."""
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["group_names"].initial = ", ".join(
                self.instance.groups.order_by("name").values_list("name", flat=True))

    def clean_group_names(self):
        """Trim and deduplicate group names before any database writes."""
        names = list(dict.fromkeys(
            name.strip() for name in self.cleaned_data["group_names"].split(",") if name.strip()))
        if any(len(name) > 150 for name in names):
            raise forms.ValidationError("Group names must be at most 150 characters.")
        return names

    def save_groups(self, user):
        """Create missing groups and replace the account membership set."""
        user.groups.set([Group.objects.get_or_create(name=name)[0]
                         for name in self.cleaned_data["group_names"]])


class BlockedRecoveryEmailsForm(forms.Form):
    """Validate a complete batch of addresses before changing the recovery blocklist."""
    required_css_class = "required"
    emails = forms.CharField(
        label="Email addresses", max_length=50000,
        widget=forms.Textarea(attrs={"rows": 8}),
        help_text="Enter one address per line, or separate addresses with commas. Matching ignores case.",
    )

    def clean_emails(self):
        """Validate the complete normalized address batch before saving any entries."""
        addresses = []
        validator = forms.EmailField(max_length=254)
        for value in self.cleaned_data["emails"].replace(",", "\n").splitlines():
            if not value.strip():
                continue
            address = normalize_identifier(value)
            try:
                validator.clean(address)
            except forms.ValidationError:
                raise forms.ValidationError("Invalid email address: %(email)s", params={"email": value})
            addresses.append(address)
        if not addresses:
            raise forms.ValidationError("Enter at least one email address.")
        return list(dict.fromkeys(addresses))
