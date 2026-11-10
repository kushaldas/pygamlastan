"""Explicitly allowlisted fields for IdP account administration."""
import csv
import io

from django import forms
from django.contrib.auth.models import Group

from .models import User, normalize_identifier


class AccountForm(forms.ModelForm):
    """Allow only administrator-editable profile, role, and membership fields."""
    required_css_class = "required"

    group_names = forms.CharField(
        required=False, label="Groups", strip=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text='CSV group names, for example: Students, "cn=staff,ou=groups". '
                  'Quote names containing commas, quotes, or newlines. New groups are created automatically.',
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
            value = io.StringIO(newline="")
            # Quote every existing name so leading/trailing spaces, commas,
            # quotes, and embedded newlines survive an unchanged form submission.
            csv.writer(value, quoting=csv.QUOTE_ALL, lineterminator="").writerow(
                self.instance.groups.order_by("name").values_list("name", flat=True))
            self.fields["group_names"].initial = value.getvalue()

    def clean_group_names(self):
        """Parse one CSV record losslessly and validate names before any writes."""
        try:
            rows = list(csv.reader(io.StringIO(self.cleaned_data["group_names"], newline=""),
                                   skipinitialspace=True, strict=True))
        except csv.Error as exc:
            raise forms.ValidationError("Enter valid CSV group names with properly closed quotes.") from exc
        if len(rows) > 1:
            raise forms.ValidationError("Enter a single CSV row; quote group names containing newlines.")
        names = list(dict.fromkeys(name for name in (rows[0] if rows else []) if name.strip()))
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
