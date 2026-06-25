"""IdP HTTP endpoints: home, metadata, SSO (Redirect + POST), login, logout, error."""
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from django.conf import settings

from . import saml_logic as sl
from . import sp_resolver
from .idp_config import get_idp_config

# Session key holding the in-flight AuthnRequest while the user logs in.
PENDING = "saml_pending"


def _error(request, message, status=400):
    """Render the error page (the metadata errorURL target) with a message."""
    return render(
        request,
        "idp/error.html",
        {"message": message, "cfg": get_idp_config()},
        status=status,
    )


def index(request):
    cfg = get_idp_config()
    return render(
        request,
        "idp/index.html",
        {
            "cfg": cfg,
            "mdq_url": settings.SAML_IDP_MDQ_URL,
            "metadata_cert": settings.SAML_IDP_METADATA_CERT,
            "file_sp_count": sp_resolver.file_sp_count(),
        },
    )


def metadata(request):
    cfg = get_idp_config()
    return HttpResponse(
        sl.idp_metadata_xml(cfg), content_type="application/samlmetadata+xml"
    )


@require_http_methods(["GET"])
def error(request):
    """The errorURL target (SWAMID Tech 5.1.13). SPs may send a user here when
    SSO fails; the SAML errorURL context params are surfaced if present."""
    context = {
        k: request.GET[k]
        for k in (
            "errorURL_code", "errorURL_ts", "errorURL_rp", "errorURL_tid",
            "errorURL_ctx",
        )
        if k in request.GET
    }
    return render(
        request,
        "idp/error.html",
        {"message": None, "context": context, "cfg": get_idp_config()},
    )


@csrf_exempt  # the SAML POST binding is a cross-origin form post from the SP
@require_http_methods(["GET", "POST"])
def sso(request):
    try:
        saml_text, relay_state = sl.decode_authn_request(
            request.method, request.META.get("QUERY_STRING", ""), request.POST.dict()
        )
        authn = sl.parse_authn(saml_text)
    except Exception as exc:  # noqa: BLE001
        return _error(request, f"Could not decode the AuthnRequest: {exc}")

    issuer = authn.issuer.value if authn.issuer else None
    # Resolve the SP from a local file or MDQ; remote metadata must verify.
    sp_metadata_xml = sp_resolver.resolve(issuer)
    if sp_metadata_xml is None:
        return _error(
            request,
            f"The Service Provider {issuer!r} could not be resolved "
            "(not found, or its metadata signature did not verify).",
        )

    try:
        processed = sl.process_authn(authn, sp_metadata_xml)
    except Exception as exc:  # noqa: BLE001
        return _error(request, f"The AuthnRequest was rejected: {exc}")

    request.session[PENDING] = {
        "request_id": processed.request_id,
        "sp_entity_id": processed.sp_entity_id,
        "acs_url": processed.acs_url,
        "name_id_format": processed.requested_name_id_format,
        "relay_state": relay_state,
    }
    if not request.user.is_authenticated:
        return redirect(reverse("idp:login"))
    return _issue(request)


def _issue(request):
    """Build, sign and POST the response for the pending request. Caller ensures
    the user is authenticated."""
    pending = request.session.pop(PENDING, None)
    if not pending:
        return redirect("idp:index")
    cfg = get_idp_config()
    signed = sl.build_signed_response(
        sp_entity_id=pending["sp_entity_id"],
        acs_url=pending["acs_url"],
        request_id=pending["request_id"],
        name_id_format=pending["name_id_format"],
        user=request.user,
        cfg=cfg,
    )
    html = sl.encode_post_response(signed, pending["acs_url"], pending["relay_state"])
    return HttpResponse(html)


@require_http_methods(["GET", "POST"])
def login_view(request):
    pending = PENDING in request.session
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password"),
        )
        if user is not None:
            login(request, user)
            if PENDING in request.session:
                return _issue(request)
            return redirect("idp:index")
        return render(
            request,
            "idp/login.html",
            {"error": "Invalid username or password.", "pending": pending},
            status=401,
        )
    return render(request, "idp/login.html", {"pending": pending})


def logout_view(request):
    logout(request)
    return redirect("idp:index")
