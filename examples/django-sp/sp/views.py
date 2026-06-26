"""SP HTTP endpoints: home (shows released attributes), metadata, login (start
SSO), ACS (consume the Response), logout."""
import logging

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from . import idp_resolver
from . import saml_logic as sl
from .sp_config import get_sp_config

log = logging.getLogger(__name__)

# Session keys: the in-flight request id, the IdP it was sent to, and the
# established SAML identity.
PENDING_REQUEST_ID = "saml_request_id"
PENDING_IDP = "saml_pending_idp"
IDENTITY = "saml_identity"


def _error(request, message, status=400):
    return render(
        request,
        "sp/error.html",
        {"message": message, "cfg": get_sp_config()},
        status=status,
    )


def index(request):
    cfg = get_sp_config()
    return render(
        request,
        "sp/index.html",
        {
            "cfg": cfg,
            "identity": request.session.get(IDENTITY),
            "mdq_url": settings.SAML_SP_MDQ_URL,
            "file_idp_count": idp_resolver.file_idp_count(),
        },
    )


def metadata(request):
    cfg = get_sp_config()
    return HttpResponse(
        sl.sp_metadata_xml(cfg), content_type="application/samlmetadata+xml"
    )


def _start_sso(request, cfg, idp_entity_id):
    """Resolve ``idp_entity_id``, build an AuthnRequest, and redirect to its SSO."""
    idp = idp_resolver.resolve(idp_entity_id)
    if idp is None:
        return _error(
            request,
            f"The IdP {idp_entity_id!r} could not be resolved "
            "(not found, or its metadata signature did not verify).",
        )
    sso_url = idp_resolver.sso_redirect_location(idp)
    if not sso_url:
        return _error(request, "The IdP advertises no HTTP-Redirect SSO endpoint.")

    try:
        redirect_url, request_id = sl.build_authn_redirect(cfg, sso_url, relay_state=None)
    except Exception:  # noqa: BLE001
        log.exception("failed to build AuthnRequest for IdP %s", idp_entity_id)
        return _error(request, "Could not start the login. Please try again.")

    request.session[PENDING_REQUEST_ID] = request_id
    request.session[PENDING_IDP] = idp_entity_id
    return redirect(redirect_url)


@require_http_methods(["GET", "POST"])
def login_view(request):
    """Start SSO. With a fixed IdP configured, go straight there; otherwise send
    the user to the discovery service to choose one."""
    cfg = get_sp_config()
    if cfg.idp_entity_id:
        return _start_sso(request, cfg, cfg.idp_entity_id)
    if not cfg.discovery_url:
        return _error(request, "No IdP and no discovery service configured.")
    return redirect(sl.discovery_redirect_url(cfg))


@require_http_methods(["GET"])
def disco(request):
    """DiscoveryResponse endpoint: the DS returns here with the chosen IdP's
    entityID (SAML IdP Discovery Protocol). Start SSO to that IdP."""
    cfg = get_sp_config()
    idp_entity_id = request.GET.get("entityID")
    if not idp_entity_id:
        # User cancelled at the discovery service, or no IdP was selected.
        return _error(request, "No Identity Provider was selected.")
    return _start_sso(request, cfg, idp_entity_id)


@csrf_exempt  # the SAML POST binding is a cross-origin form post from the IdP
@require_http_methods(["POST"])
def acs(request):
    """Assertion Consumer Service: verify + validate the Response, store identity."""
    cfg = get_sp_config()
    # Which IdP do we expect? The one we sent the request to (pinned in session),
    # falling back to the Response's own Issuer if the session is unavailable.
    idp_entity_id = request.session.pop(PENDING_IDP, None) or sl.issuer_from_post(
        request.POST
    )
    idp = idp_resolver.resolve(idp_entity_id)
    if idp is None:
        return _error(request, "The issuing IdP could not be resolved for verification.")

    expected_request_id = request.session.pop(PENDING_REQUEST_ID, None)
    try:
        result, _relay_state = sl.process_acs(
            cfg, request.POST, idp, expected_request_id
        )
    except Exception:  # noqa: BLE001
        log.warning("SAML Response from %s rejected", idp.entity_id, exc_info=True)
        return _error(request, "The SAML Response could not be validated.", status=403)

    request.session[IDENTITY] = {
        "name_id": result.name_id,
        "name_id_format": result.name_id_format,
        "idp_entity_id": result.idp_entity_id,
        "session_index": result.session_index,
        "authn_context": result.authn_context_class_ref,
        "attributes": sl.attributes_for_display(result),
    }
    return redirect("sp:index")


def logout_view(request):
    """Local logout: drop the SP session (no SAML Single Logout in this demo)."""
    request.session.flush()
    return redirect("sp:index")
