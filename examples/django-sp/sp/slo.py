"""SP browser SLO. All protocol state lives in SQLite, independent of cookies."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_POST
from pygamlastan import bindings, core, crypto, logout as saml_logout, xml

from . import idp_resolver
from .models import LogoutReplay, LogoutTransaction, SamlLogin
from .saml_logic import _duplicate_preserving_form_pairs, _hardened_verifier
from .sp_config import get_sp_config

LIFETIME = timedelta(minutes=5)
SKEW = 60


def name_id_data(name_id):
    return {key: getattr(name_id, key) for key in (
        "value", "format", "name_qualifier", "sp_name_qualifier", "sp_provided_id"
    )}


def record_login(request, result):
    values = {
        "issuer": result.idp_entity_id, "name_id": name_id_data(result.assertion.subject.name_id),
        "session_index": result.session_index,
    }
    with transaction.atomic():
        # Persist the browser identity and its association together, so an old
        # subject's concurrent logout cannot delete a newly-replaced login.
        request.session.save()
        cleanup_logins()
        key = request.session.session_key
        expiry = Session.objects.values_list("expire_date", flat=True).get(pk=key)
        current = SamlLogin.objects.filter(session_key=key, ended=False).first()
        if current and any(getattr(current, field) != value for field, value in values.items()):
            # Keep proof that this exact association already ended. Its later
            # signed logout must not invalidate a newer, different subject.
            current.ended = True
            current.save(update_fields=["ended"])
        SamlLogin.objects.filter(session_key=key).update(expires_at=expiry)
        SamlLogin.objects.update_or_create(
            session_key=key, ended=False, defaults={**values, "expires_at": expiry},
        )


def cleanup_logins():
    now = timezone.now()
    active_keys = Session.objects.filter(expire_date__gt=now).values("session_key")
    SamlLogin.objects.filter(ended=False).exclude(session_key__in=active_keys).update(
        ended=True, expires_at=now + LIFETIME + timedelta(seconds=SKEW),
    )
    SamlLogin.objects.filter(expires_at__lt=now).exclude(session_key__in=active_keys).delete()


def end_logins(keys):
    """Retain ended associations for retries and other requests in this flow."""
    SamlLogin.objects.filter(session_key__in=keys).update(
        ended=True, expires_at=timezone.now() + LIFETIME + timedelta(seconds=SKEW),
    )


class ReplayCache:
    def __init__(self, issuer):
        self.issuer = issuer

    def check_and_insert(self, identifier, expiry):
        digest = hashlib.sha256(json.dumps([self.issuer, identifier]).encode()).hexdigest()
        _, created = LogoutReplay.objects.get_or_create(digest=digest, defaults={
            "expires_at": max(expiry, timezone.now() + LIFETIME + timedelta(seconds=SKEW)),
        })
        return created

    def cleanup(self):
        LogoutReplay.objects.filter(expires_at__lt=timezone.now()).delete()


def endpoint(entity, preferred=core.BINDING_HTTP_REDIRECT, response=False):
    for binding in dict.fromkeys([preferred, core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST]):
        for ep in entity.single_logout_services("idp"):
            if ep.binding == binding:
                url = (ep.response_location if response else None) or ep.location
                parts = urlsplit(url)
                if parts.scheme in ("http", "https") and parts.netloc and not parts.fragment:
                    return binding, url
    raise ValueError("The IdP does not publish a supported logout endpoint.")


def verify(decoded, text, parsed, root, entity, cfg):
    verifiers = [_hardened_verifier(cert) for cert in entity.signing_certificates("idp")]
    verified = False
    redirect = [getattr(decoded, key, None) for key in ("sig_alg", "signature", "signature_input")]
    if any(redirect):
        if not all(redirect):
            raise ValueError("Incomplete logout redirect signature.")
        verified = False
        for verifier in verifiers:
            try:
                if verifier.verify_redirect_query(redirect[2].encode(), redirect[1], redirect[0]):
                    verified = True
                    break
            except Exception:
                continue
        if not verified:
            raise ValueError("Invalid logout redirect signature.")
    if root.find(f"{{{core.XMLDSIG_NS}}}Signature") is not None:
        for verifier in verifiers:
            try:
                results = verifier.verify_all_enveloped(text)
                if results and all(r.is_valid() for r in results) and any(parsed.id in r.signed_reference_ids() for r in results):
                    verified = True
                    break
            except Exception:
                continue
        else:
            raise ValueError("Invalid logout XML signature.")
    if not verified or root.get("Destination") != cfg.slo_url:
        raise ValueError("Unsigned or misaddressed logout message.")
    issued = datetime.fromisoformat(root.attrib["IssueInstant"].replace("Z", "+00:00"))
    if issued.tzinfo is None or not -SKEW <= (timezone.now() - issued).total_seconds() <= LIFETIME.total_seconds() + SKEW:
        raise ValueError("Stale logout message.")


def sign_message(text, identifier, cfg):
    ds = core.XMLDSIG_NS
    template = (
        f'<ds:Signature xmlns:ds="{ds}"><ds:SignedInfo>'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#{identifier}"><ds:Transforms>'
        f'<ds:Transform Algorithm="{ds}enveloped-signature"/>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        '<ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>'
        f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cfg.cert_b64}</ds:X509Certificate>'
        '</ds:X509Data></ds:KeyInfo></ds:Signature>'
    )
    close = text.index("</saml:Issuer>") + len("</saml:Issuer>")
    return crypto.SamlSigner.from_pem(cfg.key_pem).sign_enveloped(text[:close] + template + text[close:])


def send(message, is_request, binding, url, relay, cfg):
    text = message.to_xml()
    if binding == core.BINDING_HTTP_REDIRECT:
        return HttpResponseRedirect(bindings.redirect_encode(
            text.encode(), is_request, url, relay_state=relay,
            signer=crypto.SamlSigner.from_pem(cfg.key_pem),
            sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        ))
    signed = sign_message(text, message.id, cfg)
    return HttpResponse(bindings.post_encode(signed.encode(), is_request, url, relay_state=relay))


def cleanup():
    now = timezone.now()
    LogoutReplay.objects.filter(expires_at__lt=now).delete()
    LogoutTransaction.objects.filter(expires_at__lt=now).delete()
    cleanup_logins()


def completed(request, partial=False):
    return render(request, "sp/logged_out.html", {"partial": partial})


@never_cache
@require_POST
def local_logout(request):
    cleanup()
    cfg = get_sp_config()
    login = SamlLogin.objects.filter(session_key=request.session.session_key, ended=False).first()
    had_identity = bool(request.session.get("saml_identity"))
    request.session.flush()
    if not login:
        return completed(request, partial=had_identity)
    end_logins([login.session_key])
    try:
        entity = idp_resolver.resolve(login.issuer)
        binding, url = endpoint(entity)
        message = saml_logout.create_sp_logout_request(saml_logout.SpLogoutRequestOptions(
            cfg.entity_id, core.NameId(**login.name_id), destination=url,
            session_indexes=[login.session_index] if login.session_index else [],
            not_on_or_after=timezone.now() + LIFETIME,
        ))
        state = LogoutTransaction.objects.create(
            token=secrets.token_urlsafe(32), issuer=login.issuer,
            request_id=message.id, expires_at=timezone.now() + LIFETIME,
        )
        return send(message, True, binding, url, state.token, cfg)
    except Exception:
        return completed(request, partial=True)


@never_cache
@csrf_exempt  # Signed SAML protocol only. The local logout action has CSRF protection.
@require_http_methods(["GET", "POST"])
def service(request):
    try:
        cleanup()
        cfg = get_sp_config()
        decoded = (bindings.post_decode(_duplicate_preserving_form_pairs(request.POST)) if request.method == "POST"
                   else bindings.redirect_decode(request.META.get("QUERY_STRING", "")))
        text = decoded.saml_xml.decode("utf-8")
        parsed = xml.parse_logout_request(text) if decoded.is_request else xml.parse_logout_response(text)
        root = ET.fromstring(text)  # Native secure parser above rejects DTDs/resource abuse.
        issuer = parsed.issuer.value if parsed.issuer else None
        entity = idp_resolver.resolve(issuer)
        if entity is None or entity.entity_id != issuer or not entity.is_idp():
            raise ValueError("Unknown IdP.")
        verify(decoded, text, parsed, root, entity, cfg)
        if not decoded.is_request:
            with transaction.atomic():
                state = LogoutTransaction.objects.get(pk=decoded.relay_state, expires_at__gt=timezone.now())
                if issuer != state.issuer or parsed.in_response_to != state.request_id:
                    raise ValueError("LogoutResponse does not match the pending request.")
                state.delete()
            return completed(request, partial=not parsed.is_success() or parsed.status.status_code.sub_status is not None)
        if parsed.not_on_or_after and parsed.not_on_or_after > timezone.now() + LIFETIME + timedelta(seconds=SKEW):
            raise ValueError("Logout validity window too long.")
        saml_logout.validate_logout_request_with_replay(
            parsed, issuer, True, timezone.now(), ReplayCache(issuer),
            clock_skew_seconds=SKEW, max_request_age_seconds=int(LIFETIME.total_seconds()),
        )
        binding, url = endpoint(entity, core.BINDING_HTTP_POST if request.method == "POST" else core.BINDING_HTTP_REDIRECT, response=True)
        with transaction.atomic():
            matches = [s for s in SamlLogin.objects.filter(issuer=issuer) if s.name_id == name_id_data(parsed.name_id)
                       and (not parsed.session_indexes or s.session_index in parsed.session_indexes)]
            known_indexes = {s.session_index for s in matches}
            if not matches or (parsed.session_indexes and not set(parsed.session_indexes) <= known_indexes):
                message = saml_logout.create_logout_response_error(cfg.entity_id, parsed.id, core.STATUS_REQUESTER, "No matching SAML session.", url)
            else:
                keys = [s.session_key for s in matches if not s.ended]
                Session.objects.filter(session_key__in=keys).delete()
                end_logins(keys)
                if request.session.session_key in keys:
                    request.session.flush()
                message = saml_logout.create_logout_response_success(cfg.entity_id, parsed.id, url)
        return send(message, False, binding, url, decoded.relay_state, cfg)
    except Exception:
        return HttpResponseBadRequest("SAML logout was rejected.")
