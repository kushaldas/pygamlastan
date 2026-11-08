"""Signed browser Single Logout with durable participants, replay and flow state."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from django.contrib.auth import logout
from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_POST
from pygamlastan import bindings, core, crypto, logout as saml_logout, metadata, xml

from . import saml_logic as sl, sp_resolver
from .idp_config import get_idp_config
from .models import LogoutFlow, LogoutReplay, SamlParticipant

LIFETIME = timedelta(minutes=5)
SKEW = 60
RECOVERY_COOKIE = "saml_logout_flow"
RECOVERY_SALT = "idp.saml-logout-recovery"
MAX_PREPARATION_ATTEMPTS = 3


class NoMatchingLogout(ValueError):
    pass


class LogoutStateChanged(ValueError):
    pass


def name_id_data(name_id):
    return {key: getattr(name_id, key) for key in (
        "value", "format", "name_qualifier", "sp_name_qualifier", "sp_provided_id"
    )}


def record_issued(request, response_xml, entity_id):
    assertion = xml.parse_response(response_xml).assertions[0]
    with transaction.atomic():
        # Publish the session renewal and new participant together. Once logout
        # deletes the session, an in-flight SSO must not add an unqueued SP.
        request.session.save()
        expiry = Session.objects.values_list("expire_date", flat=True).get(pk=request.session.session_key)
        SamlParticipant.objects.filter(session_key=request.session.session_key).update(expires_at=expiry)
        cleanup_participants()
        SamlParticipant.objects.create(
            session_key=request.session.session_key, entity_id=entity_id,
            name_id=name_id_data(assertion.subject.name_id),
            session_index=assertion.authn_statements[0].session_index,
            expires_at=expiry,
        )


class ReplayCache:
    def __init__(self, issuer):
        self.issuer = issuer

    def check_and_insert(self, identifier, expiry):
        digest = hashlib.sha256(json.dumps([self.issuer, identifier]).encode()).hexdigest()
        _, created = LogoutReplay.objects.get_or_create(
            digest=digest, defaults={"expires_at": max(expiry, timezone.now() + LIFETIME + timedelta(seconds=SKEW))},
        )
        return created

    def cleanup(self):
        LogoutReplay.objects.filter(expires_at__lt=timezone.now()).delete()


def decode(request):
    decoded = sl.decode_authn_request(request.method, request.META.get("QUERY_STRING", ""), request.POST)
    text = decoded.saml_xml.decode("utf-8")
    parsed = xml.parse_logout_request(text) if decoded.is_request else xml.parse_logout_response(text)
    # The native secure parser above rejects DTDs and bounds XML resources.
    root = ET.fromstring(text)
    return decoded, text, parsed, root


def peer(entity_id):
    text = sp_resolver.resolve(entity_id)
    if not text:
        raise ValueError("Unregistered logout issuer.")
    entity = metadata.parse_entity(text)
    if entity.entity_id != entity_id or not entity.is_sp():
        raise ValueError("Metadata does not identify the requesting SP.")
    return entity


def endpoint(entity, preferred=core.BINDING_HTTP_REDIRECT, response=False):
    for binding in dict.fromkeys([preferred, core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST]):
        for ep in entity.single_logout_services("sp"):
            if ep.binding == binding:
                url = (ep.response_location if response else None) or ep.location
                parts = urlsplit(url)
                if parts.scheme in ("https", "http") and parts.netloc and not parts.fragment:
                    return binding, url
    raise ValueError("No supported SingleLogoutService in SP metadata.")


def verify(decoded, text, parsed, root, entity, cfg):
    message = SimpleNamespace(id=parsed.id, has_signature=root.find(f"{{{core.XMLDSIG_NS}}}Signature") is not None)
    if not sl._verify_authn_request_signature(message, text, decoded, entity):
        raise ValueError("Logout messages must be signed.")
    if root.get("Destination") != cfg.slo_url:
        raise ValueError("Logout Destination does not match this IdP.")
    issued = datetime.fromisoformat(root.attrib["IssueInstant"].replace("Z", "+00:00"))
    if issued.tzinfo is None or not -SKEW <= (timezone.now() - issued).total_seconds() <= LIFETIME.total_seconds() + SKEW:
        raise ValueError("Logout message is stale or issued in the future.")


def sign_message(text, identifier, cfg):
    close = text.index("</saml:Issuer>") + len("</saml:Issuer>")
    text = text[:close] + sl._signature_template(identifier, cfg.cert_b64) + text[close:]
    return crypto.SamlSigner.from_pem(cfg.key_pem).sign_enveloped(text)


def send(text, identifier, is_request, binding, url, relay_state, cfg):
    if binding == core.BINDING_HTTP_REDIRECT:
        return HttpResponseRedirect(bindings.redirect_encode(
            text.encode(), is_request, url, relay_state=relay_state,
            signer=crypto.SamlSigner.from_pem(cfg.key_pem),
            sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        ))
    signed = sign_message(text, identifier, cfg)
    return HttpResponse(bindings.post_encode(signed.encode(), is_request, url, relay_state=relay_state))


def cleanup_participants():
    # A later SSO (or password change) can extend the browser session. Its
    # persisted expiry, not an earlier assertion's snapshot, is authoritative.
    active_keys = Session.objects.filter(expire_date__gt=timezone.now()).values("session_key")
    SamlParticipant.objects.exclude(session_key__in=active_keys).delete()


def cleanup():
    now = timezone.now()
    LogoutFlow.objects.filter(expires_at__lt=now).delete()
    cleanup_participants()
    LogoutReplay.objects.filter(expires_at__lt=now).delete()


def prepare_flow(participants, cfg, origin=None, excluded_ids=()):
    """Resolve metadata and prepare messages before taking SQLite's write lock."""
    grouped = {}
    partial = False
    for participant in participants:
        if participant.pk in excluded_ids:
            continue
        key = (participant.entity_id, json.dumps(participant.name_id, sort_keys=True))
        grouped.setdefault(key, []).append(participant.session_index)
    queue = []
    for (entity_id, subject), indexes in grouped.items():
        try:
            binding, url = endpoint(peer(entity_id))
            message = saml_logout.create_sp_logout_request(saml_logout.SpLogoutRequestOptions(
                cfg.entity_id, core.NameId(**json.loads(subject)), session_indexes=indexes,
                destination=url, not_on_or_after=timezone.now() + LIFETIME,
            ))
            queue.append({"entity_id": entity_id, "binding": binding, "url": url,
                          "id": message.id, "xml": message.to_xml()})
        except Exception:
            partial = True
    return LogoutFlow(token=secrets.token_urlsafe(32), origin=origin, queue=queue,
                      partial=partial, expires_at=timezone.now() + LIFETIME)


def drive(request, flow, cfg):
    if flow.queue:
        target = flow.queue[0]
        response = send(target["xml"], target["id"], True, target["binding"], target["url"], flow.token, cfg)
        # Cross-site POST may omit the authentication cookie. Writing recovery
        # state to request.session would then overwrite an unrelated browser's
        # authenticated session cookie with a newly-created anonymous session.
        response.set_signed_cookie(
            RECOVERY_COOKIE, flow.token, salt=RECOVERY_SALT,
            max_age=int(LIFETIME.total_seconds()), path="/idp/logout/",
            secure=urlsplit(cfg.base_url).scheme == "https", httponly=True, samesite="Lax",
        )
        return response
    # Completion is consumed once. Keep failure status visible to local users.
    with transaction.atomic():
        if not LogoutFlow.objects.filter(pk=flow.pk).delete()[0]:
            return HttpResponseBadRequest("The logout flow has already advanced.")
    if flow.origin:
        origin = flow.origin
        message = (saml_logout.create_logout_response_partial if flow.partial else
                   saml_logout.create_logout_response_success)(cfg.entity_id, origin["id"], origin["url"])
        return send(message.to_xml(), message.id, False, origin["binding"], origin["url"], origin["relay"], cfg)
    return render(request, "idp/logged_out.html", {"partial": flow.partial})


def invalidate(request, session_keys):
    Session.objects.filter(session_key__in=session_keys).delete()
    SamlParticipant.objects.filter(session_key__in=session_keys).delete()
    if request.session.session_key in session_keys:
        logout(request)


def snapshot_state(snapshot):
    keys, participants, excluded = snapshot
    # Expiry can be renewed without changing logout targets. Compare the actual
    # association identity, membership and browser key used for invalidation.
    members = tuple((p.pk, p.session_key, p.entity_id, p.session_index,
                     json.dumps(p.name_id, sort_keys=True)) for p in participants)
    return keys, members, excluded


def start_flow(request, cfg, select_snapshot, origin=None):
    for _ in range(MAX_PREPARATION_ATTEMPTS):
        with transaction.atomic():
            snapshot = select_snapshot()
        keys, participants, excluded = snapshot
        # MDQ/network work must never hold SQLite's write lock.
        flow = prepare_flow(participants, cfg, origin, excluded_ids=excluded)
        with transaction.atomic():
            current = select_snapshot()
            if snapshot_state(current) != snapshot_state(snapshot):
                continue
            # IMMEDIATE mode excludes password rotation and new SSO writes from
            # this final check through session/participant deletion.
            flow.save()
            invalidate(request, keys)
        return flow
    raise LogoutStateChanged("Logout state kept changing during preparation.")


def local_snapshot(key):
    anchors = set()

    def select():
        # Participant IDs survive password changes, letting this logout follow
        # the same browser to its rotated key without touching other browsers.
        keys = {key} if key else set()
        keys.update(SamlParticipant.objects.filter(pk__in=anchors).values_list("session_key", flat=True))
        participants = list(SamlParticipant.objects.filter(session_key__in=keys).order_by("pk"))
        if key and not participants and not Session.objects.filter(pk=key).exists():
            raise LogoutStateChanged("The browser session changed. Please retry logout.")
        anchors.update(p.pk for p in participants)
        return frozenset(keys), participants, frozenset()

    return select


def remote_snapshot(issuer, parsed):
    def select():
        matches = [p for p in SamlParticipant.objects.filter(entity_id=issuer)
                   if p.name_id == name_id_data(parsed.name_id)
                   and (not parsed.session_indexes or p.session_index in parsed.session_indexes)]
        if not matches or not set(parsed.session_indexes) <= {p.session_index for p in matches}:
            raise NoMatchingLogout("No matching SAML session for every requested index.")
        keys = frozenset(p.session_key for p in matches)
        participants = list(SamlParticipant.objects.filter(session_key__in=keys).order_by("pk"))
        return keys, participants, frozenset(p.pk for p in matches)

    return select


@never_cache
@require_POST
def local_logout(request):
    cleanup()
    cfg = get_idp_config()
    key = request.session.session_key
    try:
        flow = start_flow(request, cfg, local_snapshot(key))
    except LogoutStateChanged:
        return HttpResponse("Logout state changed. Please retry logout.", status=409)
    if not key:
        logout(request)
    return drive(request, flow, cfg)


@never_cache
@csrf_exempt  # Only signed SAML protocol messages; local logout remains CSRF protected.
@require_http_methods(["GET", "POST"])
def service(request):
    try:
        cleanup()
        cfg = get_idp_config()
        decoded, text, parsed, root = decode(request)
        issuer = parsed.issuer.value if parsed.issuer else None
        entity = peer(issuer)
        verify(decoded, text, parsed, root, entity, cfg)
        if not decoded.is_request:
            # Cookie-independent correlation is required for cross-site POST.
            # The random RelayState and signed request ID must BOTH match.
            with transaction.atomic():
                flow = LogoutFlow.objects.get(pk=decoded.relay_state, expires_at__gt=timezone.now())
                if not flow.queue or flow.queue[0]["entity_id"] != issuer or flow.queue[0]["id"] != parsed.in_response_to:
                    raise ValueError("Unsolicited or mismatched LogoutResponse.")
                flow.queue = flow.queue[1:]
                flow.partial |= not parsed.is_success() or parsed.status.status_code.sub_status is not None
                flow.save()
            return drive(request, flow, cfg)

        if parsed.not_on_or_after and parsed.not_on_or_after > timezone.now() + LIFETIME + timedelta(seconds=SKEW):
            raise ValueError("Logout validity window is too long.")
        saml_logout.validate_logout_request_with_replay(
            parsed, issuer, True, timezone.now(), ReplayCache(issuer),
            clock_skew_seconds=SKEW, max_request_age_seconds=int(LIFETIME.total_seconds()),
        )
        incoming_binding = core.BINDING_HTTP_POST if request.method == "POST" else core.BINDING_HTTP_REDIRECT
        binding, url = endpoint(entity, incoming_binding, response=True)
        origin = {"entity_id": issuer, "id": parsed.id, "binding": binding, "url": url, "relay": decoded.relay_state}
        try:
            flow = start_flow(request, cfg, remote_snapshot(issuer, parsed), origin)
        except (NoMatchingLogout, LogoutStateChanged) as exc:
            message = saml_logout.create_logout_response_error(
                cfg.entity_id, parsed.id, core.STATUS_REQUESTER, str(exc), url,
            )
            return send(message.to_xml(), message.id, False, binding, url, decoded.relay_state, cfg)
        return drive(request, flow, cfg)
    except Exception:
        # No redirects or session destruction are permitted on invalid messages.
        return HttpResponseBadRequest("SAML logout was rejected.")


@never_cache
@require_http_methods(["GET", "POST"])
def status(request):
    """Let a browser skip an unreachable SP without claiming complete logout."""
    token = request.get_signed_cookie(
        RECOVERY_COOKIE, default=None, salt=RECOVERY_SALT, max_age=int(LIFETIME.total_seconds()),
    )
    if request.method == "POST":
        with transaction.atomic():
            current = LogoutFlow.objects.filter(pk=token).first()
            if current is None or current.expires_at <= timezone.now():
                return HttpResponseBadRequest("The logout flow has already advanced or expired.")
            # A stale tab must not skip a different participant.
            if current.queue and current.queue[0]["id"] == request.POST.get("request_id"):
                current.queue = current.queue[1:]
                current.partial = True
                current.save()
            else:
                return HttpResponseBadRequest("The logout flow has already advanced.")
        return drive(request, current, get_idp_config())
    flow = LogoutFlow.objects.filter(pk=token).first()
    if flow is None or flow.expires_at <= timezone.now():
        return render(request, "idp/logged_out.html", {"partial": True})
    return render(request, "idp/logout_status.html", {"target": flow.queue[0] if flow.queue else None})
