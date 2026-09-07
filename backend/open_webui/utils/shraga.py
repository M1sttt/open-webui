"""
Native Shraga / ADFS SSO for Open WebUI.

This is a Python port of the external ``owui-auth-proxy`` (which used
``@yesodot/passport-shraga`` in front of Open WebUI in trusted-header mode).
Instead of a reverse proxy, Shraga is wired straight into the app:

    GET  /shraga/login      -> 302 to the Shraga IdP
    POST /shraga/callback    <- Shraga posts back a signed JWT
                             -> user is provisioned, the normal Open WebUI
                                ``token`` cookie is issued, redirect to /auth

Shraga is *not* OIDC (custom redirect + POST-back signed JWT), so this cannot
reuse ``utils/oauth.py``. JWT verification mirrors passport-shraga's three modes:

    (a) pinned RSA/EC public key   -> SHRAGA_PUBLIC_KEY / SHRAGA_PUBLIC_KEY_FILE
    (b) key fetched over TLS        -> SHRAGA_PUBLIC_KEY_URL
    (c) per-login HS256 sign key    -> SHRAGA_USE_SIGN_KEY (+ SignInSecret cookie)

User provisioning, group sync and admin-role mapping mirror the trusted-header
branch of ``routers/auths.py::signin``.
"""

from __future__ import annotations

import base64
import logging
import secrets
import urllib.parse
import uuid

import aiohttp
import jwt
from fastapi import HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from open_webui.env import (
    AIOHTTP_CLIENT_SESSION_SSL,
    ENABLE_SHRAGA_AUTH,
    ENABLE_SHRAGA_GROUP_MANAGEMENT,
    SHRAGA_ADMIN_GROUPS,
    SHRAGA_BUTTON_LABEL,
    SHRAGA_CALLBACK_URL,
    SHRAGA_DEV_BYPASS_EMAIL,
    SHRAGA_DEV_BYPASS_GROUPS,
    SHRAGA_DEV_BYPASS_NAME,
    SHRAGA_PUBLIC_KEY,
    SHRAGA_PUBLIC_KEY_FILE,
    SHRAGA_PUBLIC_KEY_URL,
    SHRAGA_URL,
    SHRAGA_USE_SIGN_KEY,
    WEBUI_AUTH_COOKIE_SAME_SITE,
    WEBUI_AUTH_COOKIE_SECURE,
)
from open_webui.internal.db import get_async_db_context
from open_webui.models.auths import Auths
from open_webui.models.config import Config
from open_webui.models.groups import Groups
from open_webui.models.users import Users
from open_webui.utils.auth import create_token
from open_webui.utils.misc import parse_duration

log = logging.getLogger(__name__)

SIGN_KEY_COOKIE = 'SignInSecret'
# JWT signature algorithms accepted from Shraga in pinned/fetched-key mode.
_ASYM_ALGS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'PS256']

_public_key_cache: str | None = None


def shraga_enabled() -> bool:
    return bool(ENABLE_SHRAGA_AUTH)


def shraga_config() -> dict:
    """Shape surfaced on GET /api/config for the login page."""
    return {'enable': bool(ENABLE_SHRAGA_AUTH), 'label': SHRAGA_BUTTON_LABEL}


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------
async def _load_public_key() -> str | None:
    """Return the Shraga signing public key (PEM), fetching once if needed."""
    global _public_key_cache

    if SHRAGA_PUBLIC_KEY:
        return SHRAGA_PUBLIC_KEY
    if SHRAGA_PUBLIC_KEY_FILE:
        try:
            with open(SHRAGA_PUBLIC_KEY_FILE, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            log.error('shraga: cannot read SHRAGA_PUBLIC_KEY_FILE (%s): %s', SHRAGA_PUBLIC_KEY_FILE, e)
            return None

    if _public_key_cache:
        return _public_key_cache
    if not SHRAGA_PUBLIC_KEY_URL:
        return None
    try:
        async with aiohttp.ClientSession(trust_env=True) as session:
            async with session.get(SHRAGA_PUBLIC_KEY_URL, ssl=AIOHTTP_CLIENT_SESSION_SSL) as resp:
                resp.raise_for_status()
                _public_key_cache = await resp.text()
                return _public_key_cache
    except Exception as e:
        log.error('shraga: failed to fetch signing key from %s: %s', SHRAGA_PUBLIC_KEY_URL, e)
        return None


async def _verify_jwt(token: str, request: Request) -> dict:
    """Verify the callback JWT and return its claims. Raises HTTPException(400) on failure."""
    if SHRAGA_USE_SIGN_KEY:
        secret = request.cookies.get(SIGN_KEY_COOKIE)
        if not secret:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail='Shraga sign-in secret cookie missing')
        try:
            return jwt.decode(token, secret, algorithms=['HS256'], options={'verify_aud': False})
        except Exception as e:
            log.warning('shraga: HS256 sign-key verification failed: %s', e)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail='Invalid Shraga token')

    public_key = await _load_public_key()
    if not public_key:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Shraga is not configured with a verification key',
        )
    try:
        return jwt.decode(token, public_key, algorithms=_ASYM_ALGS, options={'verify_aud': False})
    except Exception as e:
        log.warning('shraga: asymmetric JWT verification failed: %s', e)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail='Invalid Shraga token')


def _profile_from_claims(claims: dict) -> dict:
    """
    Map raw Shraga JWT claims to {email, name, groups}.

    Mirrors owui-auth-proxy/auth-proxy/server.js: Shraga's ``name`` is an object
    ``{firstName, lastName}`` and there is normally no groups claim (org data
    lives in Kartoffel, not the token). Adjust the claim names here if your
    Shraga deployment emits a different shape.
    """
    email = (
        claims.get('email')
        or claims.get('upn')
        or claims.get('mail')
        or claims.get('userPrincipalName')
        or ''
    )

    name_claim = claims.get('name')
    if isinstance(name_claim, dict):
        full_name = ' '.join(
            p for p in [name_claim.get('firstName'), name_claim.get('lastName')] if p
        ).strip()
    elif isinstance(name_claim, str):
        full_name = name_claim
    else:
        full_name = ' '.join(
            p
            for p in [
                claims.get('firstName') or claims.get('first_name') or claims.get('givenName'),
                claims.get('lastName') or claims.get('last_name') or claims.get('surname'),
            ]
            if p
        ).strip()

    if not full_name:
        full_name = claims.get('displayName') or email

    groups = claims.get('groups')
    groups = [str(g).strip() for g in groups if str(g).strip()] if isinstance(groups, list) else []

    return {'email': str(email).lower().strip(), 'name': full_name, 'groups': groups}


# ---------------------------------------------------------------------------
# User provisioning (mirrors the trusted-header branch of auths.signin)
# ---------------------------------------------------------------------------
async def _provision_user(request: Request, profile: dict):
    from open_webui.routers.auths import signup_handler  # lazy: avoids an import cycle

    email = profile['email']
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail='Shraga token has no email/upn claim')

    async with get_async_db_context() as db:
        user = await Users.get_user_by_email(email, db=db)
        if not user:
            try:
                await signup_handler(
                    request,
                    email,
                    str(uuid.uuid4()),  # random password, never used
                    profile['name'] or email,
                    db=db,
                    source='shraga',
                )
            except Exception:
                if not await Users.get_user_by_email(email, db=db):
                    raise

        user = await Auths.authenticate_user_by_email(email, db=db)
        if not user:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail='Shraga user could not be resolved')

        groups = profile['groups']
        if ENABLE_SHRAGA_GROUP_MANAGEMENT and groups:
            try:
                await Groups.sync_groups_by_group_names(user.id, groups, db=db)
            except Exception as e:
                log.error('shraga: group sync failed for %s: %s', user.id, e)

        if SHRAGA_ADMIN_GROUPS:
            is_admin_group = any(g in SHRAGA_ADMIN_GROUPS for g in groups)
            if is_admin_group and user.role != 'admin':
                updated = await Users.update_user_role_by_id(user.id, 'admin', db=db)
                user = updated or user

        return user


async def _issue_session_redirect(request: Request, user) -> RedirectResponse:
    """Set the Open WebUI ``token`` cookie and redirect to /auth (frontend picks it up)."""
    expires_delta = parse_duration(await Config.get('auth.jwt_expiry'))
    token = create_token(data={'id': user.id}, expires_delta=expires_delta)
    max_age = int(expires_delta.total_seconds()) if expires_delta else None

    webui_url = await Config.get('webui.url')
    base = (str(webui_url or request.base_url)).rstrip('/')
    resp = RedirectResponse(url=f'{base}/auth', status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key='token',
        value=token,
        httponly=False,  # the /auth page reads it from document.cookie (same as OAuth)
        samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
        secure=WEBUI_AUTH_COOKIE_SECURE,
        **({'max_age': max_age} if max_age is not None else {}),
    )
    resp.delete_cookie(SIGN_KEY_COOKIE)
    return resp


def _error_redirect(request: Request, message: str) -> RedirectResponse:
    base = str(request.base_url).rstrip('/')
    return RedirectResponse(
        url=f'{base}/auth?error={urllib.parse.quote_plus(message)}',
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------------------------
# Route handlers (wired in main.py)
# ---------------------------------------------------------------------------
def _callback_url(request: Request) -> str:
    if SHRAGA_CALLBACK_URL:
        return SHRAGA_CALLBACK_URL
    return f'{str(request.base_url).rstrip("/")}/shraga/callback'


async def handle_shraga_login(request: Request):
    if not ENABLE_SHRAGA_AUTH:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    # DEV bypass: skip Shraga, sign in as a fixed identity.
    if SHRAGA_DEV_BYPASS_EMAIL:
        log.warning('shraga: DEV bypass active - signing in as %s', SHRAGA_DEV_BYPASS_EMAIL)
        user = await _provision_user(
            request,
            {
                'email': SHRAGA_DEV_BYPASS_EMAIL.lower(),
                'name': SHRAGA_DEV_BYPASS_NAME,
                'groups': list(SHRAGA_DEV_BYPASS_GROUPS),
            },
        )
        return await _issue_session_redirect(request, user)

    if not SHRAGA_URL:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='SHRAGA_URL is not set')

    params = {'callbackURL': _callback_url(request)}
    sign_secret = None
    if SHRAGA_USE_SIGN_KEY:
        sign_secret = base64.b64encode(secrets.token_bytes(32)).decode()
        params['signKey'] = sign_secret

    redirect = RedirectResponse(
        url=f'{SHRAGA_URL.rstrip("/")}/login?{urllib.parse.urlencode(params)}',
        status_code=status.HTTP_302_FOUND,
    )
    if sign_secret is not None:
        redirect.set_cookie(
            key=SIGN_KEY_COOKIE,
            value=sign_secret,
            httponly=True,
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
            max_age=600,
        )
    return redirect


async def handle_shraga_callback(request: Request, response: Response):
    if not ENABLE_SHRAGA_AUTH:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    # Shraga posts the browser back with the signed JWT as ?jwt= or a form field.
    token = request.query_params.get('jwt') or request.query_params.get('id_token')
    if not token:
        try:
            form = await request.form()
            token = (
                form.get('jwt')
                or form.get('id_token')
                or form.get('token')
                or form.get('assertion')
            )
        except Exception:
            token = None

    if not token:
        return _error_redirect(request, 'Shraga callback did not include a token')

    try:
        claims = await _verify_jwt(token, request)
        profile = _profile_from_claims(claims)
        user = await _provision_user(request, profile)
        return await _issue_session_redirect(request, user)
    except HTTPException as e:
        return _error_redirect(request, str(e.detail) if e.detail else 'Shraga sign-in failed')
    except Exception as e:  # pragma: no cover - defensive
        log.exception('shraga: unexpected callback error: %s', e)
        return _error_redirect(request, 'Shraga sign-in failed')
