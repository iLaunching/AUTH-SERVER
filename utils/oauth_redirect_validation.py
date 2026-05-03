"""
Allow-list for OAuth post-login redirects (redirect_url on /auth/*/login).
Blocks open redirects while permitting HTTPS frontends and native app URL schemes.
"""

import os
from typing import Optional
from urllib.parse import urlparse

from config.oauth import OAuthConfig


def _frontend_https_hosts() -> set[str]:
    hosts: set[str] = set()
    try:
        p = urlparse(OAuthConfig.FRONTEND_URL)
        if p.hostname:
            hosts.add(p.hostname.lower())
    except Exception:
        pass
    extra = os.getenv("ALLOWED_OAUTH_REDIRECT_HOSTS", "")
    for part in extra.split(","):
        h = part.strip().lower()
        if h:
            hosts.add(h)
    # Production web (landing / signup-interface)
    hosts.update({"ilaunching.com", "www.ilaunching.com"})
    return hosts


def is_allowed_post_oauth_redirect(url: Optional[str]) -> bool:
    """
    redirect_url values accepted after Google/Facebook/Microsoft OAuth completes:
    - https://… on an allow-listed host (FRONTEND_URL host + ilaunching.com + ALLOWED_OAUTH_REDIRECT_HOSTS)
    - ilaunching://oauth-callback — native iOS app (must match app Info.plist URL scheme)
    """
    if not url or not str(url).strip():
        return False
    raw = str(url).strip()
    try:
        parsed = urlparse(raw)
    except Exception:
        return False

    scheme = (parsed.scheme or "").lower()

    if scheme in ("http", "https"):
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host in ("localhost", "127.0.0.1"):
            return True
        return host in _frontend_https_hosts()

    # Native app callback (single fixed URL from iOS client)
    app_scheme = os.getenv("NATIVE_OAUTH_CALLBACK_SCHEME", "ilaunching").lower()
    app_host = os.getenv("NATIVE_OAUTH_CALLBACK_NETLOC", "oauth-callback").lower()
    if scheme == app_scheme and (parsed.netloc or "").lower() == app_host:
        return True

    return False
