"""Server-side session guard for multi-tab shared backend sessions.

Hardens session handling against fixation, cookie theft/XSS, cross-origin
credentialed requests, parent-domain leakage, enumerable ids, stale sessions
and unbounded concurrent logins.
"""

import secrets

# RFC 6265bis cookie name prefix. __Host- additionally requires Secure,
# no Domain attribute and Path="/".
HOST_PREFIX = '__Host-'

# SameSite=None lets the browser attach the cookie on cross-site requests;
# a session cookie must only travel first-party (or top-level navigations).
ALLOWED_SAMESITE = ('Lax', 'Strict')

# 256 bits of entropy; secrets.token_urlsafe renders this as 43 characters,
# well above the 32-character minimum and not enumerable like auto-increment
# integers or timestamp-derived ids.
_ID_ENTROPY_BYTES = 32


def new_session_id():
    """Return a high-entropy, unguessable session id from the OS CSPRNG."""
    return secrets.token_urlsafe(_ID_ENTROPY_BYTES)


def rotate_on_login(old_id, user, store=None):
    """Issue a fresh session id at login and retire the pre-auth id.

    Rotation defeats session fixation: an id an attacker planted before
    authentication must never become a valid authenticated session. When a
    server-side ``store`` (keyed by session id) is supplied, the old id is
    revoked there as well so the previous session cannot linger.
    """
    new_id = new_session_id()
    while new_id == old_id:
        new_id = new_session_id()
    if store is not None and old_id in store:
        del store[old_id]
    return new_id


def cookie_flags(flags):
    """Validate the security attributes of a session cookie.

    Returns ``True`` only when all of the following hold:

    * ``HttpOnly`` and ``Secure`` are both set (blocks XSS cookie theft and
      plaintext transmission);
    * ``SameSite`` is ``Lax`` or ``Strict`` -- never ``None`` with
      credentials;
    * ``Domain`` has no leading dot (no parent-domain wildcard that leaks
      the cookie to every sub-domain); a ``__Host-`` cookie must not carry
      ``Domain`` at all;
    * ``Path``, when present, is absolute; for ``__Host-`` it must be ``/``;
    * the only accepted name ``Prefix`` is ``__Host-``.
    """
    if not isinstance(flags, dict):
        return False

    if flags.get('HttpOnly') is not True:
        return False
    if flags.get('Secure') is not True:
        return False
    if flags.get('SameSite') not in ALLOWED_SAMESITE:
        return False

    domain = flags.get('Domain')
    if domain is not None:
        if not isinstance(domain, str) or domain.startswith('.'):
            return False

    path = flags.get('Path')
    if path is not None:
        if not isinstance(path, str) or not path.startswith('/'):
            return False

    prefix = flags.get('Prefix')
    if prefix is not None:
        if prefix != HOST_PREFIX:
            return False
        # RFC 6265bis __Host- constraints: no Domain attribute, Path="/".
        if domain is not None:
            return False
        if path is not None and path != '/':
            return False

    return True


def session_valid(session, now, idle_limit, absolute_limit):
    """Enforce dual timeouts: idle window and absolute lifetime.

    A session is valid only when it exists, is not revoked, and neither the
    time since its last use (``now - last``) exceeds ``idle_limit`` nor the
    time since creation (``now - created``) exceeds ``absolute_limit``.
    Missing or malformed records are treated as invalid.
    """
    if not isinstance(session, dict) or not session:
        return False
    if session.get('revoked'):
        return False

    last_used = session.get('last')
    created = session.get('created')
    # bool is a subclass of int; reject it explicitly to avoid surprises.
    if not isinstance(last_used, (int, float)) or isinstance(last_used, bool):
        return False
    if not isinstance(created, (int, float)) or isinstance(created, bool):
        return False

    if now - last_used > idle_limit:
        return False
    if now - created > absolute_limit:
        return False
    return True


def revoke_session(store, session_id):
    """Revoke a session on the server side.

    Returns ``True`` when the session existed and was removed, ``False`` for
    an unknown id. Logout must call this -- clearing the cookie on the
    client alone leaves the server-side session usable.
    """
    if session_id in store:
        del store[session_id]
        return True
    return False


def concurrent_ok(store, user, limit):
    """Return ``True`` only while ``user`` is below the concurrent-login cap.

    ``store`` maps user -> current active session count. When the cap is
    reached the caller must reject the new login (or evict the oldest
    session) so stale devices cannot stay online forever.
    """
    if limit is None or limit <= 0:
        return False
    return store.get(user, 0) < limit
