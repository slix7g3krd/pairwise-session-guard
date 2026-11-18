import pytest

from security.session_guard import (
    new_session_id,
    rotate_on_login,
    cookie_flags,
    session_valid,
    revoke_session,
    concurrent_ok
)


def test_length():
    assert len(new_session_id()) >= 32

def test_rotate():
    assert rotate_on_login('old', 'u') != 'old'

def test_rotate_unique():
    assert rotate_on_login('old', 'u') != rotate_on_login('old', 'u')

def test_cookie_ok():
    assert cookie_flags({'HttpOnly': True, 'Secure': True, 'SameSite': 'Lax'}) is True

def test_cookie_bad():
    assert cookie_flags({'HttpOnly': False, 'Secure': True, 'SameSite': 'Lax'}) is False

def test_idle():
    assert session_valid({'last': 0, 'created': 0}, 100, 10, 100) is False

def test_absolute():
    assert session_valid({'last': 99, 'created': 0}, 200, 10, 100) is False

def test_valid():
    assert session_valid({'last': 95, 'created': 50}, 100, 10, 100) is True

def test_revoke():
    store = {'s1': True}
    assert revoke_session(store, 's1') is True

def test_concurrent():
    store = {'u': 3}
    assert concurrent_ok(store, 'u', 2) is False

def test_domain():
    assert cookie_flags({'HttpOnly': True, 'Secure': True, 'SameSite': 'Lax', 'Domain': '.example.com'}) is False

def test_path():
    assert cookie_flags({'HttpOnly': True, 'Secure': True, 'SameSite': 'Lax', 'Path': '/'}) is True

def test_host_prefix():
    assert cookie_flags({'HttpOnly': True, 'Secure': True, 'SameSite': 'Lax', 'Prefix': '__Host-'}) is True

def test_empty():
    assert session_valid({}, 100, 10, 100) is False

def test_revoke_unknown():
    assert revoke_session({}, 's1') is False
