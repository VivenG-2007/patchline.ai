import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import base64

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import get_settings
from app.core.security import _verify


def _generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _sign(private_pem: str) -> str:
    settings = get_settings()
    return jwt.encode(
        {"sub": "user-1", "type": "access", "iss": settings.jwt_issuer, "aud": settings.jwt_audience},
        private_pem,
        algorithm="RS256",
    )


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    # get_settings() is @lru_cache'd; clear it before/after each test so
    # monkeypatched env vars in one test can't leak into the next.
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_verify_accepts_token_signed_with_current_key(monkeypatch):
    current_priv, current_pub = _generate_keypair()
    monkeypatch.setenv("JWT_PUBLIC_KEY_BASE64", base64.b64encode(current_pub.encode()).decode())
    monkeypatch.delenv("JWT_PREVIOUS_PUBLIC_KEY_BASE64", raising=False)
    token = _sign(current_priv)
    payload = _verify(token)
    assert payload["sub"] == "user-1"


def test_verify_falls_back_to_previous_key_during_rotation_window(monkeypatch):
    previous_priv, previous_pub = _generate_keypair()
    _current_priv, current_pub = _generate_keypair()
    monkeypatch.setenv("JWT_PUBLIC_KEY_BASE64", base64.b64encode(current_pub.encode()).decode())
    monkeypatch.setenv("JWT_PREVIOUS_PUBLIC_KEY_BASE64", base64.b64encode(previous_pub.encode()).decode())
    token = _sign(previous_priv)  # signed just before the rotation
    payload = _verify(token)
    assert payload["sub"] == "user-1"


def test_verify_rejects_token_matching_neither_key(monkeypatch):
    attacker_priv, _attacker_pub = _generate_keypair()
    _current_priv, current_pub = _generate_keypair()
    _previous_priv, previous_pub = _generate_keypair()
    monkeypatch.setenv("JWT_PUBLIC_KEY_BASE64", base64.b64encode(current_pub.encode()).decode())
    monkeypatch.setenv("JWT_PREVIOUS_PUBLIC_KEY_BASE64", base64.b64encode(previous_pub.encode()).decode())
    token = _sign(attacker_priv)
    with pytest.raises(Exception):
        _verify(token)
