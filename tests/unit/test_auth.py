"""
@file test_auth.py
@brief Unit tests for JWT and password hashing in app.services.
@details Tests create_access_token, decode_access_token, PasswordHasher
         without any I/O. All crypto operations use the test JWT_SECRET
         injected via conftest environment stubs.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch

from jose import jwt

from app.services import (
    JWT_ALGORITHM,
    JWT_SECRET,
    PasswordHasher,
    create_access_token,
)
from app.main import _decode_token_value

pytestmark = pytest.mark.unit


# ── create_access_token ───────────────────────────────────────────────────

class TestCreateAccessToken:
    """Verify JWT creation encodes the correct claims."""

    def test_token_contains_sub_email_role(self):
        """Token payload must include sub, email, and role claims."""
        token = create_access_token(
            user_id="u-123",
            email="test@mef.edu.tr",
            role="instructor",
        )
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        assert payload["sub"] == "u-123"
        assert payload["email"] == "test@mef.edu.tr"
        assert payload["role"] == "instructor"

    def test_token_has_expiry(self):
        """Token must contain an exp claim set in the future."""
        token = create_access_token(
            user_id="u-1",
            email="a@mef.edu.tr",
            role="student",
        )
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

        assert exp > datetime.now(tz=timezone.utc)

    def test_token_has_issued_at(self):
        """Token must contain an iat claim."""
        token = create_access_token(
            user_id="u-1",
            email="a@mef.edu.tr",
            role="student",
        )
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        assert "iat" in payload


# ── _decode_token_value ───────────────────────────────────────────────────

class TestDecodeTokenValue:
    """Verify JWT decoding and error handling."""

    def test_valid_token_decodes(self):
        """A token signed with the correct secret should decode without error."""
        token = create_access_token(
            user_id="u-42",
            email="decode@mef.edu.tr",
            role="student",
        )
        payload = _decode_token_value(token)

        assert payload["sub"] == "u-42"
        assert payload["email"] == "decode@mef.edu.tr"

    def test_invalid_token_raises_401(self):
        """A malformed token must raise HTTPException 401."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _decode_token_value("not.a.valid.jwt")

        assert exc_info.value.status_code == 401

    def test_wrong_secret_raises_401(self):
        """A token signed with a different secret must raise HTTPException 401."""
        from fastapi import HTTPException

        bad_token = jwt.encode(
            {"sub": "u-1", "email": "x@mef.edu.tr", "role": "student"},
            "wrong-secret",
            algorithm=JWT_ALGORITHM,
        )
        with pytest.raises(HTTPException) as exc_info:
            _decode_token_value(bad_token)

        assert exc_info.value.status_code == 401


# ── PasswordHasher ────────────────────────────────────────────────────────

class TestPasswordHasher:
    """Verify bcrypt hashing and verification."""

    def test_hash_produces_bcrypt_string(self):
        """Hash output should start with the bcrypt prefix."""
        hashed = PasswordHasher.hash("secure123")

        assert hashed.startswith("$2")

    def test_verify_correct_password(self):
        """Correct password must verify against its own hash."""
        hashed = PasswordHasher.hash("correct-pw")

        assert PasswordHasher.verify("correct-pw", hashed) is True

    def test_verify_wrong_password(self):
        """Wrong password must fail verification."""
        hashed = PasswordHasher.hash("correct-pw")

        assert PasswordHasher.verify("wrong-pw", hashed) is False

    def test_hash_is_not_plaintext(self):
        """Hash must not be identical to the plaintext input."""
        plaintext = "mysecret"
        hashed = PasswordHasher.hash(plaintext)

        assert hashed != plaintext
