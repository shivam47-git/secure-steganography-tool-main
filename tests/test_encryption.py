"""Unit tests for the password-based encryption layer."""

from __future__ import annotations

import base64

import pytest

from encryption import (
    SALT_SIZE,
    InvalidPasswordError,
    decrypt_message,
    derive_key,
    encrypt_message,
    password_strength,
)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    plaintext = "top secret message"
    password = "correct horse battery staple"
    cipher = encrypt_message(plaintext, password)
    assert isinstance(cipher, str)
    assert cipher != plaintext
    assert decrypt_message(cipher, password) == plaintext


def test_encrypt_produces_different_ciphertexts_each_time():
    """Random salt should make every ciphertext unique even for the same input."""
    plaintext = "same message"
    password = "same password"
    c1 = encrypt_message(plaintext, password)
    c2 = encrypt_message(plaintext, password)
    assert c1 != c2
    # Both still decrypt to the same plaintext.
    assert decrypt_message(c1, password) == plaintext
    assert decrypt_message(c2, password) == plaintext


def test_unicode_plaintext_roundtrip():
    plaintext = "السلام عليكم — مرحبا 🛡️🔐"
    password = "Strong!Passw0rd"
    cipher = encrypt_message(plaintext, password)
    assert decrypt_message(cipher, password) == plaintext


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_wrong_password_raises():
    cipher = encrypt_message("hello", "right-password")
    with pytest.raises(InvalidPasswordError):
        decrypt_message(cipher, "wrong-password")


def test_empty_message_rejected():
    with pytest.raises(ValueError):
        encrypt_message("", "password")


def test_empty_password_rejected_on_encrypt():
    with pytest.raises(ValueError):
        encrypt_message("hi", "")


def test_empty_password_rejected_on_derive_key():
    with pytest.raises(ValueError):
        derive_key("", b"\x00" * SALT_SIZE)


def test_malformed_payload_raises_value_error():
    """A clearly invalid base64 blob must surface a ValueError, not crash."""
    with pytest.raises(ValueError):
        decrypt_message("not-valid-base64-!!!@@@###", "password")


def test_truncated_payload_raises_value_error():
    """A payload shorter than the salt must be rejected."""
    short = base64.urlsafe_b64encode(b"abc").decode("ascii")
    with pytest.raises(ValueError):
        decrypt_message(short, "password")


def test_tampered_ciphertext_raises_invalid_password():
    """Flipping a bit in the Fernet token should fail integrity check."""
    cipher = encrypt_message("hello", "password")
    raw = bytearray(base64.urlsafe_b64decode(cipher.encode("ascii")))
    # Flip a bit well past the salt to corrupt the token, not the salt.
    raw[-1] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(InvalidPasswordError):
        decrypt_message(tampered, "password")


# ---------------------------------------------------------------------------
# Key derivation determinism
# ---------------------------------------------------------------------------

def test_derive_key_deterministic():
    salt = b"\x01" * SALT_SIZE
    k1 = derive_key("p4ss", salt)
    k2 = derive_key("p4ss", salt)
    assert k1 == k2


def test_derive_key_changes_with_salt():
    k1 = derive_key("p4ss", b"\x01" * SALT_SIZE)
    k2 = derive_key("p4ss", b"\x02" * SALT_SIZE)
    assert k1 != k2


# ---------------------------------------------------------------------------
# Password strength heuristic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "password,min_score",
    [
        ("", 0),
        ("abc", 1),  # only lowercase, short -> 1
        ("abcdefgh", 2),  # length + lowercase
        ("Abcdefgh", 3),  # + uppercase
        ("Abcdefg1", 4),  # + digit
        ("Abcdefg1!", 5),  # + symbol
    ],
)
def test_password_strength_scoring(password, min_score):
    score, label = password_strength(password)
    assert score == min_score
    assert isinstance(label, str) and label
