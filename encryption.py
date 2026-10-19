"""
encryption.py
=============

Password-based symmetric encryption for the Secure Image Steganography Tool.

This module wraps :pymod:`cryptography`'s Fernet (AES-128-CBC + HMAC-SHA256)
authenticated symmetric scheme with a password-based key derivation function
(PBKDF2-HMAC-SHA256). A random per-message salt is generated and prepended to
the ciphertext so that the same password produces different ciphertexts for
identical plaintexts, and so that decryption is fully self-contained.

Wire format produced by :func:`encrypt_message` (and consumed by
:func:`decrypt_message`)::

    base64( salt(16 bytes) || fernet_token )

The base64 layer keeps the payload safely embeddable inside a UTF-8 string
delimited by the steganography sentinel.

Author: <Your Name>
Course: Information Security – Final Year Project
"""

from __future__ import annotations

import base64
import os
from typing import Final

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Length, in bytes, of the random per-message salt.
SALT_SIZE: Final[int] = 16

#: PBKDF2 iteration count. 480_000 matches current OWASP guidance for
#: PBKDF2-HMAC-SHA256 (2023+). Increase as hardware evolves.
PBKDF2_ITERATIONS: Final[int] = 480_000

#: Fernet keys must be 32 raw bytes, base64-url encoded.
KEY_LENGTH: Final[int] = 32


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class InvalidPasswordError(Exception):
    """Raised when decryption fails due to a wrong password or tampered data."""


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from ``password`` and ``salt``.

    Uses PBKDF2-HMAC-SHA256 with :data:`PBKDF2_ITERATIONS` iterations.

    Parameters
    ----------
    password:
        The user-supplied passphrase. Must be a non-empty string.
    salt:
        Random salt bytes; should be :data:`SALT_SIZE` bytes long.

    Returns
    -------
    bytes
        A 44-byte url-safe base64 string suitable for :class:`Fernet`.

    Raises
    ------
    ValueError
        If ``password`` is empty.
    """
    if not password:
        raise ValueError("Password must be a non-empty string.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_message(message: str, password: str) -> str:
    """Encrypt ``message`` with a password-derived key.

    A fresh random salt is generated for every call. The returned string is a
    base64-encoded blob of ``salt || fernet_token`` that can be safely embedded
    inside a steganographic payload.

    Parameters
    ----------
    message:
        Plaintext message to encrypt. Must not be empty.
    password:
        Passphrase used to derive the encryption key.

    Returns
    -------
    str
        ASCII-safe base64 string containing the salt and the Fernet token.
    """
    if not message:
        raise ValueError("Message must be a non-empty string.")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(message.encode("utf-8"))

    payload = salt + token
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_message(payload_b64: str, password: str) -> str:
    """Decrypt a payload produced by :func:`encrypt_message`.

    Parameters
    ----------
    payload_b64:
        Base64 string of ``salt || fernet_token``.
    password:
        Passphrase to derive the decryption key.

    Returns
    -------
    str
        The recovered plaintext.

    Raises
    ------
    InvalidPasswordError
        If the password is incorrect or the payload has been tampered with.
    ValueError
        If the payload is malformed (e.g. truncated salt).
    """
    try:
        payload = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise ValueError("Encrypted payload is not valid base64.") from exc

    if len(payload) <= SALT_SIZE:
        raise ValueError("Encrypted payload is too short to contain a salt.")

    salt, token = payload[:SALT_SIZE], payload[SALT_SIZE:]
    key = derive_key(password, salt)

    try:
        plaintext = Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise InvalidPasswordError(
            "Decryption failed. The password is incorrect or the data has "
            "been corrupted/tampered with."
        ) from exc

    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def password_strength(password: str) -> tuple[int, str]:
    """Return a coarse strength score (0-4) and a human-readable label.

    The score is a simple heuristic intended for UI feedback only — it is **not**
    a substitute for proper password policy. Criteria:

    * length >= 8
    * contains lowercase letters
    * contains uppercase letters
    * contains digits
    * contains punctuation/symbols

    A point is awarded for each criterion met (length being a hard prerequisite).
    """
    if not password:
        return 0, "Empty"

    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1

    label = {
        0: "Very weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very strong",
        5: "Excellent",
    }[score]
    return score, label
