
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
 
    if not message:
        raise ValueError("Message must be a non-empty string.")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(message.encode("utf-8"))

    payload = salt + token
    return base64.urlsafe_b64encode(payload).decode("ascii")


def decrypt_message(payload_b64: str, password: str) -> str:

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
