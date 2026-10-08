"""Password hashing with scrypt (memory-hard KDF from the standard library).

Stored format:  scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>
The parameters travel with the hash so they can be raised later without
invalidating existing accounts (see needs_rehash).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
_MAXMEM = 128 * 1024 * 1024

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128


def _derive(password: str, salt: bytes, n: int, r: int, p: int, length: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=length, maxmem=_MAXMEM
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    key = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_BYTES)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification. Returns False for any malformed hash."""
    try:
        scheme, n, r, p, salt_b64, key_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(key_b64, validate=True)
        n_i, r_i, p_i = int(n), int(r), int(p)
        # Refuse absurd parameters so a corrupted record cannot exhaust memory.
        if not (2**10 <= n_i <= 2**20 and 1 <= r_i <= 16 and 1 <= p_i <= 4):
            return False
        actual = _derive(password, salt, n_i, r_i, p_i, len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    parts = stored.split("$")
    return parts[:4] != ["scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P)]


def password_problems(password: str) -> list[str]:
    """Return the reasons a password is unacceptable (empty list if it is fine)."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"must be at most {MAX_PASSWORD_LENGTH} characters")
    if not any(c.isalpha() for c in password):
        problems.append("must contain a letter")
    if not any(c.isdigit() for c in password):
        problems.append("must contain a digit")
    return problems


# A real hash of a random value, used to spend the same time on unknown
# accounts as on known ones so login timing does not reveal who is registered.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
