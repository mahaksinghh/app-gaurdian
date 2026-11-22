import hashlib
import hmac
import secrets
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import ScanReport

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=32 * 1024, parallelism=2)
DUMMY_PASSWORD_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))


def password_matches(stored: str | None, candidate: str) -> bool:
    try:
        matches = PASSWORDS.verify(stored or DUMMY_PASSWORD_HASH, candidate)
    except (InvalidHashError, VerificationError):
        return False
    return stored is not None and matches


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def secret_hash(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


class Vault:
    def __init__(self, key: bytes) -> None:
        self.rate_key = hmac.digest(key, b"appguardian/auth-buckets/v1", "sha256")
        self.login_key = hmac.digest(key, b"appguardian/login-lookup/v1", "sha256")
        self.aead = AESGCM(hmac.digest(key, b"appguardian/history-encryption/v1", "sha256"))

    def login_hash(self, email: str) -> bytes:
        return hmac.digest(self.login_key, email.casefold().encode("utf-8"), "sha256")

    def auth_bucket(self, operation: str, client: str, subject: bytes = b"") -> bytes:
        data = b"\0".join((operation.encode(), client.encode(), subject))
        return hmac.digest(self.rate_key, data, "sha256")

    def seal(self, account: UUID, device: UUID, record: UUID, report: ScanReport) -> bytes:
        nonce = secrets.token_bytes(12)
        aad = b"appguardian/scan/v1" + account.bytes + device.bytes + record.bytes
        return nonce + self.aead.encrypt(nonce, report.model_dump_json().encode(), aad)

    def open(self, account: UUID, device: UUID, record: UUID, sealed: bytes) -> ScanReport:
        aad = b"appguardian/scan/v1" + account.bytes + device.bytes + record.bytes
        return ScanReport.model_validate_json(self.aead.decrypt(sealed[:12], sealed[12:], aad))
