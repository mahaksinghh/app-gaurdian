import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path

from .assistant import Advisor


@dataclass(frozen=True)
class Settings:
    database_url: str
    history_key: bytes
    enrollment_secret: str
    retention_days: int = 7
    worker_socket: str | None = None
    advisor: Advisor | None = None
    kev_path: Path | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        try:
            key = base64.b64decode(os.environ["GUARDIAN_HISTORY_KEY"], altchars=b"-_", validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("GUARDIAN_HISTORY_KEY must be a base64-encoded 32-byte key.") from exc
        ai = [os.environ.get(f"GUARDIAN_AI_{key}", "") for key in ("URL", "MODEL", "TOKEN")]
        if any(ai) and not all(ai):
            raise ValueError("Configure the assistant URL, model, and token together.")
        kev_path = os.environ.get("GUARDIAN_KEV_PATH")
        return cls(
            database_url=os.environ["GUARDIAN_DATABASE_URL"],
            history_key=key,
            enrollment_secret=os.environ["GUARDIAN_ENROLLMENT_SECRET"],
            retention_days=int(os.environ.get("GUARDIAN_RETENTION_DAYS", "7")),
            worker_socket=os.environ.get("GUARDIAN_WORKER_SOCKET"),
            advisor=Advisor(*ai) if all(ai) else None,
            kev_path=Path(kev_path) if kev_path else None,
        )

    def __post_init__(self) -> None:
        if len(self.history_key) != 32:
            raise ValueError("History encryption requires a 32-byte key.")
        if len(self.enrollment_secret) < 32:
            raise ValueError("Enrollment requires a private secret at least 32 characters long.")
        if not 1 <= self.retention_days <= 30:
            raise ValueError("History retention must be between 1 and 30 days.")
