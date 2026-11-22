from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints, model_validator

Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
PackageName = Annotated[str, StringConstraints(min_length=1, max_length=255, pattern=r"^[a-zA-Z0-9_.]+$")]
PermissionName = Annotated[str, StringConstraints(min_length=1, max_length=255, pattern=r"^[a-zA-Z0-9_.-]+$")]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AccountCredentials(Input):
    email: Annotated[str, StringConstraints(max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")]
    password: Annotated[SecretStr, Field(min_length=12, max_length=256)]


class Registration(AccountCredentials):
    enrollment_secret: Annotated[SecretStr, Field(min_length=32, max_length=256)]


class Login(AccountCredentials):
    device_id: UUID | None = None
    device_secret: Annotated[SecretStr, Field(min_length=43, max_length=43)] | None = None

    @model_validator(mode="after")
    def require_device_pair(self) -> "Login":
        if (self.device_id is None) != (self.device_secret is None):
            raise ValueError("Provide both device credentials or neither.")
        return self


class Session(BaseModel):
    token: str
    device_id: UUID
    device_secret: str | None = None
    expires_at: datetime


class Device(BaseModel):
    id: UUID
    created_at: datetime
    revoked_at: datetime | None
    current: bool


class Consent(Input):
    store_report: Literal[True]


class ScanReport(Input):
    kind: Literal["apk", "installed"]
    package_name: PackageName
    version: Annotated[str, StringConstraints(max_length=128)]
    apk_sha256: Sha256 | None = None
    signer_sha256: Annotated[list[Sha256], Field(max_length=16)]
    requested_permissions: Annotated[list[PermissionName], Field(max_length=256)]
    granted_permissions: Annotated[list[PermissionName], Field(max_length=256)]

    @model_validator(mode="after")
    def verify_kind(self) -> "ScanReport":
        if self.kind == "apk" and (self.apk_sha256 is None or self.granted_permissions):
            raise ValueError("APK reports require a file hash and have no granted permissions.")
        if self.kind == "installed" and self.apk_sha256 is not None:
            raise ValueError("Installed app reports do not contain an archive hash.")
        if not set(self.granted_permissions) <= set(self.requested_permissions):
            raise ValueError("Granted permissions must be among the requested permissions.")
        return self


class StoreReport(Input):
    consent: Consent
    report: ScanReport


class ScanRecord(BaseModel):
    id: UUID
    created_at: datetime
    expires_at: datetime
    origin: Literal["device-reported"] = "device-reported"
    report: ScanReport


class ArchiveScan(BaseModel):
    origin: Literal["worker-inspected"] = "worker-inspected"
    report: ScanReport
    signature: Literal["verified", "unverified"]
    debuggable: bool
