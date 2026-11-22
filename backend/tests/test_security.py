from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError

from guardian.models import StoreReport
from guardian.security import Vault


def test_ciphertext_is_bound_to_record_and_device():
    user, device, scan = uuid4(), uuid4(), uuid4()
    report = StoreReport.model_validate(
        {
            "consent": {"store_report": True},
            "report": {
                "kind": "apk",
                "package_name": "com.example.secret_package",
                "version": "1",
                "apk_sha256": "a" * 64,
                "signer_sha256": [],
                "requested_permissions": [],
                "granted_permissions": [],
            },
        }
    ).report
    vault = Vault(bytes(range(32)))
    sealed = vault.seal(user, device, scan, report)
    assert report.package_name.encode() not in sealed
    assert vault.open(user, device, scan, sealed) == report
    assert vault.seal(user, device, scan, report) != sealed
    for scoped_ids in ((uuid4(), device, scan), (user, uuid4(), scan), (user, device, uuid4())):
        with pytest.raises(InvalidTag):
            vault.open(*scoped_ids, sealed)


def test_storage_requires_explicit_consent():
    with pytest.raises(ValidationError):
        StoreReport.model_validate(
            {
                "consent": {"store_report": False},
                "report": {
                    "kind": "installed",
                    "package_name": "com.example.app",
                    "version": "1",
                    "signer_sha256": [],
                    "requested_permissions": [],
                    "granted_permissions": [],
                },
            }
        )
