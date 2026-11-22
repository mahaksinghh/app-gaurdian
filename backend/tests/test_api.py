import os
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from guardian.api import create_app
from guardian.config import Settings
from guardian.migrate import migrate, purge_expired

PASSWORD = "test-password-example-0001"
ENROLLMENT = "test-enrollment-secret-" + "a" * 24


@pytest.fixture
def service():
    dsn = os.environ.get("GUARDIAN_TEST_DATABASE_URL")
    if dsn is None:
        pytest.skip("Set GUARDIAN_TEST_DATABASE_URL for PostgreSQL integration tests")
    migrate(dsn)
    with TestClient(create_app(Settings(dsn, bytes(range(32)), ENROLLMENT))) as client:
        assert client.get("/readyz").status_code == 200
        yield client, dsn


def register(client):
    email = f"{uuid4()}@example.test"
    response = client.post(
        "/v1/auth/register",
        json={"email": email, "password": PASSWORD, "enrollment_secret": ENROLLMENT},
    )
    assert response.status_code == 201, response.text
    return email, response.json()


def headers(session):
    return {"Authorization": f"Bearer {session['token']}"}


def report():
    return {
        "consent": {"store_report": True},
        "report": {
            "kind": "installed",
            "package_name": "com.example.private_app",
            "version": "1",
            "signer_sha256": [],
            "requested_permissions": ["android.permission.CAMERA"],
            "granted_permissions": ["android.permission.CAMERA"],
        },
    }


def test_device_and_account_isolation_encryption_and_revocation(service):
    client, dsn = service
    email, first = register(client)
    _, other_account = register(client)
    credentials = {"email": email, "password": PASSWORD}
    response = client.post("/v1/auth/login", json=credentials)
    assert response.status_code == 200, response.text
    second_device = response.json()

    saved = client.post("/v1/scans", headers=headers(first), json=report())
    assert saved.status_code == 201, saved.text
    record = saved.json()
    assert record["origin"] == "device-reported"
    assert client.get("/v1/scans", headers=headers(first)).json() == [record]
    for session in (second_device, other_account):
        assert client.get("/v1/scans", headers=headers(session)).json() == []
        assert client.delete(f"/v1/scans/{record['id']}", headers=headers(session)).status_code == 404

    with psycopg.connect(dsn) as db:
        encrypted = db.execute(
            "SELECT sealed_report FROM guardian_scans WHERE id = %s", (UUID(record["id"]),)
        ).fetchone()[0]
    assert b"com.example.private_app" not in encrypted
    assert b"android.permission.CAMERA" not in encrypted

    reconnect = {"device_id": first["device_id"], "device_secret": first["device_secret"]}
    response = client.post("/v1/auth/login", json=credentials | reconnect)
    assert response.status_code == 200, response.text
    assert response.json()["device_id"] == first["device_id"]
    assert "device_secret" not in response.json()
    assert client.get("/v1/scans", headers=headers(response.json())).json() == [record]

    device_path = f"/v1/devices/{first['device_id']}"
    assert client.delete(device_path, headers=headers(other_account)).status_code == 404
    assert client.delete(device_path, headers=headers(second_device)).status_code == 204
    assert client.get("/v1/scans", headers=headers(first)).status_code == 401
    assert client.post("/v1/auth/login", json=credentials | reconnect).status_code == 401
    with psycopg.connect(dsn) as db:
        assert db.execute("SELECT 1 FROM guardian_scans WHERE id = %s", (UUID(record["id"]),)).fetchone() is None


def test_history_expiry_and_deletion(service):
    client, dsn = service
    _, device = register(client)
    expired = client.post("/v1/scans", headers=headers(device), json=report())
    assert expired.status_code == 201, expired.text
    expired_id = UUID(expired.json()["id"])
    with psycopg.connect(dsn) as db:
        db.execute(
            """
            UPDATE guardian_scans SET created_at = now() - interval '2 days',
                expires_at = now() - interval '1 day'
            WHERE id = %s
            """,
            (expired_id,),
        )
    assert client.get("/v1/scans", headers=headers(device)).json() == []
    scans, _ = purge_expired(dsn)
    assert scans >= 1

    report_to_remove = client.post("/v1/scans", headers=headers(device), json=report()).json()
    assert client.delete(f"/v1/scans/{report_to_remove['id']}", headers=headers(device)).status_code == 204
    assert client.get("/v1/scans", headers=headers(device)).json() == []
    assert client.post("/v1/auth/logout", headers=headers(device)).status_code == 204
    assert client.get("/v1/scans", headers=headers(device)).status_code == 401


def test_requests_are_authenticated_bounded_and_redacted(service):
    client, _ = service
    assert client.get("/v1/scans").status_code == 401
    assert client.post("/v1/scans", content=b"a" * (129 * 1024)).status_code == 413
    sensitive = "sensitive-invalid"
    response = client.post("/v1/auth/login", json={"email": sensitive, "password": PASSWORD})
    assert response.status_code == 422
    assert sensitive not in response.text and PASSWORD not in response.text


def test_sharing_requires_second_consent_and_stays_in_account(service):
    client, _ = service
    email, android = register(client)
    _, outsider = register(client)
    browser = client.post("/v1/auth/login", json={"email": email, "password": PASSWORD}).json()

    private = client.post("/v1/scans", headers=headers(android), json=report())
    assert private.status_code == 201
    assert private.json()["shared_with_account"] is False
    assert client.get("/v1/account/scans", headers=headers(browser)).json() == []

    data = report()
    data["consent"]["allow_account_dashboard"] = True
    shared = client.post("/v1/scans", headers=headers(android), json=data)
    assert shared.status_code == 201
    assert client.get("/v1/account/scans", headers=headers(browser)).json() == [shared.json()]
    assert client.get("/v1/account/scans", headers=headers(outsider)).json() == []
    assert client.get("/v1/scans", headers=headers(browser)).json() == []
    assert client.delete(f"/v1/scans/{shared.json()['id']}", headers=headers(browser)).status_code == 404
