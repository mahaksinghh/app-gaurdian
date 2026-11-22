from io import BytesIO
from zipfile import ZipFile

from fastapi.testclient import TestClient

from guardian import worker as service
from guardian.apk import ArchiveRejected
from guardian.models import ArchiveScan, ScanReport


def test_worker_streams_and_removes_temporary_upload(monkeypatch):
    captured = None

    def inspect(path):
        nonlocal captured
        captured = path
        assert path.read_bytes() == b"sample"
        return ArchiveScan(
            report=ScanReport(
                kind="apk",
                package_name="com.example.test",
                version="1",
                apk_sha256="1" * 64,
                signer_sha256=[],
                requested_permissions=[],
                granted_permissions=[],
            ),
            signature="unverified",
            debuggable=False,
        )

    monkeypatch.setattr(service, "inspect", inspect)
    with TestClient(service.worker) as client:
        result = client.post("/inspect", content=iter((b"sam", b"ple")))
    assert result.status_code == 200
    assert result.json()["signature"] == "unverified"
    assert captured is not None and not captured.exists()


def test_worker_limits_upload_and_does_not_leak_parser_errors(monkeypatch):
    def reject(_):
        raise ArchiveRejected("private parser detail")

    monkeypatch.setattr(service, "MAX_UPLOAD_BYTES", 5)
    monkeypatch.setattr(service, "inspect", reject)

    with TestClient(service.worker) as client:
        rejected = client.post("/inspect", content=b"abc")
        assert rejected.status_code == 422
        assert "private" not in rejected.text
        assert client.post("/inspect", content=iter((b"123", b"456"))).status_code == 413


def test_worker_requires_an_apk_manifest():
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", b"")
    with TestClient(service.worker) as client:
        assert client.post("/inspect", content=buffer.getvalue()).status_code == 422
