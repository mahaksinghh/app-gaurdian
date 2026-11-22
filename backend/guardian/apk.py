import hashlib
import os
import re
import signal
import subprocess
import tempfile
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from .models import ArchiveScan, ScanReport

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_TOOL_OUTPUT = 512 * 1024
MAX_DECLARED_EXPANDED = 256 * 1024 * 1024
PERMISSION = re.compile(r"^uses-permission(?:-sdk-\d+)?: name='([A-Za-z0-9_.-]{1,255})'")
PACKAGE = re.compile(r"^package: name='([A-Za-z0-9_.]{1,255})' versionCode='[^']*' versionName='([^']{0,128})'")
CERTIFICATE = re.compile(r"^Signer #\d+ certificate SHA-256 digest: ([0-9A-Fa-f]{64})\s*$", re.MULTILINE)


class ArchiveRejected(ValueError):
    pass


class ScanUnavailable(RuntimeError):
    pass


def check_container(path: Path) -> None:
    try:
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > 20_000:
                raise ArchiveRejected("Unsupported APK entry count.")
            seen: set[str] = set()
            expanded = 0
            for item in entries:
                name = item.filename
                if name in seen or name.startswith("/") or ".." in name.split("/") or item.flag_bits & 1:
                    raise ArchiveRejected("Unsupported APK entry.")
                seen.add(name)
                expanded += item.file_size
                if expanded > MAX_DECLARED_EXPANDED:
                    raise ArchiveRejected("APK declares too much expanded data.")
            manifest = archive.getinfo("AndroidManifest.xml")
            if manifest.is_dir() or not 0 < manifest.file_size <= 1024 * 1024:
                raise ArchiveRejected("Unsupported APK manifest size.")
    except (BadZipFile, KeyError, NotImplementedError) as exc:
        raise ArchiveRejected("File is not a supported standalone APK.") from exc


def run_tool(arguments: list[str]) -> tuple[int, str]:
    # prlimit applies to each tool and any descendants without preexec hooks.
    limits = ["/usr/bin/prlimit", "--fsize=524288:524288", "--nofile=128:128", "--cpu=12:14", "--"]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "JAVA_TOOL_OPTIONS": "-Xmx192m -XX:ActiveProcessorCount=2"}
    try:
        with tempfile.TemporaryFile() as output:
            with subprocess.Popen(
                limits + arguments,
                stdout=output,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                env=env,
                start_new_session=True,
            ) as process:
                try:
                    status = process.wait(timeout=16)
                except subprocess.TimeoutExpired as exc:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise ScanUnavailable("APK tooling timed out.") from exc
            output.seek(0)
            raw = output.read(MAX_TOOL_OUTPUT + 1)
    except OSError as exc:
        raise ScanUnavailable("APK tooling is unavailable.") from exc
    if len(raw) >= MAX_TOOL_OUTPUT or status < 0:
        raise ScanUnavailable("APK tooling reached a resource limit.")
    return status, raw.decode("utf-8", errors="replace")


def inspect(path: Path) -> ArchiveScan:
    check_container(path)
    status, badging = run_tool(["/usr/bin/aapt", "dump", "badging", str(path)])
    if status != 0:
        raise ArchiveRejected("Android tooling could not read the APK metadata.")
    package = PACKAGE.match(badging)
    if package is None:
        raise ArchiveRejected("APK did not provide supported package metadata.")

    permissions = sorted({match[1] for line in badging.splitlines() if (match := PERMISSION.match(line))})
    if len(permissions) > 256:
        raise ArchiveRejected("APK requests more permissions than can be reported.")
    signing_status, signing = run_tool(["/usr/bin/apksigner", "verify", "--print-certs", str(path)])
    certificates = sorted({digest.lower() for digest in CERTIFICATE.findall(signing)}) if signing_status == 0 else []
    if len(certificates) > 16:
        raise ArchiveRejected("APK has more signing certificates than can be reported.")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return ArchiveScan(
        report=ScanReport(
            kind="apk",
            package_name=package[1],
            version=package[2],
            apk_sha256=digest,
            signer_sha256=certificates,
            requested_permissions=permissions,
            granted_permissions=[],
        ),
        signature="verified" if signing_status == 0 and certificates else "unverified",
        debuggable="application-debuggable" in badging.splitlines(),
    )
