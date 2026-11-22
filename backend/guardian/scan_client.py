from collections.abc import AsyncIterator

import anyio
import httpx
from fastapi import HTTPException, Request
from pydantic import ValidationError

from .apk import MAX_UPLOAD_BYTES
from .models import ArchiveScan


class ArchiveTooLarge(ValueError):
    pass


async def inspect_upload(request: Request, socket: str | None) -> ArchiveScan:
    if socket is None:
        raise HTTPException(503, "Cloud APK inspection is disabled.")
    if request.headers.get("X-AppGuardian-Scan-Consent") != "true":
        raise HTTPException(400, "Explicit upload consent is required.")
    if request.headers.get("Content-Type") not in {
        "application/vnd.android.package-archive", "application/octet-stream"
    }:
        raise HTTPException(415, "Send an APK as the raw request body.")
    declared_length = request.headers.get("Content-Length")
    if declared_length is not None:
        if not declared_length.isascii() or not declared_length.isdigit():
            raise HTTPException(400, "Invalid upload length.")
        if len(declared_length) > 10 or int(declared_length) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "APK exceeds the upload limit.")

    async def chunks() -> AsyncIterator[bytes]:
        size = 0
        async for chunk in request.stream():
            if len(chunk) > MAX_UPLOAD_BYTES - size:
                raise ArchiveTooLarge()
            size += len(chunk)
            yield chunk

    try:
        with anyio.fail_after(75):
            transport = httpx.AsyncHTTPTransport(uds=socket)
            async with httpx.AsyncClient(transport=transport, timeout=40, trust_env=False) as client:
                async with client.stream("POST", "http://worker/inspect", content=chunks()) as response:
                    if response.status_code == 422:
                        raise HTTPException(422, "APK format is invalid or unsupported.")
                    if response.status_code == 413:
                        raise ArchiveTooLarge()
                    if response.status_code != 200:
                        raise HTTPException(503, "APK inspection was unavailable.")
                    payload = bytearray()
                    async for part in response.aiter_bytes():
                        if len(part) > 128 * 1024 - len(payload):
                            raise HTTPException(503, "APK inspection returned invalid evidence.")
                        payload.extend(part)
        return ArchiveScan.model_validate_json(bytes(payload))
    except ArchiveTooLarge as exc:
        raise HTTPException(413, "APK exceeds the upload limit.") from exc
    except (httpx.HTTPError, TimeoutError, ValidationError) as exc:
        raise HTTPException(503, "APK inspection was unavailable.") from exc
