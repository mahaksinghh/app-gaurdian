import asyncio
import tempfile
from pathlib import Path

import anyio
from fastapi import FastAPI, HTTPException, Request

from .apk import MAX_UPLOAD_BYTES, ArchiveRejected, ScanUnavailable, inspect
from .models import ArchiveScan

worker = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
busy = asyncio.Lock()


@worker.get("/healthz")
def health() -> dict[str, bool]:
    return {"ok": True}


@worker.post("/inspect")
async def check(request: Request) -> ArchiveScan:
    if busy.locked():
        raise HTTPException(429, "APK worker is busy.")
    async with busy:
        with tempfile.TemporaryDirectory(prefix="guardian-") as folder:
            path = Path(folder) / "submitted.apk"
            size = 0
            try:
                with anyio.fail_after(35):
                    async with await anyio.open_file(path, "wb") as target:
                        async for chunk in request.stream():
                            if len(chunk) > MAX_UPLOAD_BYTES - size:
                                raise HTTPException(413, "APK exceeds the worker limit.")
                            size += len(chunk)
                            await target.write(chunk)
            except TimeoutError as exc:
                raise HTTPException(408, "APK upload took too long.") from exc

            try:
                return await anyio.to_thread.run_sync(inspect, path)
            except ArchiveRejected as exc:
                raise HTTPException(422, "APK format is invalid or unsupported.") from exc
            except (OSError, ScanUnavailable) as exc:
                raise HTTPException(503, "APK inspection was unavailable.") from exc
