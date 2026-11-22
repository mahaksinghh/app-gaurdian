import hmac
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg import Error
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout
from starlette.datastructures import MutableHeaders

from .assistant import guide
from .catalog import Assessment, load as load_catalog
from .config import Settings
from .models import (
    ArchiveScan, AssessmentRequest, Device, Guidance, GuidanceRequest, Login, Registration,
    ScanRecord, Session, StoreReport,
)
from .scan_client import inspect_upload
from .security import PASSWORDS, Vault, new_secret, password_matches, secret_hash


class JsonBodyLimit:
    """Limit buffered JSON requests, including uploads without Content-Length."""

    def __init__(self, app, maximum_bytes: int = 128 * 1024):
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def no_store(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        if scope["method"] not in {"POST", "PUT", "PATCH"} or scope["path"] == "/v1/archives/scan":
            return await self.app(scope, receive, no_store)

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(chunk) > self.maximum_bytes - len(body):
                response = JSONResponse({"detail": "Request content is too large."}, status_code=413)
                return await response(scope, receive, no_store)
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, no_store)


@dataclass(frozen=True)
class Principal:
    account_id: UUID
    device_id: UUID
    token_hash: bytes


bearer = HTTPBearer(auto_error=False)


def unauthenticated() -> HTTPException:
    return HTTPException(401, "Invalid or expired credentials.", {"WWW-Authenticate": "Bearer"})


def principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    if credentials is None or len(credentials.credentials) != 43:
        raise unauthenticated()
    token_hash = secret_hash(credentials.credentials)
    with request.app.state.pool.connection() as db:
        row = db.execute(
            """
            SELECT session.account_id, session.device_id
            FROM guardian_sessions AS session
            JOIN guardian_devices AS device ON (session.device_id, session.account_id)
                = (device.id, device.account_id)
            WHERE session.token_hash = %s AND session.expires_at > now() AND device.revoked_at IS NULL
            """,
            (token_hash,),
        ).fetchone()
    if row is None:
        raise unauthenticated()
    return Principal(row["account_id"], row["device_id"], token_hash)


Authenticated = Annotated[Principal, Depends(principal)]


def start_session(db, account_id: UUID, device_id: UUID | None, device_secret: str | None) -> Session:
    if device_id is None:
        device_id = uuid4()
        device_secret = new_secret()
        db.execute(
            "INSERT INTO guardian_devices (id, account_id, secret_hash) VALUES (%s, %s, %s)",
            (device_id, account_id, secret_hash(device_secret)),
        )
        issued_secret = device_secret
    else:
        device = db.execute(
            """
            SELECT id FROM guardian_devices
            WHERE id = %s AND account_id = %s AND secret_hash = %s AND revoked_at IS NULL
            FOR SHARE
            """,
            (device_id, account_id, secret_hash(device_secret)),
        ).fetchone()
        if device is None:
            raise unauthenticated()
        issued_secret = None

    token = new_secret()
    row = db.execute(
        """
        INSERT INTO guardian_sessions (token_hash, device_id, account_id, expires_at)
        VALUES (%s, %s, %s, now() + interval '12 hours')
        RETURNING expires_at
        """,
        (secret_hash(token), device_id, account_id),
    ).fetchone()
    return Session(token=token, device_id=device_id, device_secret=issued_secret, expires_at=row["expires_at"])


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        selected = settings or Settings.from_env()
        app.state.settings = selected
        app.state.vault = Vault(selected.history_key)
        app.state.catalog = (
            load_catalog(selected.kev_path) if selected.kev_path and selected.kev_path.is_file() else None
        )
        with ConnectionPool(
            selected.database_url,
            min_size=1,
            max_size=8,
            timeout=5,
            kwargs={"row_factory": dict_row, "connect_timeout": 5},
        ) as pool:
            pool.wait(timeout=10)
            app.state.pool = pool
            yield

    app = FastAPI(title="AppGuardian", version="0.1.0", lifespan=lifespan)
    app.add_middleware(JsonBodyLimit)

    @app.exception_handler(RequestValidationError)
    async def reject_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Validation errors can include unredacted inputs such as passwords and reports.
        return JSONResponse({"detail": "Invalid request."}, status_code=422)

    @app.exception_handler(PoolTimeout)
    @app.exception_handler(Error)
    async def database_unavailable(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": "Storage is temporarily unavailable."}, status_code=503)

    @app.get("/healthz")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/readyz")
    def ready(request: Request) -> dict[str, bool]:
        with request.app.state.pool.connection() as db:
            db.execute("SELECT 1 FROM guardian_accounts LIMIT 1")
        return {"ok": True}

    @app.post("/v1/auth/register", status_code=201, response_model_exclude_none=True)
    def register(body: Registration, request: Request) -> Session:
        supplied = body.enrollment_secret.get_secret_value().encode()
        if not hmac.compare_digest(supplied, request.app.state.settings.enrollment_secret.encode()):
            raise HTTPException(403, "Enrollment is unavailable.")
        login_hash = request.app.state.vault.login_hash(body.email)
        password_hash = PASSWORDS.hash(body.password.get_secret_value())
        account_id = uuid4()
        with request.app.state.pool.connection() as db:
            row = db.execute(
                """
                INSERT INTO guardian_accounts (id, login_hash, password_hash) VALUES (%s, %s, %s)
                ON CONFLICT (login_hash) DO NOTHING RETURNING id
                """,
                (account_id, login_hash, password_hash),
            ).fetchone()
            if row is None:
                raise HTTPException(409, "An account already exists.")
            return start_session(db, account_id, None, None)

    @app.post("/v1/auth/login", response_model_exclude_none=True)
    def login(body: Login, request: Request) -> Session:
        login_hash = request.app.state.vault.login_hash(body.email)
        with request.app.state.pool.connection() as db:
            account = db.execute(
                "SELECT id, password_hash FROM guardian_accounts WHERE login_hash = %s", (login_hash,)
            ).fetchone()
        if not password_matches(account["password_hash"] if account else None, body.password.get_secret_value()):
            raise unauthenticated()
        device_secret = body.device_secret.get_secret_value() if body.device_secret is not None else None
        with request.app.state.pool.connection() as db:
            return start_session(db, account["id"], body.device_id, device_secret)

    @app.post("/v1/auth/logout", status_code=204, response_class=Response)
    def logout(request: Request, user: Authenticated) -> None:
        with request.app.state.pool.connection() as db:
            db.execute("DELETE FROM guardian_sessions WHERE token_hash = %s", (user.token_hash,))

    @app.get("/v1/devices")
    def devices(request: Request, user: Authenticated) -> list[Device]:
        with request.app.state.pool.connection() as db:
            rows = db.execute(
                """
                SELECT id, created_at, revoked_at FROM guardian_devices
                WHERE account_id = %s ORDER BY created_at DESC LIMIT 100
                """,
                (user.account_id,),
            ).fetchall()
        return [Device(**row, current=row["id"] == user.device_id) for row in rows]

    @app.delete("/v1/devices/{device_id}", status_code=204, response_class=Response)
    def revoke_device(device_id: UUID, request: Request, user: Authenticated) -> None:
        with request.app.state.pool.connection() as db:
            row = db.execute(
                """
                UPDATE guardian_devices SET revoked_at = COALESCE(revoked_at, now())
                WHERE account_id = %s AND id = %s RETURNING id
                """,
                (user.account_id, device_id),
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Device not found.")
            db.execute(
                "DELETE FROM guardian_sessions WHERE account_id = %s AND device_id = %s",
                (user.account_id, device_id),
            )
            db.execute(
                "DELETE FROM guardian_scans WHERE account_id = %s AND device_id = %s",
                (user.account_id, device_id),
            )

    @app.post("/v1/guide")
    async def guidance(body: GuidanceRequest, request: Request, user: Authenticated) -> Guidance:
        return await guide(body, request.app.state.settings.advisor)

    @app.post("/v1/assessments/kev")
    def assess_cves(body: AssessmentRequest, request: Request, user: Authenticated) -> Assessment:
        catalog = request.app.state.catalog
        if catalog is None:
            raise HTTPException(503, "The vulnerability catalog is unavailable.")
        return catalog.assessment(body.cve_ids)

    @app.post("/v1/archives/scan")
    async def scan_archive(request: Request, user: Authenticated) -> ArchiveScan:
        return await inspect_upload(request, request.app.state.settings.worker_socket)

    @app.post("/v1/scans", status_code=201)
    def store_scan(body: StoreReport, request: Request, user: Authenticated) -> ScanRecord:
        scan_id = uuid4()
        encrypted = request.app.state.vault.seal(user.account_id, user.device_id, scan_id, body.report)
        with request.app.state.pool.connection() as db:
            device = db.execute(
                """
                SELECT id FROM guardian_devices
                WHERE account_id = %s AND id = %s AND revoked_at IS NULL FOR SHARE
                """,
                (user.account_id, user.device_id),
            ).fetchone()
            if device is None:
                raise unauthenticated()
            row = db.execute(
                """
                INSERT INTO guardian_scans (id, account_id, device_id, expires_at, sealed_report)
                VALUES (%s, %s, %s, now() + make_interval(days => %s), %s)
                RETURNING created_at, expires_at
                """,
                (scan_id, user.account_id, user.device_id, request.app.state.settings.retention_days, encrypted),
            ).fetchone()
        return ScanRecord(id=scan_id, report=body.report, **row)

    @app.get("/v1/scans")
    def list_scans(
        request: Request, user: Authenticated, limit: Annotated[int, Query(ge=1, le=100)] = 25
    ) -> list[ScanRecord]:
        with request.app.state.pool.connection() as db:
            rows = db.execute(
                """
                SELECT id, created_at, expires_at, sealed_report FROM guardian_scans
                WHERE account_id = %s AND device_id = %s AND expires_at > now()
                ORDER BY created_at DESC, id DESC LIMIT %s
                """,
                (user.account_id, user.device_id, limit),
            ).fetchall()
        vault = request.app.state.vault
        return [
            ScanRecord(
                id=row["id"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                report=vault.open(user.account_id, user.device_id, row["id"], row["sealed_report"]),
            )
            for row in rows
        ]

    @app.delete("/v1/scans/{scan_id}", status_code=204, response_class=Response)
    def delete_scan(scan_id: UUID, request: Request, user: Authenticated) -> None:
        with request.app.state.pool.connection() as db:
            result = db.execute(
                "DELETE FROM guardian_scans WHERE account_id = %s AND device_id = %s AND id = %s",
                (user.account_id, user.device_id, scan_id),
            )
            if result.rowcount != 1:
                raise HTTPException(404, "Scan not found.")

    @app.delete("/v1/scans", status_code=204, response_class=Response)
    def clear_history(request: Request, user: Authenticated) -> None:
        with request.app.state.pool.connection() as db:
            db.execute(
                "DELETE FROM guardian_scans WHERE account_id = %s AND device_id = %s",
                (user.account_id, user.device_id),
            )

    return app


app = create_app()
