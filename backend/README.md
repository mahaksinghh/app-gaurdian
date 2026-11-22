# AppGuardian API

The API stores encrypted, explicitly consented scan reports, scoped to the device that submitted them. A report is marked as device-reported. This service accepts structured evidence and fingerprints. It provides no APK upload endpoint.

## Run locally

Copy `.env.example` to `.env`. Set the database password and enrollment secret to independently generated hex secrets. For example, each can be generated with `openssl rand -hex 32`. Generate the 32-byte base64 history key with `openssl rand -base64 32`. Keep `.env` private and exclude it from version control.

Run `docker compose up --build -d` and open the API documentation at `http://localhost:8000/docs`. The Compose stack runs the schema migration before the API starts and purges expired reports and sessions hourly. `GET /readyz` checks storage connectivity.

1. Call `POST /v1/auth/register` with email, password and the private enrollment secret. Save the returned device ID and secret in protected storage. The endpoint is for an operator-managed pilot.
2. Use the session token as `Authorization: Bearer <token>`. To sign in to an existing device's history, pass its ID and device secret together with account credentials to `POST /v1/auth/login`.
3. Save a report with `POST /v1/scans` and explicit `consent.store_report: true`. Use `GET /v1/scans` and `DELETE /v1/scans` to view and clear history on that device. A user can revoke another device belonging to the same account, which removes that device's tokens and reports.
4. Run `docker compose exec api python -m guardian.migrate purge` to delete expired data immediately.

## Storage and deployment

Report content uses AES-256-GCM with the account, device and record IDs bound to the ciphertext. PostgreSQL still stores IDs and retention timestamps. The service stores a keyed lookup of login identifiers, Argon2id password hashes, and SHA-256 hashes of random session and device tokens. Expired reports become inaccessible immediately and are purged by the retention job. Infrastructure backups require their own retention and deletion policy.

Keep this development stack bound to loopback. Before external deployment, place the API behind HTTPS, set request and authentication rate limits at the gateway, use a managed secrets store and TLS to a least-privilege PostgreSQL service, configure backup retention, and disable or protect API docs. Enrollment currently relies on the private operator secret. Account verification and public registration are separate work.

The master key binds both encrypted history and account lookup. Back it up separately from PostgreSQL and rotate it only through a planned migration. A direct key replacement prevents historical reports from being opened and existing logins from being located.

For local tests, install `backend/requirements-test.txt` and run `python -m pytest` from `backend`. Set `GUARDIAN_TEST_DATABASE_URL` to a dedicated test database to exercise real PostgreSQL isolation and expiry. CI supplies the test database.
