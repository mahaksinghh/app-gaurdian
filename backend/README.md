# AppGuardian API

The API stores encrypted, explicitly consented scan reports, scoped to the device that submitted them. A report is marked as device-reported. History accepts structured evidence and fingerprints. The separate optional archive endpoint sends an explicitly consented upload to an isolated worker for one-time inspection.

## Run locally

Copy `.env.example` to `.env`. Set the database password and enrollment secret to independently generated hex secrets. For example, each can be generated with `openssl rand -hex 32`. Generate the 32-byte base64 history key with `openssl rand -base64 32`. Keep `.env` private and exclude it from version control.

Run `docker compose up --build -d` and open the API documentation at `http://localhost:8000/docs`. The Compose stack runs the schema migration before the API starts and purges expired reports and sessions hourly. `GET /readyz` checks storage connectivity.

1. Call `POST /v1/auth/register` with email, password and the private enrollment secret. Save the returned device ID and secret in protected storage. The endpoint is for an operator-managed pilot.
2. Use the session token as `Authorization: Bearer <token>`. To sign in to an existing device's history, pass its ID and device secret together with account credentials to `POST /v1/auth/login`.
3. Save a report with `POST /v1/scans` and explicit `consent.store_report: true`. Use `GET /v1/scans` and `DELETE /v1/scans` to view and clear history on that device. A user can revoke another device belonging to the same account, which removes that device's tokens and reports.
4. Run `docker compose exec api python -m guardian.migrate purge` to delete expired data immediately.

## One-time APK inspection

Send an authenticated `POST /v1/archives/scan` with `Content-Type: application/vnd.android.package-archive`, `X-AppGuardian-Scan-Consent: true`, and a raw standalone APK body up to 25 MiB. The worker returns an APK hash, package metadata, requested permissions, Android tooling's signing verification result, signer fingerprints when verified, and whether the tool found a debug flag. Each field describes evidence from the uploaded file. APK content and the result are held only for the request by this endpoint.

The worker runs as a separate non-root container with no external network interface, no database or AI credentials, a read-only filesystem, and bounded temporary storage. The API accesses it over a Unix socket. Android tooling runs with bounded output, CPU time, and deadlines. It parses package data without installing or running the app. The distribution's tool versions determine which APK formats are recognized. Treat an unverified signature as an inability to verify the signature. A successful signature check authenticates package bytes under that signer and requires independent trust in the signer.

## Guided response and assessed CVE lookup

Use authenticated `POST /v1/guide` with a scenario, language (`en` or `hi`), and selected evidence codes. The service constructs a fixed response plan with protective actions and a final verification step. When the user opts in with `use_ai: true` and an HTTPS chat-completions provider is configured, the provider receives only the language, scenario and selected category IDs. The provider can reorder evidence explanations. The API validates that order and uses its own bilingual action text. On timeout or invalid output, the deterministic sequence is returned.

To enable the vulnerability catalog, run `docker compose --profile intelligence run --rm --build catalog` and `docker compose restart api`. Repeat to refresh it. The catalog CLI fetches and validates the official CISA mirror and installs the release atomically. [CISA catalog and CC0 license](https://github.com/cisagov/kev-data).

Use authenticated `POST /v1/assessments/kev` with up to 50 CVE IDs from an authorized assessment. Exact matches include CISA's remediation guidance, source and release date. Package identity and an unlisted CVE cannot establish applicability or safety. Assessments are one-time responses and are kept out of scan history.

## Storage and deployment

Report content uses AES-256-GCM with the account, device and record IDs bound to the ciphertext. PostgreSQL still stores IDs and retention timestamps. The service stores a keyed lookup of login identifiers, Argon2id password hashes, and SHA-256 hashes of random session and device tokens. Expired reports become inaccessible immediately and are purged by the retention job. Infrastructure backups require their own retention and deletion policy.

Keep this development stack bound to loopback. Before external deployment, place the API behind HTTPS, set request and authentication rate limits at the gateway, use a managed secrets store and TLS to a least-privilege PostgreSQL service, configure backup retention, and disable or protect API docs. Enrollment currently relies on the private operator secret. Account verification and public registration are separate work.

The master key binds both encrypted history and account lookup. Back it up separately from PostgreSQL and rotate it only through a planned migration. A direct key replacement prevents historical reports from being opened and existing logins from being located.

For local tests, install `backend/requirements-test.txt` and run `python -m pytest` from `backend`. Set `GUARDIAN_TEST_DATABASE_URL` to a dedicated test database to exercise real PostgreSQL isolation and expiry. CI supplies the test database.
