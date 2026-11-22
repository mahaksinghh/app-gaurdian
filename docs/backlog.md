# Startup backlog

| Area | Remaining work and acceptance evidence |
| --- | --- |
| Android review | Device tests for valid, unsigned, malformed and oversized APKs, revoked document access, split APK handling, and certificate rotation. Isolate parsing and clean stale temporary files after process death. |
| Installed apps | Opt-in history with encrypted storage and retention controls. Define which changes can be observed in each Android profile, including when the app is backgrounded. |
| Recovery | Add provider-specific bilingual instructions and user-confirmed recovery milestones. Test permission revocation, uninstall confirmation, and incomplete verification on a device. |
| Network protection | Build explicit VpnService consent, visible service status, start/stop controls and policy enforcement. Verify DNS behavior, IPv6, service revocation, and compatibility with other VPNs. |
| Assistant | Translate the deterministic finding and action catalog into Hindi. Add a configurable assistant that receives only explicitly consented fields and cannot change findings or invent verdicts. |
| FastAPI and PostgreSQL | Account and device enrollment, authenticated history and deletion APIs, tenant isolation, encrypted minimal retention, migrations and integration tests. |
| Worker | Separate untrusted scan execution from the API. Limit runtime, memory and process capabilities. Verify cleanup and enforce the absence of outbound network access. |
| Threat intelligence | Review licensing and provenance before importing sources. Track source freshness and test exact-match interpretation and false-positive handling. |
| Dashboard and B2B | Build account-scoped views, tenant-scoped assessment imports and audit trails after authorization tests pass. Decide whether to deploy the optional dashboard to Vercel. |
| Releases | Device UI and security tests, signed release builds, deployment and rollback runbooks, Docker Compose, and release privacy review. |
