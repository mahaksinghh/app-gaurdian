# AppGuardian release coverage

| Area | Pilot implementation | Release validation and limitations |
| --- | --- | --- |
| Android APK review | Local document consent, APK SHA-256, signer fingerprints, permissions and bounded manifest checks. | Validate split/rotated packages and malformed/resource-heavy fixtures across supported device versions. The local platform fingerprint is evidence for comparison. The worker has a separate signing verification step. |
| Installed app review | Android-visible launcher apps, permission grants, guided Settings actions, recheck and encrypted opt-in periodic watch. | Validate grant revocation and reinstallation on physical devices. Android visibility and scheduling define what the app can observe. |
| Local history and recovery | Encrypted opt-in report history, per-report deletion, and English/Hindi provider checklists with user-confirmed steps. | Verify provider navigation and accessibility on supported device sizes. Recovery confirmation comes from the user. |
| Network protection | User-configured DNS blocking, explicit Android VPN consent, encrypted forwarding and a visible stop control. | Verify DNS results on physical devices and networks. The tunnel handles a bounded UDP DNS route, with bypasses and failure modes documented. |
| Cloud API and history | Private pilot enrollment, token and device isolation, encrypted consented reports, deletion, revocation and scheduled TTL. | Public registration and production infrastructure require an operator-managed release. |
| APK worker | Consent gate, bounded upload and Android tooling in a non-root service with no external network interface. | Expand package-tool compatibility coverage and assess the container boundary before public uploads. |
| Assistant | Deterministic English/Hindi guidance with optional model prioritization of whitelisted evidence. | Configure and independently validate the chosen provider. User-visible actions come from the catalog. |
| Threat intelligence and assessment | Exact CVE matches from CISA’s CC0 catalog with release provenance. Account console covers shared history, device revocation and CVE assessments. | Analysts validate affected products and versions. The catalog does not classify APK hashes. |
| Delivery | Android debug builds, Docker Compose, GitHub Actions and local deployment instructions. | Production HTTPS, release signing, physical-device QA and operator review require a release environment. |
