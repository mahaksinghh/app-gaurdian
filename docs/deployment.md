# AppGuardian deployment runbook

## Test the Android app

Build with JDK 17, Android SDK 35, and Gradle 8.9. From the repository checkout run:

```sh
gradle testDebugUnitTest lintDebug assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

GitHub Actions also uploads the debug APK. A debug package uses a development signing key. Create and protect your release signing key before distributing through a store, and run the release review for your distribution policies.

### Exercise the core flows

1. In AppGuardian, choose a known APK and compare its file SHA-256 to a trusted copy. Confirm that the report shows requested permissions and a signer fingerprint when Android supplies it.
2. Review a visible installed test app. Open Android Settings and change a permission the test app declares. Return to verify whether the grant change is visible. For the watch, opt in and check the updated baseline using **Check watched apps**.
3. Open local history after manually saving a report. Delete it and verify its disappearance.
4. Use account recovery, select the provider and language, and confirm steps after checking the provider’s account.
5. Enable DNS protection with a test domain after reading the consent screen. Confirm the service status, verify a blocked DNS request from a compatible app, and stop it. Test on Wi-Fi and mobile data. Private DNS, IPv6, direct IP access and other VPNs affect coverage.

## Start the account and worker stack

Set the three required secrets in `.env` using [the backend setup](../backend/README.md). Keep the values out of shared logs and source control. Then run:

```sh
docker compose up --build --wait
curl --fail http://127.0.0.1:8000/readyz
```

The API binds to loopback. For Android cloud connection, use an HTTPS reverse proxy in front of the API with a certificate trusted by the device. Configure the proxy to stream APK uploads, bound request bodies to 25 MiB plus transport overhead, and allow up to 80 seconds for a scan response. Rate-limit sign-in, enrollment and archive endpoints. Have the proxy overwrite forwarding headers and configure the API to trust only that proxy for client addresses. Use a managed secrets store and a private PostgreSQL network; obtain a TLS DSN when using a separate database host.

For example, with a valid DNS name pointed at your proxy host, a Caddy site can forward `guardian.example.com` to `127.0.0.1:8000`. Keep the worker isolated and reach it only through its mounted Unix socket. Open the website at `https://guardian.example.com/dashboard/` or use the optional [Vercel setup](../backend/README.md#web-console).

Issue the enrollment code to your pilot users through a private channel. Connect Android to the HTTPS origin. Verify consented upload, report visibility, sign-out, and device revocation before onboarding additional people. Test the configured model with synthetic evidence and independently review the operator and provider data terms. The deterministic guidance works with provider settings empty.

## Release and operations

- Record the deployed Git commit, container image IDs, Android signing fingerprint, schema version and enabled integrations. Confirm green Android, PostgreSQL, isolation, browser, and Android-to-backend checks on that commit.
- Monitor readiness, failed sign-ins, retention runs and worker timeouts. Keep APK content, permissions, passwords and bearer values out of logs. An isolated worker outage affects cloud inspection. The on-device flow remains available.
- Verify the PostgreSQL backup in a separate environment and protect the data and history key in different stores. The key also derives the keyed account lookup. Keep the original key for recovery, and plan any key change as a coordinated migration or re-enrollment. Expire backups according to your retention policy.
- For rollback, restore your previous tagged images and compatible settings, then run the ready and isolation checks. Do not run a destructive schema downgrade on the live data. Use an isolated restore to validate any database rollback plan.
- Before a public release, test representative physical devices and Android versions, enrollment abuse controls, managed-device restrictions, data deletion, background scheduling and VPN restrictions. Complete the distribution store privacy and VPN declarations for your deployment.
