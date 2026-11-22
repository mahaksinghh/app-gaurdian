# Privacy and threat model

The user initiates each APK review by selecting one document. AppGuardian streams up to 100 MiB into private cache while computing SHA-256 and asks Android to parse the local copy. It does not execute the APK. A finally block attempts deletion on success and error. A process kill can leave the temporary file in cache until Android evicts it. Scan results and one-off permission rechecks are held in memory by default. A user can explicitly save individual reports in encrypted device-only history for up to seven days. The history never includes the APK itself or the input path. Users can delete reports at any time. When a user enables permission monitoring, AppGuardian encrypts the baseline and recent change events in device-only storage using Android Keystore. Stopping monitoring removes that package baseline and events. Android backup is disabled. Network access is used only when a user starts DNS protection or requests an action through a configured cloud account.

APK documents, document providers, and manifest metadata are untrusted. The byte cap limits copied data. The reviewer reads up to 1 MiB of the APK manifest to identify explicit debug, test-only, and cleartext opt-in flags, then obtains package and certificate metadata from Android. Android's parser still processes attacker-controlled bytes. The app currently performs this work on a background thread in the app process, so parser isolation and guarantees against hangs need further work.

Certificate fingerprints identify certificates Android reported for the reviewed package. A trusted external reference is required to judge publisher identity. Static indicators describe requested capabilities. They cannot verify behavior, installation provenance, a clean device, or recovery of an external account.

Android package visibility limits the list to visible launcher apps in the current profile. Verification compares observable permission grants for a selected package with its previous in-memory snapshot. An explicit watch schedules periodic checks via Android WorkManager. Doze, force-stop, and device policies can delay or prevent checks. Monitoring only sees changes between successful observations and keeps at most 14 days of events. A package that becomes invisible cannot be confirmed uninstalled.


## Optional DNS protection

The user chooses a provider and approves an Android VPN session. AppGuardian routes traffic directed to one virtual DNS address, answers blocked names locally, and submits allowed DNS requests to that provider over HTTPS. The resolver receives allowed names and the device’s source IP. AppGuardian keeps only in-memory counters and forwards no traffic before consent. The VPN can replace an existing VPN in the same profile.

The tunnel handles standard IPv4 UDP DNS queries. Direct IP connections, apps using their own DNS, Android Private DNS, IPv6 traffic outside the configured route, and TCP fallback can bypass coverage or fail to resolve. DoH outages can cause DNS failures for participating apps. The notification and app provide a stop control, and the service stops when Android revokes consent. The user can always manage the VPN through Android Settings.


## Optional cloud account

The Android client accepts a user-configured HTTPS server. Session and device credentials stay in Android Keystore-backed local storage. The password is only sent when entering a registration or sign-in request and is not stored by the app.

Sending a report and sending an APK require separate confirmation. Reports send only package evidence needed for history. APK uploads go to the temporary isolated worker. Guidance sends a language, scenario, and selected evidence categories. A model provider receives those categories only after the user opts in for that request. Local scanning, history, and recovery remain available without setting up a cloud account.
