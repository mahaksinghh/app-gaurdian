# Privacy and threat model

The user initiates each APK review by selecting one document. AppGuardian streams up to 100 MiB into private cache while computing SHA-256 and asks Android to parse the local copy. It does not execute the APK. A finally block attempts deletion on success and error. A process kill can leave the temporary file in cache until Android evicts it. Results and permission snapshots are held in memory. The app declares no Internet permission and disables Android backup.

APK documents, document providers, and manifest metadata are untrusted. The byte cap limits copied data. Android's parser still processes attacker-controlled bytes. The app currently performs this work on a background thread in the app process, so parser isolation and guarantees against hangs need further work.

Certificate fingerprints identify certificates Android reported for the reviewed package. A trusted external reference is required to judge publisher identity. Static indicators describe requested capabilities. They cannot verify behavior, installation provenance, a clean device, or recovery of an external account.

Android package visibility limits the list to visible launcher apps in the current profile. Verification compares observable permission grants for a selected package with its previous in-memory snapshot. It does not continuously observe background permission changes. A package that becomes invisible cannot be confirmed uninstalled.
