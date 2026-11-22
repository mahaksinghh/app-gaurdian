# AppGuardian

AppGuardian reviews a user-selected APK on the phone and helps the user inspect and change permissions for installed apps Android makes visible.

## Run the Android app

Open the repository in Android Studio with JDK 17, Android SDK 35 and Gradle 8.9. Run the app on Android 9 or later. From a terminal with that toolchain, run `gradle testDebugUnitTest lintDebug assembleDebug`. The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

1. Tap **Choose APK** and select a standalone APK. The app reports its SHA-256, signing certificate fingerprints when Android exposes them, manifest permissions, and selected static indicators.
2. Tap **Review installed apps** to select an Android-visible launcher app. Check requested and granted permissions.
3. Tap **Open app settings** to review permissions or uninstall through Android. Return to compare grants with the previous snapshot in this app session.
4. Use **Watch permission changes** on an installed app to opt into periodic encrypted monitoring. Open **Permission monitor** to read recent events or stop a watch. Android can delay background work.
5. Open **Account recovery** for instructions to secure an account through its provider.

[Privacy and threat model](docs/privacy.md) · [Startup backlog](docs/backlog.md)
