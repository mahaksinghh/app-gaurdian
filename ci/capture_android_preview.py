"""Capture the published debug APK on a dedicated Android emulator."""

import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

PACKAGE = "com.appguardian.privacy"
DEMO_FILE = "AppGuardian-demo.apk"
OUTPUT = Path("preview-output")
HIERARCHY = "/data/local/tmp/appguardian-preview.xml"


def adb(*args: str) -> bytes:
    return subprocess.check_output(["adb", *args], timeout=45)


def window() -> list[ET.Element]:
    try:
        adb("shell", "rm", "-f", HIERARCHY)
        adb("shell", "uiautomator", "dump", HIERARCHY)
        return list(ET.fromstring(adb("exec-out", "cat", HIERARCHY)).iter("node"))
    except (subprocess.SubprocessError, ET.ParseError):
        return []


def node_text(node: ET.Element) -> tuple[str, str]:
    return node.get("text", ""), node.get("content-desc", "")


def find(nodes: list[ET.Element], label: str, partial: bool = False) -> ET.Element | None:
    for node in nodes:
        if partial and any(label.casefold() in part.casefold() for part in node_text(node)):
            return node
        if not partial and label in node_text(node):
            return node
    return None


def wait_for(label: str, *, partial: bool = False, swipe: str | None = None) -> ET.Element:
    deadline = time.monotonic() + 28
    while time.monotonic() < deadline:
        nodes = window()
        launcher_dialog = find(nodes, "Pixel Launcher isn't responding")
        if launcher_dialog is not None:
            close = find(nodes, "Close app")
            if close is not None:
                tap(close)
                time.sleep(0.5)
                continue
        match = find(nodes, label, partial)
        if match is not None:
            return match
        if swipe == "up":
            adb("shell", "input", "swipe", "540", "1680", "540", "620", "320")
        elif swipe == "down":
            adb("shell", "input", "swipe", "540", "600", "540", "1680", "320")
        else:
            time.sleep(0.4)
    raise RuntimeError(f"Timed out waiting for {label!r}")


def tap(node: ET.Element) -> None:
    left, top, right, bottom = map(int, re.findall(r"\d+", node.attrib["bounds"]))
    adb("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))


def capture(name: str) -> None:
    time.sleep(0.35)
    image = adb("exec-out", "screencap", "-p")
    if not image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("Emulator returned an invalid screenshot")
    (OUTPUT / f"{name}.png").write_bytes(image)
    print(f"Captured {name}", flush=True)


def launch() -> None:
    adb("shell", "am", "force-stop", PACKAGE)
    adb("shell", "am", "start", "-W", "-n", f"{PACKAGE}/.MainActivity")
    wait_for("Choose APK")


def select_apk() -> None:
    tap(wait_for("Choose APK"))
    try:
        document = wait_for(DEMO_FILE)
    except RuntimeError:
        tap(wait_for("Show roots"))
        tap(wait_for("Downloads"))
        document = wait_for(DEMO_FILE)
    capture("02-file-picker")
    tap(document)


def run(apk: str) -> None:
    adb("shell", "settings", "put", "global", "hide_error_dialogs", "1")
    adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb("shell", "wm", "dismiss-keyguard")
    adb("install", "-r", apk)
    adb("push", apk, f"/sdcard/Download/{DEMO_FILE}")
    adb("shell", "am", "broadcast", "-a", "android.intent.action.MEDIA_SCANNER_SCAN_FILE",
        "-d", f"file:///sdcard/Download/{DEMO_FILE}")

    launch()
    capture("01-home")

    select_apk()
    wait_for("Debuggable build")
    capture("03-apk-findings")
    wait_for("Protect and verify", swipe="up")
    capture("04-apk-evidence-and-guidance")

    launch()
    tap(wait_for("Review installed apps"))
    tap(wait_for(PACKAGE, swipe="up"))
    wait_for("Open app settings", swipe="up")
    capture("05-installed-app")
    tap(wait_for("Open app settings"))
    wait_for("App info")
    capture("08-android-app-settings")
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    wait_for("No permission grant changes were visible", partial=True, swipe="down")
    capture("07-permission-recheck")

    launch()
    tap(wait_for("Account recovery"))
    wait_for("If you suspect account access", partial=True)
    capture("06-account-recovery")


OUTPUT.mkdir(exist_ok=True)
try:
    run(sys.argv[1])
except Exception:
    diagnostics = [
        {key: node.get(key, "") for key in ("text", "content-desc", "resource-id", "bounds")}
        for node in window()
    ]
    (OUTPUT / "diagnostic.txt").write_text("\n".join(map(str, diagnostics)), encoding="utf-8")
    capture("diagnostic")
    raise
