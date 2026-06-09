"""Create a fake APK-like ZIP and run the static engine against it."""

from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

from .static import analyze_apk


def build_demo_apk(path: Path) -> None:
    manifest = """
    <manifest package="com.fake.boi.rewards">
      <uses-permission android:name="android.permission.INTERNET" />
      <uses-permission android:name="android.permission.READ_SMS" />
      <uses-permission android:name="android.permission.SEND_SMS" />
    </manifest>
    """
    suspicious_code = """
    SmsManager.getDefault().sendTextMessage("+919999999999", null, otp, null, null);
    String endpoint = "https://fraud-example.invalid/collect";
    String note = "Bank of India KYC OTP password login";
    """

    with zipfile.ZipFile(path, "w") as apk:
        apk.writestr("AndroidManifest.xml", manifest)
        apk.writestr("classes.dex", suspicious_code)
        apk.writestr("res/raw/config.json", '{"c2":"192.168.10.15"}')


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        apk_path = Path(temp_dir) / "fake_boi_rewards.apk"
        build_demo_apk(apk_path)
        report = analyze_apk(apk_path, include_ai=False)
        print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
