"""Risk scoring helpers for static APK findings."""

from __future__ import annotations

from typing import Any


HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}

MEDIUM_RISK_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
}

BANKING_KEYWORDS = {
    "bank",
    "boi",
    "bank of india",
    "upi",
    "otp",
    "pin",
    "password",
    "netbanking",
    "login",
    "aadhaar",
    "pan",
    "kyc",
    "card",
    "cvv",
    "wallet",
}

SUSPICIOUS_API_KEYWORDS = {
    "SmsManager",
    "sendTextMessage",
    "TelephonyManager",
    "getDeviceId",
    "getSubscriberId",
    "DexClassLoader",
    "Runtime.getRuntime",
    "exec(",
    "KeyStore",
    "Cipher",
    "Base64",
    "SharedPreferences",
}


def score_findings(findings: dict[str, Any]) -> dict[str, Any]:
    """Return a risk score, verdict, and scoring reasons from static findings."""
    score = 0
    reasons: list[str] = []

    permissions = set(findings.get("permissions", []))
    high_permissions = sorted(permissions & HIGH_RISK_PERMISSIONS)
    medium_permissions = sorted(permissions & MEDIUM_RISK_PERMISSIONS)

    if high_permissions:
        points = min(45, len(high_permissions) * 9)
        score += points
        reasons.append(f"High-risk permissions found: {', '.join(high_permissions)}")

    if medium_permissions:
        points = min(15, len(medium_permissions) * 4)
        score += points
        reasons.append(f"Network/storage/location permissions found: {', '.join(medium_permissions)}")

    urls = findings.get("urls", [])
    ips = findings.get("ip_addresses", [])
    if urls:
        points = min(20, len(urls) * 5)
        score += points
        reasons.append(f"Embedded URLs found: {len(urls)}")
    if ips:
        points = min(15, len(ips) * 5)
        score += points
        reasons.append(f"Embedded IP addresses found: {len(ips)}")

    keyword_hits = findings.get("keyword_hits", {})
    banking_hits = keyword_hits.get("banking", [])
    api_hits = keyword_hits.get("suspicious_api", [])

    if banking_hits:
        points = min(20, len(banking_hits) * 4)
        score += points
        reasons.append(f"Banking/fraud-sensitive keywords found: {', '.join(banking_hits)}")

    if api_hits:
        points = min(25, len(api_hits) * 5)
        score += points
        reasons.append(f"Suspicious Android/API patterns found: {', '.join(api_hits)}")

    if "android.permission.INTERNET" in permissions and (
        high_permissions or banking_hits or urls or ips
    ):
        score += 10
        reasons.append("Internet access combines with fraud-relevant indicators")

    score = max(0, min(100, score))
    verdict = _verdict(score)

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons or ["No major static indicators found in the extracted data"],
    }


def _verdict(score: int) -> str:
    if score >= 75:
        return "High Risk"
    if score >= 45:
        return "Medium Risk"
    if score >= 20:
        return "Low Risk"
    return "Minimal Risk"
