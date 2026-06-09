"""Optional Gemini report generation for APK analysis findings."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib import request


GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)


def generate_ai_summary(findings: dict[str, Any]) -> str:
    """Generate a plain-English security summary with Gemini if configured.

    If GEMINI_API_KEY is not set, this returns a deterministic local summary so
    the engine remains demoable without network access.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return _fallback_summary(findings)

    prompt = _build_prompt(findings)
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 700,
        },
    }

    req = request.Request(
        f"{GEMINI_ENDPOINT}?key={api_key}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        return (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
            or _fallback_summary(findings)
        )
    except Exception as exc:  # pragma: no cover - network/API dependent
        return f"{_fallback_summary(findings)} Gemini summary failed: {exc}"


def _build_prompt(findings: dict[str, Any]) -> str:
    compact = json.dumps(findings, indent=2, ensure_ascii=True)[:14000]
    return (
        "You are a mobile banking fraud malware analyst for a hackathon project. "
        "Explain these static APK findings in a concise report for bank security "
        "reviewers. Include: likely behavior, why it matters for financial fraud, "
        "top evidence, and recommended next steps. Do not invent evidence.\n\n"
        f"Findings JSON:\n{compact}"
    )


def _fallback_summary(findings: dict[str, Any]) -> str:
    score = findings.get("risk_score", "unknown")
    verdict = findings.get("verdict", "Unknown")
    reasons = findings.get("scoring_reasons", [])
    top_reasons = "; ".join(reasons[:3]) if reasons else "limited static indicators"
    return (
        f"Static analysis verdict: {verdict} with risk score {score}/100. "
        f"Key evidence: {top_reasons}. Review suspicious permissions, URLs, "
        "banking-related keywords, and API patterns before allowing this APK."
    )
