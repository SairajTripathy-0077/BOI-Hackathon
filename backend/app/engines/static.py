"""Static APK analysis engine.

This module intentionally starts with a dependency-light MVP:
- validates that the input is an APK/ZIP
- extracts manifest text when available
- scans file names and printable strings for suspicious indicators
- produces JSON-ready findings for API routes or a dashboard
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from .genai import generate_ai_summary
from .scoring import BANKING_KEYWORDS, SUSPICIOUS_API_KEYWORDS, score_findings


URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+", re.IGNORECASE)
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
PERMISSION_RE = re.compile(r"android\.permission\.[A-Z0-9_]+")
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")

MAX_BYTES_PER_FILE = 750_000
MAX_STRINGS = 8000


def analyze_apk(apk_path: str | Path, include_ai: bool = True) -> dict[str, Any]:
    """Analyze an APK with static heuristics and return a JSON-ready report."""
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {path}")
    if not zipfile.is_zipfile(path):
        raise ValueError(f"File is not a valid APK/ZIP: {path}")

    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        manifest_blob = _read_member(apk, "AndroidManifest.xml")
        printable_strings = _collect_printable_strings(apk, names)

    text_corpus = "\n".join([manifest_blob, *printable_strings])
    permissions = sorted(set(PERMISSION_RE.findall(text_corpus)))
    urls = sorted(set(URL_RE.findall(text_corpus)))[:100]
    ip_addresses = sorted(set(IP_RE.findall(text_corpus)))[:100]

    keyword_hits = {
        "banking": _find_keywords(text_corpus, BANKING_KEYWORDS),
        "suspicious_api": _find_keywords(text_corpus, SUSPICIOUS_API_KEYWORDS),
    }

    findings: dict[str, Any] = {
        "apk_file": str(path),
        "apk_size_bytes": path.stat().st_size,
        "package_name": _extract_package_name(manifest_blob, text_corpus),
        "file_count": len(names),
        "interesting_files": _interesting_files(names),
        "permissions": permissions,
        "urls": urls,
        "ip_addresses": ip_addresses,
        "keyword_hits": keyword_hits,
        "sample_strings": printable_strings[:80],
    }

    scoring = score_findings(findings)
    findings.update(
        {
            "risk_score": scoring["risk_score"],
            "verdict": scoring["verdict"],
            "scoring_reasons": scoring["reasons"],
        }
    )

    if include_ai:
        findings["ai_summary"] = generate_ai_summary(findings)

    return findings


def _read_member(apk: zipfile.ZipFile, member_name: str) -> str:
    try:
        raw = apk.read(member_name)
    except KeyError:
        return ""
    return _decode_bytes(raw[:MAX_BYTES_PER_FILE])


def _collect_printable_strings(apk: zipfile.ZipFile, names: list[str]) -> list[str]:
    strings: list[str] = []
    for name in names:
        lowered = name.lower()
        if _skip_file(lowered):
            continue
        try:
            raw = apk.read(name)[:MAX_BYTES_PER_FILE]
        except (KeyError, RuntimeError, zipfile.BadZipFile):
            continue
        for match in PRINTABLE_RE.findall(raw):
            value = _decode_bytes(match).strip()
            if _looks_useful(value):
                strings.append(value)
                if len(strings) >= MAX_STRINGS:
                    return _dedupe(strings)
    return _dedupe(strings)


def _decode_bytes(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-16le", "latin-1"):
        try:
            return raw.decode(encoding, errors="ignore")
        except LookupError:
            continue
    return raw.decode("latin-1", errors="ignore")


def _skip_file(name: str) -> bool:
    return name.endswith(
        (
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".gif",
            ".mp3",
            ".mp4",
            ".wav",
            ".ttf",
            ".otf",
        )
    )


def _looks_useful(value: str) -> bool:
    if len(value) < 4:
        return False
    lowered = value.lower()
    return (
        "android.permission." in value
        or "http://" in lowered
        or "https://" in lowered
        or any(keyword in lowered for keyword in BANKING_KEYWORDS)
        or any(keyword.lower() in lowered for keyword in SUSPICIOUS_API_KEYWORDS)
        or bool(IP_RE.search(value))
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _find_keywords(text: str, keywords: set[str]) -> list[str]:
    lowered = text.lower()
    return sorted(keyword for keyword in keywords if keyword.lower() in lowered)


def _extract_package_name(manifest_text: str, text_corpus: str) -> str | None:
    candidates = [
        re.search(r'package="([^"]+)"', manifest_text),
        re.search(r"\b([a-zA-Z][\w]*(?:\.[a-zA-Z][\w]*){2,})\b", text_corpus),
    ]
    for candidate in candidates:
        if candidate:
            return candidate.group(1)
    return None


def _interesting_files(names: list[str]) -> list[str]:
    interesting_exts = (".dex", ".so", ".json", ".xml", ".properties", ".txt")
    selected = [
        name
        for name in names
        if name.lower().endswith(interesting_exts)
        or "firebase" in name.lower()
        or "google-services" in name.lower()
    ]
    return selected[:200]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run static APK analysis")
    parser.add_argument("apk_path", help="Path to APK file")
    parser.add_argument("--no-ai", action="store_true", help="Skip Gemini/fallback summary")
    args = parser.parse_args()

    report = analyze_apk(args.apk_path, include_ai=not args.no_ai)
    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
