"""OSV client: ask osv.dev which known vulnerabilities affect package==version."""
import json
import time
from pathlib import Path

import requests

from .cvss import cvss3_base_score

OSV_URL = "https://api.osv.dev/v1/query"
CACHE_FILE = Path(__file__).parent / "output" / "osv_cache.json"

# Used only when OSV has no CVSS vector (e.g. GitHub advisories with a label).
_LABEL_TO_SCORE = {"LOW": 3.0, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.5, "CRITICAL": 9.5}


def _load_cache():
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return {}


def _save_cache(cache):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def query_osv(package, version, ecosystem="PyPI", cache=None, offline=False):
    """Return the raw list of OSV vulnerability records for package==version.

    cache: dict shared across calls (so the same package is only asked once).
    offline: never touch the network; only use what is already in the cache.
    """
    key = f"{ecosystem}:{package}=={version}"
    if cache is not None and key in cache:
        return cache[key]
    if offline:
        return []

    body = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    for attempt in range(3):
        try:
            resp = requests.post(OSV_URL, json=body, timeout=30)
            resp.raise_for_status()
            vulns = resp.json().get("vulns", [])
            break
        except requests.RequestException as exc:
            if attempt == 2:
                raise RuntimeError(f"OSV query failed for {key}: {exc}") from exc
            time.sleep(2)
    if cache is not None:
        cache[key] = vulns
    return vulns


def extract_cve_id(vuln):
    """OSV often uses GHSA-/PYSEC- IDs. Prefer a real CVE id from aliases."""
    candidates = [vuln.get("id", "")] + list(vuln.get("aliases", []))
    for c in candidates:
        if c.startswith("CVE-"):
            return c
    return vuln.get("id", "UNKNOWN")


def extract_cvss(vuln):
    """Best-effort CVSS base score (0-10) for one OSV record, or None."""
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score = cvss3_base_score(sev.get("score", ""))
            if score is not None:
                return score
    label = (vuln.get("database_specific") or {}).get("severity")
    if label:
        return _LABEL_TO_SCORE.get(str(label).upper())
    return None


def extract_fixed_version(vuln):
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def simplify(vuln):
    """Reduce one raw OSV record to the fields we care about."""
    return {
        "cve_id": extract_cve_id(vuln),
        "osv_id": vuln.get("id"),
        "cvss": extract_cvss(vuln),
        "summary": vuln.get("summary") or (vuln.get("details", "")[:200]),
        "fixed_version": extract_fixed_version(vuln),
    }
