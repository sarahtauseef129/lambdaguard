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


def _vector_version(vector):
    """'CVSS:3.1/AV:N/...' -> '3.1'. Falls back to '3.x' if the prefix is missing."""
    head = (vector or "").split("/")[0]
    return head.split(":")[1] if head.startswith("CVSS:") and ":" in head else "3.x"


def extract_cvss(vuln):
    """Best-effort CVSS base score for one OSV record. Returns (score, source, version).

    source is "osv_v3" (computed from a real v3 vector), "osv_label" (rough value
    from a LOW/MODERATE/HIGH/CRITICAL label) or None when OSV has nothing usable.
    version is "3.1"/"3.0" for a vector, None for a label.
    """
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            vector = sev.get("score", "")
            score = cvss3_base_score(vector)
            if score is not None:
                return score, "osv_v3", _vector_version(vector)
    label = (vuln.get("database_specific") or {}).get("severity")
    if label and str(label).upper() in _LABEL_TO_SCORE:
        return _LABEL_TO_SCORE[str(label).upper()], "osv_label", None
    return None, None, None


def _version_key(v):
    """Sortable version. Uses 'packaging' if installed, else None (caller falls back)."""
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        return None


def extract_fixed_version(vuln, installed_version=None):
    """Fixed version that applies to the installed version.

    - Ignores GIT ranges (those 'fixed' values are commit hashes, not versions).
    - If several branches have a fix (e.g. 1.26.19 and 2.2.2), picks the smallest
      fixed version that is newer than the installed one.
    """
    fixed = []
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    if not fixed:
        return None
    inst = _version_key(installed_version) if installed_version else None
    if inst is not None:
        newer = [(k, f) for f in fixed if (k := _version_key(f)) is not None and k > inst]
        if newer:
            return min(newer, key=lambda t: t[0])[1]
    return fixed[0]


def simplify(vuln, installed_version=None):
    """Reduce one raw OSV record to the fields we care about."""
    cvss, source, cvss_version = extract_cvss(vuln)
    return {
        "cve_id": extract_cve_id(vuln),
        "osv_id": vuln.get("id"),
        "cvss": cvss,
        "cvss_source": source,
        "cvss_version": cvss_version,
        "summary": vuln.get("summary") or (vuln.get("details", "")[:200]),
        "fixed_version": extract_fixed_version(vuln, installed_version),
    }
