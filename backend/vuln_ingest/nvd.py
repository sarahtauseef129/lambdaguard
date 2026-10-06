"""NVD fallback: get a CVSS base score by CVE id when OSV has no usable score.

OSV sometimes only has a CVSS v4 vector (which cvss.py can't read) or no score at all.
NVD publishes the numeric base score directly, so we ask it instead.

NVD is rate limited: ~5 requests / 30 s without an API key. We sleep between calls.
Optional: set an NVD_API_KEY environment variable to go faster.
"""
import json
import os
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_FILE = Path(__file__).parent / "output" / "nvd_cache.json"

# Prefer v3.1, then v3.0 (same family the baselines usually use), then v4.0, then v2.
_METRIC_ORDER = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]


def _load_cache():
    if NVD_CACHE_FILE.exists():
        return json.loads(NVD_CACHE_FILE.read_text(encoding="utf-8"))
    return {}


def _save_cache(cache):
    NVD_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    NVD_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def parse_nvd_score(payload):
    """Pull the best base score out of one NVD API response. Returns float or None."""
    try:
        metrics = payload["vulnerabilities"][0]["cve"].get("metrics", {})
    except (KeyError, IndexError, TypeError):
        return None
    for name in _METRIC_ORDER:
        entries = metrics.get(name) or []
        # prefer NVD's own ("Primary") entry when several sources scored it
        entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
        for e in entries:
            score = (e.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def fetch_nvd_scores(cve_ids, offline=False):
    """Return {cve_id: score_or_None} for CVE ids. Non-CVE ids are skipped."""
    ids = sorted({c for c in cve_ids if c.startswith("CVE-")})
    cache = _load_cache()
    out = {c: cache[c] for c in ids if c in cache}
    todo = [c for c in ids if c not in cache]
    if offline or not todo:
        return out

    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = 0.7 if key else 6.5
    print(f"  NVD: looking up {len(todo)} CVE(s) (about {int(len(todo) * delay)}s)...")
    for cve in todo:
        try:
            resp = requests.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=30)
            resp.raise_for_status()
            score = parse_nvd_score(resp.json())
            cache[cve] = score          # cache misses too (None) so we don't re-ask
            out[cve] = score
        except (requests.RequestException, ValueError) as exc:
            print(f"  [warn] NVD lookup failed for {cve}: {exc}")  # not cached: retry next run
        time.sleep(delay)
    _save_cache(cache)
    return out
