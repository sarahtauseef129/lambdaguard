"""EPSS lookup (exploit-likelihood score, 0-1) from the FIRST.org API."""
import requests

EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_epss(cve_ids, offline=False):
    """Return {cve_id: epss_float} for every CVE id we could find. Non-CVE ids are skipped."""
    ids = sorted({c for c in cve_ids if c.startswith("CVE-")})
    if offline or not ids:
        return {}
    out = {}
    for i in range(0, len(ids), 50):  # API takes a comma list; keep batches small
        batch = ids[i:i + 50]
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                out[row["cve"]] = float(row["epss"])
        except (requests.RequestException, KeyError, ValueError) as exc:
            print(f"  [warn] EPSS lookup failed for a batch: {exc}")
    return out
