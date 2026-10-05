"""Read dependencies.json (from Member A) -> write vulnerabilities.json (for Member C).

Usage (from the repo root):
    python -m backend.vuln_ingest.run
    python -m backend.vuln_ingest.run --offline     # use cache only, no internet
    python -m backend.vuln_ingest.run --no-epss
"""
import argparse
import json
from pathlib import Path

from .epss import fetch_epss
from .osv_client import CACHE_FILE, _load_cache, _save_cache, query_osv, simplify

DEFAULT_IN = Path("backend/discovery/output/dependencies.json")
DEFAULT_OUT = Path("backend/vuln_ingest/output/vulnerabilities.json")


def build_vulnerabilities(dependencies, ecosystem="PyPI", offline=False, use_epss=True):
    cache = _load_cache()
    rows = []
    for dep in dependencies:
        raw = query_osv(dep["package"], dep["version"], ecosystem, cache=cache, offline=offline)
        for vuln in raw:
            info = simplify(vuln)
            rows.append({
                "scenario": dep["scenario"],
                "component_type": dep["component_type"],
                "component_name": dep["component_name"],
                "package": dep["package"],
                "version": dep["version"],
                "cve_id": info["cve_id"],
                "cvss": info["cvss"],
                "epss": None,
                "summary": info["summary"],
                "fixed_version": info["fixed_version"],
            })
    if not offline:
        _save_cache(cache)

    if use_epss:
        scores = fetch_epss([r["cve_id"] for r in rows], offline=offline)
        for r in rows:
            r["epss"] = scores.get(r["cve_id"])
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, default=DEFAULT_IN)
    ap.add_argument("--output", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--offline", action="store_true", help="use cached OSV results only")
    ap.add_argument("--no-epss", action="store_true")
    args = ap.parse_args()

    deps = json.loads(args.input.read_text(encoding="utf-8"))
    rows = build_vulnerabilities(deps, offline=args.offline, use_epss=not args.no_epss)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    pkgs = {(d["package"], d["version"]) for d in deps}
    print(f"{len(deps)} dependency entries ({len(pkgs)} unique packages) -> {len(rows)} vulnerability rows")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
