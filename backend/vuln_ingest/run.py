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
from .nvd import fetch_nvd_scores
from .osv_client import CACHE_FILE, _load_cache, _save_cache, query_osv, simplify

DEFAULT_IN = Path("backend/discovery/output/dependencies.json")
DEFAULT_OUT = Path("backend/vuln_ingest/output/vulnerabilities.json")


_SOURCE_PRIORITY = {"nvd": 3, "osv_v3": 2, "osv_label": 1}


def _version_rank(version):
    """Prefer CVSS v3.x (comparable across CVEs) over v4.0, then v2.0 / unknown."""
    if version and version.startswith("3"):
        return 2
    if version == "4.0":
        return 1
    return 0


def _canonical_scores(rows, candidates, offline):
    """One (score, source, version) per CVE id, so the same CVE never has two scores.

    Order of preference: CVSS v3.x > v4.0 > other; then NVD > OSV vector > OSV label;
    then the higher score (conservative).
    candidates: {cve_id: [(score, source, version), ...]} collected from every OSV record.
    """
    nvd = fetch_nvd_scores(sorted({r["cve_id"] for r in rows}), offline=offline)
    canon = {}
    for cve in {r["cve_id"] for r in rows}:
        options = list(candidates.get(cve, []))
        hit = nvd.get(cve)
        if hit:
            options.append((hit["score"], "nvd", hit["version"]))
        if options:
            canon[cve] = max(options, key=lambda o: (_version_rank(o[2]),
                                                     _SOURCE_PRIORITY.get(o[1], 0), o[0]))
    return canon


def build_vulnerabilities(dependencies, ecosystem="PyPI", offline=False, use_epss=True):
    cache = _load_cache()
    merged = {}       # one row per (component, package, version, cve)
    candidates = {}   # cve_id -> [(score, source)]
    for dep in dependencies:
        raw = query_osv(dep["package"], dep["version"], ecosystem, cache=cache, offline=offline)
        for vuln in raw:
            info = simplify(vuln, installed_version=dep["version"])
            key = (dep["scenario"], dep["component_type"], dep["component_name"],
                   dep["package"], dep["version"], info["cve_id"])
            if info["cvss"] is not None:
                candidates.setdefault(info["cve_id"], []).append(
                    (info["cvss"], info["cvss_source"], info["cvss_version"]))
            if key in merged:  # same CVE reported by another OSV record (GHSA + PYSEC ...)
                row = merged[key]
                row["summary"] = row["summary"] or info["summary"]
                row["fixed_version"] = row["fixed_version"] or info["fixed_version"]
                continue
            merged[key] = {
                "scenario": dep["scenario"],
                "component_type": dep["component_type"],
                "component_name": dep["component_name"],
                "package": dep["package"],
                "version": dep["version"],
                "cve_id": info["cve_id"],
                "cvss": None,
                "cvss_source": None,
                "cvss_version": None,
                "epss": None,
                "summary": info["summary"],
                "fixed_version": info["fixed_version"],
            }
    rows = list(merged.values())
    if not offline:
        _save_cache(cache)

    canon = _canonical_scores(rows, candidates, offline)
    for r in rows:
        if r["cve_id"] in canon:
            r["cvss"], r["cvss_source"], r["cvss_version"] = canon[r["cve_id"]]

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

    still_missing = sum(r["cvss"] is None for r in rows)
    pkgs = {(d["package"], d["version"]) for d in deps}
    print(f"{len(deps)} dependency entries ({len(pkgs)} unique packages) -> {len(rows)} vulnerability rows")
    print(f"Rows still without a CVSS score: {still_missing}")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
