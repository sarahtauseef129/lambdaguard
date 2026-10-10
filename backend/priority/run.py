"""Build priorities.json from B's vulnerabilities.json and graph.json.

    python -m backend.priority.run
    python -m backend.priority.run --config my_weights.json --out other.json
"""
import argparse
import json
from pathlib import Path

from backend.graph.build_graph import load_graph
from backend.priority.scoring import build_output, load_config

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VULNS = ROOT / "backend/vuln_ingest/output/vulnerabilities.json"
DEFAULT_GRAPH = ROOT / "backend/graph/output/graph.json"
DEFAULT_OUT = ROOT / "backend/priority/output/priorities.json"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vulns", default=DEFAULT_VULNS)
    ap.add_argument("--graph", default=DEFAULT_GRAPH)
    ap.add_argument("--config", default=None, help="weights JSON (default: backend/priority/config.json)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args()

    vulns = json.loads(Path(a.vulns).read_text(encoding="utf-8"))
    G = load_graph(a.graph)
    result = build_output(vulns, G, load_config(a.config))

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    items = result["priorities"]
    print(f"Wrote {len(items)} findings ({result['meta']['unique_cves']} unique CVEs) to {out}\n")
    print(f"{'arch':>4} {'cvss':>4} {'shift':>5}  {'arch score':>10}  finding")
    for i in items[:12]:
        print(f"{i['ranks']['arch']:>4} {i['ranks']['cvss']:>4} {i['rank_shift_arch_vs_cvss']:>+5}  "
              f"{i['scores']['arch']:>10}  {i['cve_id']}  {i['package']}=={i['version']} @ {i['component_name']}")


if __name__ == "__main__":
    main()
