"""LambdaGuard API.

    python -m backend.api.main            # http://127.0.0.1:8000  (docs at /docs)
    python -m backend.api.main --port 9000
"""
import argparse
from collections import Counter
from enum import Enum
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api import data
from backend.api.data import ROOT
from backend.graph.trace import node_label, trace_cve

app = FastAPI(title="LambdaGuard API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])


class Method(str, Enum):
    cvss = "cvss"
    cvss_epss = "cvss_epss"
    arch = "arch"


def _items():
    return data.priorities()["priorities"]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/functions")
def functions():
    """Deployed functions with layers, triggers, IAM and reachable resources."""
    return data.discovery()["functions"]


@app.get("/layers")
def layers():
    return data.discovery().get("layers", [])


@app.get("/vulnerabilities")
def vulnerabilities(
    scenario: Optional[str] = None,
    component: Optional[str] = Query(None, description="function or layer name"),
    package: Optional[str] = None,
    min_cvss: Optional[float] = Query(None, ge=0, le=10),
):
    """Every finding with all three scores and ranks, in arch-rank order."""
    out = _items()
    if scenario:
        out = [i for i in out if i["scenario"] == scenario]
    if component:
        out = [i for i in out if i["component_name"] == component]
    if package:
        out = [i for i in out if i["package"] == package]
    if min_cvss is not None:
        out = [i for i in out if (i["cvss"] or 0) >= min_cvss]
    return out


@app.get("/priorities")
def priorities(method: Method = Method.arch, limit: Optional[int] = Query(None, ge=1)):
    """Findings ranked by one method. Adds `score` and `rank` for that method."""
    m = method.value
    ranked = sorted(_items(), key=lambda i: (i["ranks"][m], i["cve_id"], i["component_name"]))
    out = [{**i, "method": m, "score": i["scores"][m], "rank": i["ranks"][m]} for i in ranked]
    return out[:limit] if limit else out


@app.get("/graph")
def graph(include_vulns: bool = Query(True, description="false hides CVE nodes for a smaller picture")):
    """Nodes and edges for visualisation."""
    g = data.graph_json()
    nodes = [{**n, "label": node_label(n, n["id"])} for n in g["nodes"]]
    edges = g["edges"]
    if not include_vulns:
        keep = {n["id"] for n in nodes if n["type"] != "vulnerability"}
        nodes = [n for n in nodes if n["id"] in keep]
        edges = [e for e in edges if e["source"] in keep and e["target"] in keep]
    return {"nodes": nodes, "edges": edges}


@app.get("/trace/{cve_id}")
def trace(cve_id: str):
    """How one CVE reaches functions, IAM roles and resources: tables, paths and the sub-graph."""
    cfg = data.priorities()["meta"]["config"]
    result = trace_cve(data.graph_nx(), _items(), cve_id.strip().upper(), cfg["sensitive_resource_patterns"])
    if result is None:
        raise HTTPException(404, f"{cve_id} was not found in the security graph")
    return result


@app.get("/summary")
def summary():
    """Counts for the overview page."""
    d, items = data.discovery(), _items()
    fns = d["functions"]
    return {
        "functions": len(fns),
        "layers": len(d.get("layers", [])),
        "public_functions": sum(any(t.get("public") for t in f["triggers"]) for f in fns),
        "findings": len(items),
        "unique_cves": len({i["cve_id"] for i in items}),
        "packages": len({(i["package"], i["version"]) for i in items}),
        "by_scenario": dict(Counter(i["scenario"] for i in items)),
        "promoted": sum(i["rank_shift_arch_vs_cvss"] > 0 for i in items),
        "demoted": sum(i["rank_shift_arch_vs_cvss"] < 0 for i in items),
    }


@app.get("/vulnerabilities/{cve_id}")
def one_cve(cve_id: str):
    rows = [i for i in _items() if i["cve_id"] == cve_id]
    if not rows:
        raise HTTPException(404, f"{cve_id} not found")
    return rows


# The dashboard (frontend/) is served at "/" once it exists. Registered last so API routes win.
_frontend = ROOT / "frontend"
if (_frontend / "index.html").exists():
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")


def main():
    import uvicorn
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    print(f"API docs: http://{a.host}:{a.port}/docs")
    uvicorn.run(app, host=a.host, port=a.port)


if __name__ == "__main__":
    main()
