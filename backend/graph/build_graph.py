"""Build the security graph from A's discovery/dependency files + B's vulnerabilities.

Node ids (prefix tells the type):
    vuln:<CVE>   pkg:<name>==<version>   layer:<name>   fn:<name>
    role:<name>  trigger:<fn>:<type>      res:<arn>

Edges (source -> target, relation):
    vuln    -affects->      pkg
    pkg     -used_in->      fn | layer
    layer   -deployed_on->  fn
    fn      -has_role->     role
    fn      -triggered_by-> trigger
    role    -can_access->   res
"""
import argparse
import json
from pathlib import Path

import networkx as nx

DEFAULT_DISCOVERY = Path("backend/discovery/output/discovery_output.json")
DEFAULT_DEPS = Path("backend/discovery/output/dependencies.json")
DEFAULT_VULNS = Path("backend/vuln_ingest/output/vulnerabilities.json")
DEFAULT_OUT = Path("backend/graph/output/graph.json")

_SERVICE_OF_RESOURCE = {"s3": "s3", "dynamodb": "dynamodb"}


def _role_name(role_arn):
    return role_arn.split("/")[-1]


def _actions_for(service, allowed_actions):
    """Actions from the role policy that apply to a resource of this service."""
    out = []
    for a in allowed_actions:
        if a in ("*", "*:*") or a.split(":")[0] == service:
            out.append(a)
    return out


def build_graph(discovery, dependencies, vulnerabilities):
    G = nx.MultiDiGraph()

    # --- functions, roles, triggers, resources -------------------------------
    for fn in discovery.get("functions", []):
        fid = f"fn:{fn['name']}"
        G.add_node(fid, type="function", name=fn["name"], runtime=fn.get("runtime"), arn=fn.get("arn"))

        role = _role_name(fn["role_arn"])
        rid = f"role:{role}"
        iam = fn.get("iam", {})
        G.add_node(rid, type="iam_role", name=role,
                   allowed_actions=iam.get("allowed_actions", []),
                   attached_policies=iam.get("attached_policies", []))
        G.add_edge(fid, rid, relation="has_role")

        for t in fn.get("triggers", []):
            tid = f"trigger:{fn['name']}:{t['type']}"
            G.add_node(tid, type="trigger", trigger_type=t["type"], public=bool(t.get("public")))
            G.add_edge(fid, tid, relation="triggered_by")

        for res in fn.get("resources", []):
            resid = f"res:{res['arn']}"
            G.add_node(resid, type="resource", resource_type=res["type"], arn=res["arn"])
            actions = _actions_for(_SERVICE_OF_RESOURCE.get(res["type"], res["type"]),
                                   iam.get("allowed_actions", []))
            G.add_edge(rid, resid, relation="can_access", actions=actions)

    # --- layers ----------------------------------------------------------------
    for layer in discovery.get("layers", []):
        G.add_node(f"layer:{layer['name']}", type="layer", name=layer["name"], arn=layer.get("arn"))
    for fn in discovery.get("functions", []):
        for layer in fn.get("layers", []):
            lid = f"layer:{layer['name']}"
            if lid not in G:
                G.add_node(lid, type="layer", name=layer["name"], arn=layer.get("arn"))
            G.add_edge(lid, f"fn:{fn['name']}", relation="deployed_on")

    # --- packages --------------------------------------------------------------
    for dep in dependencies:
        pid = f"pkg:{dep['package']}=={dep['version']}"
        G.add_node(pid, type="package", name=dep["package"], version=dep["version"])
        prefix = "layer" if dep["component_type"] == "layer" else "fn"
        cid = f"{prefix}:{dep['component_name']}"
        if cid not in G:
            # component not found in discovery output; keep it so nothing is silently lost
            G.add_node(cid, type="layer" if prefix == "layer" else "function",
                       name=dep["component_name"], missing_from_discovery=True)
        if not G.has_edge(pid, cid):
            G.add_edge(pid, cid, relation="used_in", scenario=dep.get("scenario"))

    # --- vulnerabilities -------------------------------------------------------
    for v in vulnerabilities:
        vid = f"vuln:{v['cve_id']}"
        G.add_node(vid, type="vulnerability", cve_id=v["cve_id"], cvss=v.get("cvss"),
                   epss=v.get("epss"), summary=v.get("summary"))
        pid = f"pkg:{v['package']}=={v['version']}"
        if pid not in G:
            G.add_node(pid, type="package", name=v["package"], version=v["version"])
        if not G.has_edge(vid, pid):
            G.add_edge(vid, pid, relation="affects")
    return G


def save_graph(G, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = nx.node_link_data(G, edges="edges")
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_graph(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return nx.node_link_graph(data, directed=True, multigraph=True, edges="edges")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--discovery", type=Path, default=DEFAULT_DISCOVERY)
    ap.add_argument("--dependencies", type=Path, default=DEFAULT_DEPS)
    ap.add_argument("--vulnerabilities", type=Path, default=DEFAULT_VULNS)
    ap.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    G = build_graph(
        json.loads(args.discovery.read_text(encoding="utf-8")),
        json.loads(args.dependencies.read_text(encoding="utf-8")),
        json.loads(args.vulnerabilities.read_text(encoding="utf-8")),
    )
    save_graph(G, args.output)
    types = {}
    for _, d in G.nodes(data=True):
        types[d["type"]] = types.get(d["type"], 0) + 1
    print(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges {types}")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
