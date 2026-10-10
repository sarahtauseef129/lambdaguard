"""Trace one CVE through the security graph (use case "Trace a Vulnerability").

Built from the *findings* of priorities.json, so a CVE found in two scenarios shows each one
separately, and a package in a Layer reaches every function that uses that Layer.
"""
from backend.graph import queries as q
from backend.priority.scoring import _is_sensitive


def node_label(attrs, nid):
    t = attrs.get("type")
    if t == "vulnerability":
        return attrs["cve_id"]
    if t == "package":
        return f"{attrs['name']} {attrs['version']}"
    if t == "trigger":
        return attrs["trigger_type"] + (" (public)" if attrs.get("public") else "")
    if t == "iam_role":                       # lambdaguard-scenario-b-ScenarioBRole-AbC123 -> ScenarioBRole
        name = nid.split(":", 1)[1]
        parts = name.rsplit("-", 1)[0].split("-") if "-" in name else [name]
        return parts[-1]
    if t == "resource":
        return f"{attrs.get('resource_type', '')}: {attrs['arn'].replace('/', ':').rsplit(':', 1)[-1]}"
    return attrs.get("name", nid)


def _succ(G, nid, relation):
    return [(t, d) for _, t, _, d in G.out_edges(nid, keys=True, data=True) if d.get("relation") == relation]


def trace_cve(G, items, cve_id, sensitive_patterns):
    """Dict describing how the CVE reaches functions and resources, or None if it is not in the graph."""
    findings = [i for i in items if i["cve_id"] == cve_id]
    vid = f"vuln:{cve_id}"
    if not findings or vid not in G:
        return None

    nodes, edges, funcs, paths = {}, {}, {}, []

    def node(nid):
        nodes.setdefault(nid, {**G.nodes[nid], "id": nid, "label": node_label(G.nodes[nid], nid)})
        return nodes[nid]["label"]

    def edge(s, t):
        for d in (G.get_edge_data(s, t) or {}).values():
            edges[(s, t, d["relation"])] = {"source": s, "target": t, "relation": d["relation"],
                                            "actions": d.get("actions")}

    for f in findings:
        pkg = f"pkg:{f['package']}=={f['version']}"
        comp = ("layer:" if f["component_type"] == "layer" else "fn:") + f["component_name"]
        if pkg not in G or comp not in G:
            continue
        chain, chain_ids = [node(vid), node(pkg), node(comp)], [vid, pkg, comp]
        edge(vid, pkg)
        edge(pkg, comp)
        fn_ids = [t for t, _ in _succ(G, comp, "deployed_on")] if f["component_type"] == "layer" else [comp]
        for fn in fn_ids:
            edge(comp, fn) if fn != comp else None
            name = G.nodes[fn]["name"]
            fchain, fids = (chain + [node(fn)] if fn != comp else chain), (chain_ids + [fn] if fn != comp else chain_ids)
            entry = funcs.setdefault(name, {
                "name": name, "is_public": q.is_function_public(G, name), "iam_level": q.get_iam_privilege_level(G, name),
                "triggers": [], "resources": [], "via": []})
            entry["via"].append(f["component_name"]) if f["component_name"] not in entry["via"] else None
            for t, _ in _succ(G, fn, "triggered_by"):
                node(t); edge(fn, t)
                tr = {"type": G.nodes[t]["trigger_type"], "public": bool(G.nodes[t].get("public"))}
                entry["triggers"].append(tr) if tr not in entry["triggers"] else None
            roles = [t for t, _ in _succ(G, fn, "has_role")]
            reached = False
            for role in roles:
                node(role); edge(fn, role)
                for res, d in _succ(G, role, "can_access"):
                    node(res); edge(role, res); reached = True
                    ra, acts = G.nodes[res], d.get("actions") or []
                    r = {"label": nodes[res]["label"], "arn": ra["arn"], "type": ra.get("resource_type"),
                         "actions": acts, "sensitive": _is_sensitive(ra, acts, sensitive_patterns)}
                    entry["resources"].append(r) if r not in entry["resources"] else None
                    paths.append({"ids": fids + [role, res], "labels": [nodes[i]["label"] for i in fids + [role, res]]})
            if not reached:
                ids = fids + roles[:1]
                paths.append({"ids": ids, "labels": [nodes[i]["label"] for i in ids]})

    first = findings[0]
    return {
        "cve_id": cve_id, "summary": first["summary"], "cvss": first["cvss"], "cvss_version": first["cvss_version"],
        "epss": first["epss"], "fixed_version": first["fixed_version"],
        "findings": [{k: f[k] for k in ("package", "version", "component_type", "component_name", "scenario",
                                        "ranks", "scores")} for f in findings],
        "functions": sorted(funcs.values(), key=lambda x: x["name"]),
        "paths": paths,
        "graph": {"nodes": list(nodes.values()), "edges": list(edges.values())},
    }
