"""Helper queries on the security graph. Member C uses these for scoring."""
import networkx as nx


def _pkg_id(package, version):
    return f"pkg:{package}=={version}"


def _fn_name(node_id):
    return node_id.split(":", 1)[1]


def get_affected_functions(G, package, version):
    """Names of every function that ends up running this package.

    Direct: package -used_in-> function.
    Via a layer: package -used_in-> layer -deployed_on-> function.
    """
    pid = _pkg_id(package, version)
    if pid not in G:
        return []
    found = set()
    for _, comp, d in G.out_edges(pid, data=True):
        if d.get("relation") != "used_in":
            continue
        kind = G.nodes[comp]["type"]
        if kind == "function":
            found.add(_fn_name(comp))
        elif kind == "layer":
            for _, fn, d2 in G.out_edges(comp, data=True):
                if d2.get("relation") == "deployed_on":
                    found.add(_fn_name(fn))
    return sorted(found)


def is_package_in_shared_layer(G, package, version):
    """True if the package sits in a layer that is used by 2+ functions."""
    pid = _pkg_id(package, version)
    if pid not in G:
        return False
    for _, comp, d in G.out_edges(pid, data=True):
        if d.get("relation") == "used_in" and G.nodes[comp]["type"] == "layer":
            users = [t for _, t, d2 in G.out_edges(comp, data=True) if d2.get("relation") == "deployed_on"]
            if len(users) >= 2:
                return True
    return False


def is_package_in_layer(G, package, version):
    """True if the package sits in any layer (even one used by a single function)."""
    pid = _pkg_id(package, version)
    if pid not in G:
        return False
    return any(d.get("relation") == "used_in" and G.nodes[c]["type"] == "layer"
               for _, c, d in G.out_edges(pid, data=True))


def is_function_public(G, function_name):
    """True if the function has at least one public trigger (e.g. open API Gateway)."""
    fid = f"fn:{function_name}"
    if fid not in G:
        return False
    return any(G.nodes[t].get("public") for _, t, d in G.out_edges(fid, data=True)
               if d.get("relation") == "triggered_by")


def get_iam_privilege_level(G, function_name):
    """Simple heuristic: 0 none, 1 low (read-only), 2 medium (specific writes), 3 high (wildcards).

    'High' = a global wildcard ('*') or a whole-service wildcard ('s3:*', 'iam:*', ...).
    CloudWatch logging actions from the basic execution role are ignored.
    """
    fid = f"fn:{function_name}"
    if fid not in G:
        return 0
    role = next((t for _, t, d in G.out_edges(fid, data=True) if d.get("relation") == "has_role"), None)
    if role is None:
        return 0
    actions = [a for a in G.nodes[role].get("allowed_actions", []) if not a.startswith("logs:")]
    if not actions:
        return 0
    if any(a in ("*", "*:*") or a.endswith(":*") for a in actions):
        return 3
    read_prefixes = ("Get", "List", "Describe", "Query", "Scan", "BatchGet")
    if all(a.split(":")[-1].startswith(read_prefixes) for a in actions):
        return 1
    return 2


def get_reachable_resources(G, function_name):
    """Resources (S3, DynamoDB, ...) the function's role can reach: list of dicts."""
    fid = f"fn:{function_name}"
    out = []
    if fid not in G:
        return out
    for _, role, d in G.out_edges(fid, data=True):
        if d.get("relation") != "has_role":
            continue
        for _, res, d2 in G.out_edges(role, data=True):
            if d2.get("relation") == "can_access":
                out.append({"arn": G.nodes[res]["arn"], "type": G.nodes[res]["resource_type"],
                            "actions": d2.get("actions", [])})
    return out


def get_vulnerability_context(G, cve_id):
    """One-stop summary for a CVE: packages, affected functions, and per-function context."""
    vid = f"vuln:{cve_id}"
    if vid not in G:
        return None
    packages, functions = [], set()
    for _, pid, d in G.out_edges(vid, data=True):
        if d.get("relation") != "affects":
            continue
        p = G.nodes[pid]
        packages.append({"package": p["name"], "version": p["version"],
                         "in_shared_layer": is_package_in_shared_layer(G, p["name"], p["version"])})
        functions.update(get_affected_functions(G, p["name"], p["version"]))
    return {
        "cve_id": cve_id,
        "packages": packages,
        "affected_functions": [
            {"name": f,
             "public": is_function_public(G, f),
             "iam_level": get_iam_privilege_level(G, f),
             "resources": get_reachable_resources(G, f)}
            for f in sorted(functions)
        ],
    }


def trace_path(G, cve_id, function_name):
    """A readable propagation path CVE -> package -> (layer) -> function, or None."""
    src, dst = f"vuln:{cve_id}", f"fn:{function_name}"
    if src not in G or dst not in G:
        return None
    try:
        return nx.shortest_path(G, src, dst)
    except nx.NetworkXNoPath:
        return None
