"""Scoring logic: CVSS-only, CVSS+EPSS and architecture-aware priorities.

One *finding* = one CVE in one component (a function or a layer), exactly one row of
vulnerabilities.json. The same CVE in two components is two findings, because their
architectural context can differ. All scores are on a 0-100 scale; rank 1 = most urgent.
"""
import json
from pathlib import Path

from backend.graph import queries as q

CONFIG_PATH = Path(__file__).with_name("config.json")
METHODS = ("cvss", "cvss_epss", "arch")


# --------------------------------------------------------------------------- config
def load_config(path=None):
    cfg = json.loads(Path(path or CONFIG_PATH).read_text(encoding="utf-8"))
    cfg["arch_weights"] = _normalise(cfg["arch_weights"])
    cfg["cvss_epss_weights"] = _normalise(cfg["cvss_epss_weights"])
    return cfg


def _normalise(weights):
    if any(w < 0 for w in weights.values()):
        raise ValueError("weights must be >= 0")
    total = sum(weights.values())
    if total <= 0:
        raise ValueError("weights must not all be zero")
    return {k: w / total for k, w in weights.items()}


# ------------------------------------------------------------------- graph features
def functions_for_component(G, component_type, component_name):
    """Functions that run this component.

    Resolved from the *component* in the finding, not from the package node, because
    package nodes are shared (idna==2.7 is used by two scenarios) and would mix findings.
    """
    if component_type == "layer":
        lid = f"layer:{component_name}"
        if lid not in G:
            return []
        return sorted(t.split(":", 1)[1] for _, t, d in G.out_edges(lid, data=True)
                      if d.get("relation") == "deployed_on")
    return [component_name] if f"fn:{component_name}" in G else []


def _is_sensitive(resource, actions, patterns):
    """Sensitive if its name matches a configured tag, or a wildcard action reaches it."""
    name = resource["arn"].lower()
    return any(p in name for p in patterns) or any(a == "*" or a.endswith(":*") for a in actions)


def graph_features(G, finding, cfg):
    """Architecture features of one finding, read from B's graph."""
    fns = functions_for_component(G, finding["component_type"], finding["component_name"])
    total_fns = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "function") or 1

    resources, seen = [], set()
    for f in fns:
        for r in q.get_reachable_resources(G, f):
            if r["arn"] not in seen:
                seen.add(r["arn"])
                resources.append(r)
    sensitive = [r for r in resources
                 if _is_sensitive(r, r["actions"], cfg["sensitive_resource_patterns"])]

    if sensitive:
        sensitivity = 1.0
    elif resources:
        sensitivity = 0.5
    else:
        sensitivity = 0.0

    return {
        "in_graph": bool(fns),
        "affected_functions": fns,
        "num_affected_functions": len(fns),
        "total_functions": total_fns,
        "is_public": any(q.is_function_public(G, f) for f in fns),
        "layer_shared": finding["component_type"] == "layer" and len(fns) >= 2,
        "iam_level": max([q.get_iam_privilege_level(G, f) for f in fns], default=0),
        "reachable_resources": [r["arn"] for r in resources],
        "sensitive_resources": [r["arn"] for r in sensitive],
        "resource_sensitivity": sensitivity,
    }


# ------------------------------------------------------------------------- scores
def _epss_norm(epss, cap):
    return min((epss or 0.0) / cap, 1.0)


def baseline_scores(finding, cfg):
    cvss = (finding.get("cvss") or 0.0) / 10.0
    w = cfg["cvss_epss_weights"]
    return {
        "cvss": round(cvss * 100, 2),
        "cvss_epss": round(100 * (w["cvss"] * cvss + w["epss"] * _epss_norm(finding.get("epss"), cfg["epss_cap"])), 2),
    }


def arch_score(finding, feats, cfg):
    w = cfg["arch_weights"]
    parts = {
        "cvss": (finding.get("cvss") or 0.0) / 10.0,
        "epss": _epss_norm(finding.get("epss"), cfg["epss_cap"]),
        "is_public": 1.0 if feats["is_public"] else 0.0,
        "num_affected_functions": feats["num_affected_functions"] / feats["total_functions"],
        "layer_shared": 1.0 if feats["layer_shared"] else 0.0,
        "iam_privilege": feats["iam_level"] / 3.0,
        "resource_sensitivity": feats["resource_sensitivity"],
    }
    return round(100 * sum(w[k] * parts[k] for k in w), 2), parts


def competition_ranks(scores):
    """Rank 1 = highest score. Equal scores share a rank (1,2,2,4)."""
    order = sorted(scores, reverse=True)
    return [order.index(s) + 1 for s in scores]


# ------------------------------------------------------------------------ reasons
def build_reason(finding, feats, rank_cvss, rank_arch):
    bits = []
    if not feats["in_graph"]:
        return "Component not found in the architecture graph; scored on CVSS/EPSS only."
    n = feats["num_affected_functions"]
    bits.append("Reaches a public-facing function" if feats["is_public"] else "No public-facing function affected")
    if feats["layer_shared"]:
        bits.append(f"in a shared layer, so it affects {n} functions")
    elif n > 1:
        bits.append(f"affects {n} functions")
    iam = {0: "no extra IAM permissions", 1: "read-only IAM", 2: "write-capable IAM", 3: "wildcard IAM permissions"}
    bits.append(iam[feats["iam_level"]])
    if feats["sensitive_resources"]:
        bits.append(f"can reach {len(feats['sensitive_resources'])} sensitive resource(s)")
    elif feats["reachable_resources"]:
        bits.append(f"can reach {len(feats['reachable_resources'])} resource(s)")
    cv = finding.get("cvss")
    tail = f"CVSS {cv}" if cv is not None else "no CVSS"
    if finding.get("cvss_version"):
        tail += f" (v{finding['cvss_version']})"
    tail += f", EPSS {finding.get('epss')}"
    shift = rank_cvss - rank_arch
    move = f"rank {rank_arch} by architecture vs {rank_cvss} by CVSS"
    if shift > 0:
        move += f" (promoted by {shift})"
    elif shift < 0:
        move += f" (demoted by {-shift})"
    return f"{'; '.join(bits)}. {tail}. {move}."


# ----------------------------------------------------------------------- pipeline
def prioritise(vulnerabilities, G, cfg):
    rows = []
    for v in vulnerabilities:
        feats = graph_features(G, v, cfg)
        base = baseline_scores(v, cfg)
        a, parts = arch_score(v, feats, cfg)
        rows.append({"finding": v, "features": feats, "parts": parts,
                     "scores": {**base, "arch": a}})

    ranks = {m: competition_ranks([r["scores"][m] for r in rows]) for m in METHODS}
    out = []
    for i, r in enumerate(rows):
        v, f = r["finding"], r["features"]
        rk = {m: ranks[m][i] for m in METHODS}
        out.append({
            "id": f"{v['cve_id']}|{v['component_name']}|{v['package']}=={v['version']}",
            "cve_id": v["cve_id"],
            "scenario": v.get("scenario"),
            "component_type": v["component_type"],
            "component_name": v["component_name"],
            "package": v["package"],
            "version": v["version"],
            "summary": v.get("summary"),
            "fixed_version": v.get("fixed_version"),
            "cvss": v.get("cvss"),
            "cvss_version": v.get("cvss_version"),
            "cvss_source": v.get("cvss_source"),
            "epss": v.get("epss"),
            "features": f,
            "scores": r["scores"],
            "ranks": rk,
            "rank_shift_arch_vs_cvss": rk["cvss"] - rk["arch"],
            "reason": build_reason(v, f, rk["cvss"], rk["arch"]),
        })
    out.sort(key=lambda x: (x["ranks"]["arch"], x["cve_id"], x["component_name"]))
    return out


def build_output(vulnerabilities, G, cfg):
    items = prioritise(vulnerabilities, G, cfg)
    return {
        "meta": {
            "count": len(items),
            "unique_cves": len({i["cve_id"] for i in items}),
            "score_scale": "0-100, higher = more urgent; rank 1 = most urgent, ties share a rank",
            "methods": {
                "cvss": "CVSS base score x 10",
                "cvss_epss": "weighted CVSS + capped EPSS",
                "arch": "weighted CVSS + EPSS + architecture features",
            },
            "config": cfg,
        },
        "priorities": items,
    }
