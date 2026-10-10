"""Offline checks for the prioritisation engine, run on the committed real data.

    python -m backend.priority.test_priority
"""
import json

from backend.graph.build_graph import load_graph
from backend.priority import scoring as s
from backend.priority.run import DEFAULT_GRAPH, DEFAULT_VULNS


def main():
    cfg = s.load_config()
    vulns = json.load(open(DEFAULT_VULNS, encoding="utf-8"))
    G = load_graph(DEFAULT_GRAPH)
    out = s.build_output(vulns, G, cfg)
    items = out["priorities"]
    by = lambda **kw: [i for i in items if all(i[k] == v for k, v in kw.items())]

    # every input row becomes exactly one finding, with unique ids
    assert len(items) == len(vulns), "row count changed"
    assert len({i["id"] for i in items}) == len(items), "duplicate finding ids"

    # shared layer: both B functions affected, flagged shared
    for i in by(component_name="common-utils-layer"):
        f = i["features"]
        assert f["affected_functions"] == ["scenario-b-func-1", "scenario-b-func-2"]
        assert f["layer_shared"] and f["is_public"]

    # scenario A: one public function, no IAM reach
    for i in by(scenario="scenario_a"):
        f = i["features"]
        assert f["affected_functions"] == ["scenario-a-func"] and f["is_public"]
        assert f["iam_level"] == 0 and f["resource_sensitivity"] == 0.0

    # scenario C: private, wildcard IAM, sensitive resources; must NOT inherit A's function
    for i in by(scenario="scenario_c"):
        f = i["features"]
        assert f["affected_functions"] == ["scenario-c-func"], "idna==2.7 leaked across scenarios"
        assert not f["is_public"] and f["iam_level"] == 3 and f["resource_sensitivity"] == 1.0

    # scores in range, ranks consistent with scores
    for m in s.METHODS:
        for a in items:
            assert 0 <= a["scores"][m] <= 100
            for b in items:
                if a["scores"][m] > b["scores"][m]:
                    assert a["ranks"][m] < b["ranks"][m]
                if a["scores"][m] == b["scores"][m]:
                    assert a["ranks"][m] == b["ranks"][m]

    # architecture awareness changes the ranking, and the private-but-powerful case is promoted
    assert any(i["rank_shift_arch_vs_cvss"] != 0 for i in items), "arch ranking identical to CVSS"
    c = by(scenario="scenario_c", cve_id="CVE-2024-3651")[0]
    assert c["rank_shift_arch_vs_cvss"] > 0, "wildcard-IAM finding should be promoted"

    # weights are normalised and configurable
    assert abs(sum(cfg["arch_weights"].values()) - 1) < 1e-9
    only_cvss = dict(cfg, arch_weights={"cvss": 1, "epss": 0, "is_public": 0, "num_affected_functions": 0,
                                        "layer_shared": 0, "iam_privilege": 0, "resource_sensitivity": 0})
    only_cvss["arch_weights"] = s._normalise(only_cvss["arch_weights"])
    same = s.prioritise(vulns, G, only_cvss)
    assert all(i["ranks"]["arch"] == i["ranks"]["cvss"] for i in same), "cvss-only weights must match baseline"

    # unknown component degrades gracefully
    ghost = [dict(vulns[0], component_name="no-such-func")]
    g = s.prioritise(ghost, G, cfg)[0]
    assert not g["features"]["in_graph"] and "not found" in g["reason"]

    assert s.competition_ranks([9, 7, 7, 3]) == [1, 2, 2, 4]
    print("All checks passed.")


if __name__ == "__main__":
    main()
