"""Checks the graph against Nabiha's three scenarios. Needs no internet.

Run from repo root:  python -m backend.graph.test_graph
Uses real vulnerabilities.json if it exists, else the mock sample.
"""
import json
from pathlib import Path

from .build_graph import DEFAULT_DEPS, DEFAULT_DISCOVERY, DEFAULT_VULNS, build_graph
from .queries import (get_affected_functions, get_iam_privilege_level, get_reachable_resources,
                      get_vulnerability_context, is_function_public, is_package_in_shared_layer, trace_path)

MOCK = Path("backend/graph/samples/vulnerabilities_mock.json")


def main():
    vuln_path = DEFAULT_VULNS if DEFAULT_VULNS.exists() else MOCK
    print(f"Using vulnerabilities from: {vuln_path}")
    G = build_graph(json.loads(DEFAULT_DISCOVERY.read_text()),
                    json.loads(DEFAULT_DEPS.read_text()),
                    json.loads(vuln_path.read_text()))

    # Scenario B: package in a shared layer -> BOTH functions affected
    assert get_affected_functions(G, "urllib3", "1.24.1") == ["scenario-b-func-1", "scenario-b-func-2"]
    assert is_package_in_shared_layer(G, "urllib3", "1.24.1")

    # Scenario A: direct dependency, only scenario-a-func, public, low privilege
    assert get_affected_functions(G, "requests", "2.19.0") == ["scenario-a-func"]
    assert not is_package_in_shared_layer(G, "requests", "2.19.0")
    assert is_function_public(G, "scenario-a-func")
    assert get_iam_privilege_level(G, "scenario-a-func") == 0

    # urllib3 1.23 (scenario A direct) is a different node from 1.24.1 (layer)
    assert get_affected_functions(G, "urllib3", "1.23") == ["scenario-a-func"]

    # Scenario C: private, but wildcard IAM reaches S3 + DynamoDB
    assert not is_function_public(G, "scenario-c-func")
    assert get_iam_privilege_level(G, "scenario-c-func") == 3
    kinds = {r["type"] for r in get_reachable_resources(G, "scenario-c-func")}
    assert kinds == {"s3", "dynamodb"}, kinds

    # idna 2.7 is used in BOTH scenario A and scenario C
    assert get_affected_functions(G, "idna", "2.7") == ["scenario-a-func", "scenario-c-func"]

    # Scenario B function 1 is public, function 2 is not (layer vuln reaches both anyway)
    assert is_function_public(G, "scenario-b-func-1") and not is_function_public(G, "scenario-b-func-2")

    # Propagation path through the layer
    cve = next(d["cve_id"] for n, d in G.nodes(data=True)
               if d.get("type") == "vulnerability" and G.has_edge(n, "pkg:urllib3==1.24.1"))
    path = trace_path(G, cve, "scenario-b-func-2")
    print("Path:", " -> ".join(path))
    assert path and any(p.startswith("layer:") for p in path)

    ctx = get_vulnerability_context(G, cve)
    print(json.dumps(ctx, indent=2))
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
