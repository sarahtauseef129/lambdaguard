"""Offline API checks (no server needed).   python -m backend.api.test_api"""
from fastapi.testclient import TestClient

from backend.api.main import app

c = TestClient(app)


def main():
    assert c.get("/health").json() == {"status": "ok"}

    fns = c.get("/functions").json()
    assert {f["name"] for f in fns} == {"scenario-a-func", "scenario-b-func-1", "scenario-b-func-2", "scenario-c-func"}
    assert len(c.get("/layers").json()) == 1

    vulns = c.get("/vulnerabilities").json()
    assert len(vulns) == 34
    assert all({"scores", "ranks", "reason"} <= set(v) for v in vulns)
    assert {v["scenario"] for v in c.get("/vulnerabilities?scenario=scenario_c").json()} == {"scenario_c"}
    assert all(v["cvss"] >= 7.5 for v in c.get("/vulnerabilities?min_cvss=7.5").json())
    assert c.get("/vulnerabilities?min_cvss=11").status_code == 422

    for m in ("cvss", "cvss_epss", "arch"):
        r = c.get(f"/priorities?method={m}").json()
        assert len(r) == 34
        ranks = [x["rank"] for x in r]
        assert ranks == sorted(ranks) and r[0]["method"] == m and r[0]["rank"] == 1
        assert r[0]["score"] == max(x["score"] for x in r)
    assert len(c.get("/priorities?method=arch&limit=5").json()) == 5
    assert c.get("/priorities").json()[0]["method"] == "arch"          # default
    assert c.get("/priorities?method=bogus").status_code == 422

    g = c.get("/graph").json()
    assert g["nodes"] and g["edges"]
    small = c.get("/graph?include_vulns=false").json()
    assert all(n["type"] != "vulnerability" for n in small["nodes"])
    ids = {n["id"] for n in small["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in small["edges"])

    s = c.get("/summary").json()
    assert s["functions"] == 4 and s["findings"] == 34 and s["unique_cves"] == 20

    assert c.get("/vulnerabilities/CVE-2024-3651").json()
    assert c.get("/vulnerabilities/CVE-0000-0000").status_code == 404
    # trace: layer CVE reaches both B functions and A's function, through the layer
    t = c.get("/trace/CVE-2023-43804").json()
    assert {f["name"] for f in t["functions"]} == {"scenario-a-func", "scenario-b-func-1", "scenario-b-func-2"}
    assert any("common-utils-layer" in p["labels"] and "scenario-b-func-2" in p["labels"] for p in t["paths"])
    assert {n["type"] for n in t["graph"]["nodes"]} >= {"vulnerability", "package", "layer", "function", "trigger"}
    assert any(f["is_public"] for f in t["functions"]) and any(not f["is_public"] for f in t["functions"])
    # private function with wildcard IAM: resources reached and flagged sensitive
    t = c.get("/trace/cve-2024-3651").json()                       # case-insensitive
    cf = [f for f in t["functions"] if f["name"] == "scenario-c-func"][0]
    assert cf["iam_level"] == 3 and not cf["is_public"] and len(cf["resources"]) == 2 and all(r["sensitive"] for r in cf["resources"])
    assert any(p["labels"][-1].startswith("s3:") for p in t["paths"])
    assert all(n["label"] for n in c.get("/graph").json()["nodes"])
    r = c.get("/trace/CVE-0000-0000")
    assert r.status_code == 404 and "not found" in r.json()["detail"]
    print("All checks passed.")


if __name__ == "__main__":
    main()
