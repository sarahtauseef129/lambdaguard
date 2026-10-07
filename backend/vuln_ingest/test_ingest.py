"""Offline checks for the ingestion logic (no internet). Run: python -m backend.vuln_ingest.test_ingest"""
from unittest import mock

from . import run as run_mod
from .nvd import parse_nvd_score
from .osv_client import extract_fixed_version

V3_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def fake_osv(package, version, ecosystem="PyPI", cache=None, offline=False):
    # Two OSV records (GHSA + PYSEC) for the SAME CVE, with different severities,
    # plus a GIT range and two fix branches.
    ghsa = {"id": "GHSA-aaaa", "aliases": ["CVE-2099-0001"], "summary": "demo",
            "severity": [{"type": "CVSS_V3", "score": V3_98}],
            "affected": [{"ranges": [
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "deadbeefcafe"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.19"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.2.2"}]}]}]}
    pysec = {"id": "PYSEC-1", "aliases": ["CVE-2099-0001"], "database_specific": {"severity": "MODERATE"}}
    nolabel = {"id": "GHSA-bbbb", "aliases": ["CVE-2099-0002"], "summary": "no score in OSV"}
    return [ghsa, pysec, nolabel]


def main():
    # fixed-version logic
    v = fake_osv("x", "1.0")[0]
    assert extract_fixed_version(v, "1.24.1") == "1.26.19"      # not the git hash, right branch
    assert extract_fixed_version(v, "2.0.5") == "2.2.2"
    assert extract_fixed_version(v, None) != "deadbeefcafe"

    deps = [
        {"scenario": "a", "component_type": "function", "component_name": "fa", "package": "p", "version": "1.24.1"},
        {"scenario": "c", "component_type": "function", "component_name": "fc", "package": "p", "version": "1.24.1"},
    ]
    with mock.patch.object(run_mod, "query_osv", fake_osv), \
         mock.patch.object(run_mod, "_load_cache", lambda: {}), \
         mock.patch.object(run_mod, "_save_cache", lambda c: None), \
         mock.patch.object(run_mod, "fetch_epss", lambda ids, offline=False: {}), \
         mock.patch.object(run_mod, "fetch_nvd_scores",
                           lambda ids, offline=False: {"CVE-2099-0002": {"score": 6.5, "version": "3.1"}}):
        rows = run_mod.build_vulnerabilities(deps)

    # 2 CVEs x 2 components = 4 rows (GHSA+PYSEC for the same CVE are merged, not duplicated)
    assert len(rows) == 4, len(rows)
    by = {(r["component_name"], r["cve_id"]): r for r in rows}
    assert by[("fa", "CVE-2099-0001")]["cvss"] == by[("fc", "CVE-2099-0001")]["cvss"] == 9.8
    assert by[("fa", "CVE-2099-0001")]["cvss_source"] == "osv_v3"      # beats the MODERATE label
    assert by[("fa", "CVE-2099-0002")]["cvss"] == 6.5 and by[("fa", "CVE-2099-0002")]["cvss_source"] == "nvd"
    assert by[("fa", "CVE-2099-0001")]["fixed_version"] == "1.26.19"

    # NVD wins over OSV when both exist
    with mock.patch.object(run_mod, "query_osv", fake_osv), \
         mock.patch.object(run_mod, "_load_cache", lambda: {}), \
         mock.patch.object(run_mod, "_save_cache", lambda c: None), \
         mock.patch.object(run_mod, "fetch_epss", lambda ids, offline=False: {}), \
         mock.patch.object(run_mod, "fetch_nvd_scores", lambda ids, offline=False: {"CVE-2099-0001": {"score": 7.5, "version": "3.1"}}):
        rows = run_mod.build_vulnerabilities(deps)
    assert {r["cvss"] for r in rows if r["cve_id"] == "CVE-2099-0001"} == {7.5}
    # v3.x beats v4.0: OSV has a v3.1 vector (9.8) but NVD only has v4.0 (8.9) -> keep the v3 score
    with mock.patch.object(run_mod, "query_osv", fake_osv), \
         mock.patch.object(run_mod, "_load_cache", lambda: {}), \
         mock.patch.object(run_mod, "_save_cache", lambda c: None), \
         mock.patch.object(run_mod, "fetch_epss", lambda ids, offline=False: {}), \
         mock.patch.object(run_mod, "fetch_nvd_scores",
                           lambda ids, offline=False: {"CVE-2099-0001": {"score": 8.9, "version": "4.0"},
                                                       "CVE-2099-0002": {"score": 8.9, "version": "4.0"}}):
        rows = run_mod.build_vulnerabilities(deps)
    one = next(r for r in rows if r["cve_id"] == "CVE-2099-0001")
    assert (one["cvss"], one["cvss_version"], one["cvss_source"]) == (9.8, "3.1", "osv_v3"), one
    # when v4 is the only score available it is used, and labelled 4.0
    two = next(r for r in rows if r["cve_id"] == "CVE-2099-0002")
    assert (two["cvss"], two["cvss_version"], two["cvss_source"]) == (8.9, "4.0", "nvd"), two

    # NVD payload parsing returns the version too
    mk = lambda m: {"vulnerabilities": [{"cve": {"metrics": m}}]}
    assert parse_nvd_score(mk({"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5}}]})) == {"score": 7.5, "version": "3.1"}
    assert parse_nvd_score(mk({"cvssMetricV40": [{"cvssData": {"baseScore": 8.9}}]})) == {"score": 8.9, "version": "4.0"}
    both = mk({"cvssMetricV40": [{"cvssData": {"baseScore": 8.9}}], "cvssMetricV30": [{"cvssData": {"baseScore": 6.5}}]})
    assert parse_nvd_score(both) == {"score": 6.5, "version": "3.0"}   # v3 preferred over v4 inside NVD
    assert parse_nvd_score(mk({})) is None and parse_nvd_score({}) is None
    print("All ingest checks passed.")


if __name__ == "__main__":
    main()
