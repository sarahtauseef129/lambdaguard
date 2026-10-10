"""Compare the three rankings. Writes CSV tables and figures to experiments/output/.

    python -m experiments.compare_rankings
"""
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from experiments.common import (LABELS, METHODS, avg_ranks, kendall_tau_b, load_priorities,
                                savefig, short, spearman, top_ids, write_csv)

COLORS = {"cvss": "#9aa5b5", "cvss_epss": "#e0a33a", "arch": "#2f5fd0"}


def tables(items):
    write_csv("rankings.csv", [{
        "id": i["id"], "cve_id": i["cve_id"], "scenario": i["scenario"], "component": i["component_name"],
        "package": f"{i['package']}=={i['version']}", "cvss": i["cvss"], "cvss_version": i["cvss_version"],
        "epss": i["epss"], "public": i["features"]["is_public"], "functions": i["features"]["num_affected_functions"],
        "layer_shared": i["features"]["layer_shared"], "iam_level": i["features"]["iam_level"],
        "sensitivity": i["features"]["resource_sensitivity"],
        **{f"score_{m}": i["scores"][m] for m in METHODS}, **{f"rank_{m}": i["ranks"][m] for m in METHODS},
        "rank_shift": i["rank_shift_arch_vs_cvss"], "reason": i["reason"]}
        for i in items],
        ["id", "cve_id", "scenario", "component", "package", "cvss", "cvss_version", "epss", "public", "functions",
         "layer_shared", "iam_level", "sensitivity", *[f"score_{m}" for m in METHODS],
         *[f"rank_{m}" for m in METHODS], "rank_shift", "reason"])

    pairs = [("arch", "cvss"), ("arch", "cvss_epss"), ("cvss", "cvss_epss")]
    sc = {m: [i["scores"][m] for i in items] for m in METHODS}
    write_csv("rank_correlation.csv", [{"method_a": a, "method_b": b, "spearman": round(spearman(sc[a], sc[b]), 3),
                                        "kendall_tau_b": round(kendall_tau_b(sc[a], sc[b]), 3)} for a, b in pairs],
              ["method_a", "method_b", "spearman", "kendall_tau_b"])

    rows = []
    for n in (3, 5, 10):
        t = {m: set(top_ids(items, m, n)) for m in METHODS}
        rows += [{"top_n": n, "method_a": a, "method_b": b, "overlap": len(t[a] & t[b]),
                  "overlap_pct": round(100 * len(t[a] & t[b]) / n)} for a, b in pairs]
    write_csv("top_n_overlap.csv", rows, ["top_n", "method_a", "method_b", "overlap", "overlap_pct"])

    by = defaultdict(list)
    for i in items:
        by[i["scenario"]].append(i)
    srows = []
    for s, g in sorted(by.items()):
        srows.append({"scenario": s, "findings": len(g),
                      **{f"mean_rank_{m}": round(sum(i["ranks"][m] for i in g) / len(g), 1) for m in METHODS},
                      "promoted": sum(i["rank_shift_arch_vs_cvss"] > 0 for i in g),
                      "demoted": sum(i["rank_shift_arch_vs_cvss"] < 0 for i in g),
                      "unchanged": sum(i["rank_shift_arch_vs_cvss"] == 0 for i in g)})
    write_csv("scenario_summary.csv", srows, list(srows[0]))
    return srows


def figures(items, srows):
    # 1. rank shift per finding (positive = architecture-aware ranks it as more urgent than CVSS does)
    s = sorted(items, key=lambda i: i["rank_shift_arch_vs_cvss"])
    fig, ax = plt.subplots(figsize=(8, 0.3 * len(s) + 1.5))
    ax.barh([short(i) for i in s], [i["rank_shift_arch_vs_cvss"] for i in s],
            color=["#1e8e5a" if i["rank_shift_arch_vs_cvss"] > 0 else "#c0392b" if i["rank_shift_arch_vs_cvss"] < 0
                   else "#bbb" for i in s])
    ax.axvline(0, color="k", lw=0.8)
    ax.set_xlabel("Rank shift (CVSS rank − architecture rank); positive = promoted")
    ax.set_title("How architecture context moves each finding")
    ax.tick_params(axis="y", labelsize=7)
    savefig(fig, "rank_shift.png")
    plt.close(fig)

    # 2. CVSS rank vs architecture rank
    fig, ax = plt.subplots(figsize=(6, 6))
    scen = sorted({i["scenario"] for i in items})
    for k, sc in enumerate(scen):
        g = [i for i in items if i["scenario"] == sc]
        ax.scatter([i["ranks"]["cvss"] for i in g], [i["ranks"]["arch"] for i in g], s=45, alpha=0.8,
                   label=sc, color=plt.cm.Set1(k))
    hi = max(i["ranks"][m] for i in items for m in ("cvss", "arch")) + 1
    ax.plot([0, hi], [0, hi], "--", color="#888", lw=1)
    for i in sorted(items, key=lambda i: -abs(i["rank_shift_arch_vs_cvss"]))[:4]:
        ax.annotate(short(i), (i["ranks"]["cvss"], i["ranks"]["arch"]), fontsize=7, xytext=(4, 4),
                    textcoords="offset points")
    ax.set_xlim(0, hi); ax.set_ylim(hi, 0)
    ax.set_xlabel("Rank by CVSS only"); ax.set_ylabel("Rank by architecture-aware score")
    ax.set_title("Dashed line = identical ranking"); ax.legend(fontsize=8)
    savefig(fig, "rank_scatter.png")
    plt.close(fig)

    # 3. mean rank per scenario and method
    fig, ax = plt.subplots(figsize=(7, 4))
    w = 0.26
    for k, m in enumerate(METHODS):
        ax.bar([x + (k - 1) * w for x in range(len(srows))], [r[f"mean_rank_{m}"] for r in srows], w,
               label=LABELS[m], color=COLORS[m])
    ax.set_xticks(range(len(srows))); ax.set_xticklabels([r["scenario"] for r in srows])
    ax.invert_yaxis(); ax.set_ylabel("Mean rank (lower = more urgent)")
    ax.set_title("Which scenarios each method treats as urgent"); ax.legend(fontsize=8)
    savefig(fig, "scenario_mean_rank.png")
    plt.close(fig)


def main():
    items = load_priorities()
    srows = tables(items)
    figures(items, srows)
    print(f"\n{len(items)} findings. Promoted: {sum(i['rank_shift_arch_vs_cvss'] > 0 for i in items)}, "
          f"demoted: {sum(i['rank_shift_arch_vs_cvss'] < 0 for i in items)}, "
          f"unchanged: {sum(i['rank_shift_arch_vs_cvss'] == 0 for i in items)}")


if __name__ == "__main__":
    main()
