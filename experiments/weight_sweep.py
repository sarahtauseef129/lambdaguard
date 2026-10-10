"""Sensitivity of the architecture-aware ranking to its weights.

For each feature the weight is swept from 0 upward while the others keep their configured values
(weights are renormalised to sum to 1). For every setting we measure
  * Kendall tau vs the CVSS-only ranking (1 = identical, lower = more different), and
  * how many of the top 5 match the ranking produced by the default weights.

    python -m experiments.weight_sweep
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from backend.graph.build_graph import load_graph
from backend.priority import scoring as s
from backend.priority.run import DEFAULT_GRAPH, DEFAULT_VULNS
import json

from experiments.common import kendall_tau_b, savefig, top_ids, write_csv

VALUES = [0, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5]


def main():
    cfg = s.load_config()
    vulns = json.load(open(DEFAULT_VULNS, encoding="utf-8"))
    G = load_graph(DEFAULT_GRAPH)
    base_top5 = set(top_ids(s.prioritise(vulns, G, cfg), "arch", 5))

    rows = []
    for feat in cfg["arch_weights"]:
        for v in VALUES:
            w = dict(cfg["arch_weights"]); w[feat] = v
            try:
                items = s.prioritise(vulns, G, dict(cfg, arch_weights=s._normalise(w)))
            except ValueError:
                continue
            tau = kendall_tau_b([i["scores"]["arch"] for i in items], [i["scores"]["cvss"] for i in items])
            rows.append({"feature": feat, "weight": v, "tau_vs_cvss": round(tau, 3),
                         "top5_same_as_default": len(base_top5 & set(top_ids(items, "arch", 5))),
                         "promoted": sum(i["rank_shift_arch_vs_cvss"] > 0 for i in items),
                         "demoted": sum(i["rank_shift_arch_vs_cvss"] < 0 for i in items)})
    write_csv("weight_sweep.csv", rows, list(rows[0]))

    fig, (a, b) = plt.subplots(1, 2, figsize=(12, 4.5))
    for feat in cfg["arch_weights"]:
        r = [x for x in rows if x["feature"] == feat]
        a.plot([x["weight"] for x in r], [x["tau_vs_cvss"] for x in r], marker="o", label=feat)
        b.plot([x["weight"] for x in r], [x["top5_same_as_default"] for x in r], marker="o", label=feat)
    a.set_title("Agreement with CVSS-only ranking"); a.set_ylabel("Kendall tau vs CVSS (1 = identical)")
    b.set_title("Stability of the top 5"); b.set_ylabel("Top-5 findings shared with default weights")
    for ax in (a, b):
        ax.set_xlabel("Weight of the swept feature (before renormalising)"); ax.grid(alpha=0.3)
    b.set_yticks(range(0, 6))
    a.legend(fontsize=8)
    savefig(fig, "weight_sweep.png")
    plt.close(fig)


if __name__ == "__main__":
    main()
