"""Shared helpers for the experiments (standard library only, no pandas/scipy)."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIORITIES = ROOT / "backend/priority/output/priorities.json"
OUT = Path(__file__).resolve().parent / "output"
TABLES, FIGURES = OUT / "tables", OUT / "figures"
METHODS = ["cvss", "cvss_epss", "arch"]
LABELS = {"cvss": "CVSS only", "cvss_epss": "CVSS + EPSS", "arch": "Architecture-aware"}


def load_priorities(path=PRIORITIES):
    if not Path(path).exists():
        raise SystemExit(f"{path} not found. Run: python -m backend.priority.run")
    return json.loads(Path(path).read_text(encoding="utf-8"))["priorities"]


def write_csv(name, rows, fields):
    TABLES.mkdir(parents=True, exist_ok=True)
    path = TABLES / name
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print("wrote", path.relative_to(ROOT))


def savefig(fig, name):
    FIGURES.mkdir(parents=True, exist_ok=True)
    path = FIGURES / name
    fig.savefig(path, dpi=160, bbox_inches="tight")
    print("wrote", path.relative_to(ROOT))


def short(i):
    return f"{i['cve_id']} @ {i['component_name']}"


# ---- rank statistics -------------------------------------------------------------
def avg_ranks(values):
    """Rank 1 = largest value; ties get the average of the ranks they span."""
    order = sorted(range(len(values)), key=lambda k: -values[k])
    ranks, pos = [0.0] * len(values), 0
    while pos < len(order):
        end = pos
        while end + 1 < len(order) and values[order[end + 1]] == values[order[pos]]:
            end += 1
        for k in order[pos:end + 1]:
            ranks[k] = (pos + end) / 2 + 1
        pos = end + 1
    return ranks


def pearson(x, y):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    sx = sum((a - mx) ** 2 for a in x) ** 0.5
    sy = sum((b - my) ** 2 for b in y) ** 0.5
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy) if sx and sy else float("nan")


def spearman(a, b):
    """Rank correlation of two score lists (-1..1)."""
    return pearson(avg_ranks(a), avg_ranks(b))


def kendall_tau_b(a, b):
    """Kendall's tau-b of two score lists, correct for ties (-1..1)."""
    n, conc, disc, ta, tb = len(a), 0, 0, 0, 0
    for i in range(n):
        for j in range(i + 1, n):
            da, db = a[i] - a[j], b[i] - b[j]
            if da == 0 and db == 0:
                continue
            if da == 0:
                ta += 1
            elif db == 0:
                tb += 1
            elif (da > 0) == (db > 0):
                conc += 1
            else:
                disc += 1
    denom = ((conc + disc + ta) * (conc + disc + tb)) ** 0.5
    return (conc - disc) / denom if denom else float("nan")


def top_ids(items, method, n):
    """First n findings by rank for a method (ties broken by CVE id, like the API)."""
    ranked = sorted(items, key=lambda i: (i["ranks"][method], i["cve_id"], i["component_name"]))
    return [i["id"] for i in ranked[:n]]
