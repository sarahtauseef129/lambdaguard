# Experiments

Run from the repo root (needs `backend/priority/output/priorities.json`; create it with `python -m backend.priority.run`):

```powershell
python -m experiments.run_all          # both scripts
python -m experiments.compare_rankings # tables + rank figures
python -m experiments.weight_sweep     # sensitivity to the weights
```

Results go to `experiments/output/tables/*.csv` and `experiments/output/figures/*.png`.

| File | What it shows |
|---|---|
| `rankings.csv` | Every finding with features, scores, ranks, rank shift and reason |
| `rank_correlation.csv` | Spearman and Kendall tau-b between the three methods |
| `top_n_overlap.csv` | How many of the top 3/5/10 two methods share |
| `scenario_summary.csv` | Mean rank and promoted/demoted counts per scenario |
| `weight_sweep.csv` | Effect of each weight on agreement with CVSS and on the top 5 |
| `rank_shift.png`, `rank_scatter.png`, `scenario_mean_rank.png`, `weight_sweep.png` | Report figures |
