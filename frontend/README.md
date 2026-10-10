# LambdaGuard dashboard

Plain HTML + JS (Chart.js from a CDN, so it needs internet for the chart). No build step.

```powershell
python -m backend.priority.run     # only if priorities.json is missing or the weights changed
python -m backend.api.main
```

Open http://127.0.0.1:8000 — the API serves this folder at `/`.

Pages: Overview · Architecture · Vulnerabilities (search, sort, click a row for the reason and a *Trace this CVE* link) · **Trace** (use case "Trace a Vulnerability": pick a CVE for affected packages and functions, exposure, IAM level, reachable resources, propagation paths and a drawn graph; empty = whole graph) · Comparison (top N per method + chart).
