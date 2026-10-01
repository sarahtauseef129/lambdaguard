# lambdaguard
Architecture-aware vulnerability prioritization for AWS Lambda.

## Team
- Member A: Infra and Discovery
- Member B: Vulnerability Data and Graph
- Member C: Prioritization and Dashboard

## Folders
| Folder | Owner | Purpose |
|--------|-------|---------|
| infra/ | A | Test Lambda scenarios (SAM) |
| backend/discovery/ | A | boto3 discovery scripts |
| backend/vuln_ingest/ | B | CVE lookup |
| backend/graph/ | B | Graph builder |
| backend/priority/ | C | Scoring |
| backend/api/ | C | API server |
| frontend/ | C | Dashboard |
| experiments/ | B + C | Results |
| docs/ | All | Report chapters |

## Setup
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt

## Sample data
Mock files are in backend/discovery/samples/. Use them until real discovery output is ready.