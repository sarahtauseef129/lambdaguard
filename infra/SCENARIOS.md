# Test Scenarios

Each scenario is a small, controlled setup. We compare how vulnerabilities rank
by CVSS only versus by architecture-aware score.

| Scenario | Idea | Vulnerable package | Why it matters |
|----------|------|--------------------|----------------|
| A | Public function, low-privilege role | requests==2.19.0 | Exposed to the internet, small blast radius |
| B | Vulnerable package in a shared layer used by 2 functions | urllib3==1.24.1 (in layer) | One bad package affects many functions |
| C | Private function, over-permissive IAM role | idna==2.7 | Not public, but a compromise reaches S3 and DynamoDB |

## Sensitive resources (dummy data only)
- S3 bucket: lambdaguard-sensitive-<random-suffix>
- DynamoDB table: Users

## Rules
- Never put real secrets or data in these resources.
- Every resource has the tag Project=lambdaguard.
- Delete stacks after testing: sam delete