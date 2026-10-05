# Graph Model

The security graph is a NetworkX `MultiDiGraph`. It connects vulnerabilities to the
Lambda functions and cloud resources they can affect.

## Nodes

| Prefix | Type | Key attributes |
|--------|------|----------------|
| `vuln:<CVE>` | Vulnerability | cve_id, cvss, epss, summary |
| `pkg:<name>==<ver>` | Package | name, version |
| `layer:<name>` | Lambda Layer | name, arn |
| `fn:<name>` | Lambda Function | name, runtime, arn |
| `role:<name>` | IAM Role | allowed_actions, attached_policies |
| `trigger:<fn>:<type>` | Trigger | trigger_type, public |
| `res:<arn>` | Resource (S3, DynamoDB) | resource_type, arn |

## Edges

| From -> To | Relation | Meaning |
|------------|----------|---------|
| vuln -> pkg | `affects` | this vulnerability is in this package version |
| pkg -> fn / layer | `used_in` | the package is installed there |
| layer -> fn | `deployed_on` | the function uses the layer |
| fn -> role | `has_role` | the function runs with this IAM role |
| fn -> trigger | `triggered_by` | how the function is invoked |
| role -> res | `can_access` | the role's policy allows access (attribute: actions) |

## Example propagation path (Scenario B)

    vuln:<CVE> -> pkg:urllib3==1.24.1 -> layer:common-utils-layer -> fn:scenario-b-func-1
                                                                  -> fn:scenario-b-func-2

One vulnerable package in a shared layer reaches every function that uses the layer.

## Helper queries (`queries.py`)

- `get_affected_functions(G, package, version)`
- `is_package_in_shared_layer(G, package, version)` (layer used by 2+ functions)
- `is_function_public(G, function_name)`
- `get_iam_privilege_level(G, function_name)`: 0 none, 1 read-only, 2 specific writes, 3 wildcards
- `get_reachable_resources(G, function_name)`
- `get_vulnerability_context(G, cve_id)`: everything above for one CVE
- `trace_path(G, cve_id, function_name)`: readable propagation path

## Known limits

- Package versions are exact nodes: `urllib3==1.23` and `urllib3==1.24.1` are different nodes.
- IAM privilege is a simple heuristic on action names, not a full policy analysis.
- Resource edges come from the discovery output; the graph does not parse resource-level
  policy conditions.
