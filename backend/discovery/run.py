import argparse
import json
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def get_policy_statements(lam, fn_name):
    """Resource policy of the function (who is allowed to invoke it)."""
    try:
        raw = lam.get_policy(FunctionName=fn_name)["Policy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    return as_list(json.loads(raw).get("Statement"))


def api_is_public(apigw, api_id):
    """Public if at least one route has no authorizer."""
    try:
        routes = apigw.get_routes(ApiId=api_id)["Items"]
    except ClientError:
        return None
    return any(r.get("AuthorizationType", "NONE") == "NONE" for r in routes)


def find_triggers(lam, apigw, fn_name):
    triggers = []
    for st in get_policy_statements(lam, fn_name):
        principal = st.get("Principal", {})
        service = principal.get("Service", "") if isinstance(principal, dict) else ""
        cond = st.get("Condition", {})
        src = (cond.get("ArnLike", {}).get("AWS:SourceArn")
               or cond.get("ArnEquals", {}).get("AWS:SourceArn") or "")

        if service.startswith("apigateway"):
            api_id = src.split(":")[5].split("/")[0] if src.count(":") >= 5 else None
            triggers.append({
                "type": "api_gateway",
                "api_id": api_id,
                "public": api_is_public(apigw, api_id) if api_id else None,
            })
        elif service.startswith("events"):
            triggers.append({
                "type": "eventbridge",
                "rule": src.split("/")[-1],
                "public": False,
            })
        elif service.startswith("s3"):
            triggers.append({"type": "s3", "bucket_arn": src, "public": False})

    for m in lam.list_event_source_mappings(FunctionName=fn_name)["EventSourceMappings"]:
        arn = m.get("EventSourceArn", "")
        kind = arn.split(":")[2] if arn.count(":") >= 2 else "unknown"
        triggers.append({"type": kind, "source_arn": arn, "public": False})
    return triggers


def get_role_info(iam, role_arn):
    role_name = role_arn.split("/")[-1]
    attached = [p["PolicyName"] for p in
                iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]
    inline = {}
    for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        inline[name] = iam.get_role_policy(
            RoleName=role_name, PolicyName=name)["PolicyDocument"]
    return attached, inline


def resources_and_actions(inline):
    found, actions = {}, set()
    for doc in inline.values():
        for st in as_list(doc.get("Statement")):
            if st.get("Effect") != "Allow":
                continue
            actions.update(as_list(st.get("Action")))
            for arn in as_list(st.get("Resource")):
                parts = arn.split(":")
                if len(parts) < 6 or parts[0] != "arn":
                    continue  # skips "*"
                base = arn[:-2] if arn.endswith("/*") else arn
                found[base] = parts[2]
    resources = [{"type": t, "arn": a} for a, t in found.items()]
    return resources, sorted(actions)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--output", default="backend/discovery/output/discovery_output.json")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    lam = session.client("lambda")
    iam = session.client("iam")
    apigw = session.client("apigatewayv2")

    functions, layers = [], {}

    for page in lam.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            fn_layers = []
            for layer in f.get("Layers", []):
                arn = layer["Arn"]
                name = arn.split(":")[6]
                fn_layers.append({"name": name, "arn": arn})
                if arn not in layers:
                    desc = lam.get_layer_version_by_arn(Arn=arn).get("Description", "")
                    layers[arn] = {"name": name, "arn": arn, "description": desc}

            attached, inline = get_role_info(iam, f["Role"])
            resources, actions = resources_and_actions(inline)

            functions.append({
                "name": f["FunctionName"],
                "arn": f["FunctionArn"],
                "role_arn": f["Role"],
                "runtime": f.get("Runtime"),
                "layers": fn_layers,
                "triggers": find_triggers(lam, apigw, f["FunctionName"]),
                "resources": resources,
                "iam": {
                    "attached_policies": attached,
                    "inline_policy_names": sorted(inline),
                    "allowed_actions": actions,
                },
            })

    result = {"functions": functions, "layers": list(layers.values())}

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"Saved {len(functions)} functions, {len(layers)} layers -> {out}")


if __name__ == "__main__":
    main()