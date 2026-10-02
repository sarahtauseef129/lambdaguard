import argparse
import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

import boto3

DIST = re.compile(r"([^/]+)-([^/-]+)\.dist-info/")


def packages_in_zip(url):
    data = urllib.request.urlopen(url, timeout=120).read()
    found = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            m = DIST.search(name)
            if m:
                found[m.group(1).replace("_", "-").lower()] = m.group(2)
    return found


def scenario_of(fn_name):
    m = re.match(r"scenario-([a-z])-", fn_name)
    return f"scenario_{m.group(1)}" if m else "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--output", default="backend/discovery/output/dependencies.json")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    lam = session.client("lambda")

    rows, layer_owner = [], {}

    for page in lam.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            name = f["FunctionName"]
            scenario = scenario_of(name)
            url = lam.get_function(FunctionName=name)["Code"]["Location"]
            for pkg, ver in sorted(packages_in_zip(url).items()):
                rows.append({
                    "scenario": scenario,
                    "component_type": "function",
                    "component_name": name,
                    "package": pkg,
                    "version": ver,
                })
            for layer in f.get("Layers", []):
                layer_owner.setdefault(layer["Arn"], scenario)

    for arn, scenario in layer_owner.items():
        layer_name = arn.split(":")[6]
        url = lam.get_layer_version_by_arn(Arn=arn)["Content"]["Location"]
        for pkg, ver in sorted(packages_in_zip(url).items()):
            rows.append({
                "scenario": scenario,
                "component_type": "layer",
                "component_name": layer_name,
                "package": pkg,
                "version": ver,
            })

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2))
    print(f"Saved {len(rows)} dependencies -> {out}")


if __name__ == "__main__":
    main()