import json
from pathlib import Path

base = Path(__file__).parent / "samples"

discovery = json.loads((base / "discovery_output.json").read_text())
deps = json.loads((base / "dependencies.json").read_text())

func_keys = {"name", "arn", "role_arn", "runtime", "layers", "triggers", "resources"}
dep_keys = {"scenario", "component_type", "component_name", "package", "version"}

for f in discovery["functions"]:
    missing = func_keys - f.keys()
    assert not missing, f"{f.get('name')} missing: {missing}"

for d in deps:
    missing = dep_keys - d.keys()
    assert not missing, f"{d} missing: {missing}"

print("OK:", len(discovery["functions"]), "functions,", len(deps), "dependencies")