"""File access for the API. Files are re-read automatically when they change on disk."""
import json
from pathlib import Path

from backend.graph.build_graph import load_graph
from backend.priority.scoring import build_output, load_config

ROOT = Path(__file__).resolve().parents[2]
DISCOVERY = ROOT / "backend/discovery/output/discovery_output.json"
VULNS = ROOT / "backend/vuln_ingest/output/vulnerabilities.json"
GRAPH = ROOT / "backend/graph/output/graph.json"
PRIORITIES = ROOT / "backend/priority/output/priorities.json"

_cache = {}


def _cached(path, loader):
    """Return loader(path), reloading only if the file's modification time changed."""
    mtime = path.stat().st_mtime
    key = (path, loader)
    hit = _cache.get(key)
    if hit and hit[0] == mtime:
        return hit[1]
    value = loader(path)
    _cache[key] = (mtime, value)
    return value


def _json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def discovery():
    return _cached(DISCOVERY, _json)


def graph_json():
    return _cached(GRAPH, _json)


def graph_nx():
    return _cached(GRAPH, load_graph)


def priorities():
    """priorities.json; if it has not been generated yet, compute it on the fly."""
    if PRIORITIES.exists():
        return _cached(PRIORITIES, _json)
    return build_output(_cached(VULNS, _json), load_graph(GRAPH), load_config())
