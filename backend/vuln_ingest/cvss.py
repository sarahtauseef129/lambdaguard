"""Tiny CVSS v3.x base-score calculator.

OSV gives severity as a vector string like
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", not a number.
This turns that vector into the 0-10 base score.
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x):
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector):
    """Return the base score for a CVSS v3.x vector, or None if not parseable."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploit = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * pr * _UI[parts["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + exploit), 10))
        return _roundup(min(impact + exploit, 10))
    except (KeyError, ValueError, AttributeError):
        return None
