"""
The summary counts, in Python: the jq filters of ci-templates/tdxguard-lib.sh (TG_SARIF_ALL,
TG_OPENGREP_ERR, TG_CDX_SEV, ...) reimplemented so that the engine needs no jq.

Each function returns what its filter prints, and raises CountError where the filter fails
(jq exits non-zero): a report that is JSON but not of its format is an error in CI's summary
too. tests/test_counts.py runs the jq filters, read from tdxguard-lib.sh, against the same
documents and asserts equal results.

The helpers below follow jq's semantics, not Python's: `.key` on null is null and on
anything but an object an error; `.[]` iterates arrays and object values and fails on
anything else; `.[]?` swallows that failure; `==` never equates a boolean with a number.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Union

Number = Union[int, float]


class CountError(ValueError):
    """The report cannot be counted: the jq filter would fail on it."""


def _type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _index(value: Any, key: str) -> Any:
    """jq `.key`."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value.get(key)
    raise CountError(f"Cannot index {_type(value)} with string {key!r}")


def _iterate(value: Any) -> List[Any]:
    """jq `.[]`."""
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return list(value.values())
    raise CountError(f"Cannot iterate over {_type(value)}")


def _try_iterate(value: Any) -> List[Any]:
    """jq `.[]?`: an iteration that fails yields nothing."""
    try:
        return _iterate(value)
    except CountError:
        return []


def _equal(a: Any, b: Any) -> bool:
    """jq `==`: values of different jq types are never equal (true != 1)."""
    type_a, type_b = _type(a), _type(b)
    if type_a != type_b:
        return False
    if type_a == "array":
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if type_a == "object":
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    return bool(a == b)


def _ascii_downcase(value: Any) -> str:
    """jq `ascii_downcase`: only A-Z change; anything but a string is an error."""
    if not isinstance(value, str):
        raise CountError(f"{_type(value)} cannot be ascii_downcased")
    return value.translate(_ASCII_LOWER)


_ASCII_LOWER = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}


def length(document: Any) -> Number:
    """`length` (Betterleaks: one finding per array element; a clean scan writes null)."""
    if document is None:
        return 0
    if isinstance(document, bool):
        raise CountError(f"boolean ({str(document).lower()}) has no length")
    if isinstance(document, (int, float)):
        magnitude = abs(document)
        return int(magnitude) if float(magnitude).is_integer() else magnitude
    if isinstance(document, (str, list, dict)):
        return len(document)
    raise CountError(f"{_type(document)} has no length")


def sarif_all(document: Any) -> int:
    """TG_SARIF_ALL: `[.runs[].results[]] | length`."""
    return sum(len(_iterate(_index(run, "results"))) for run in _iterate(_index(document, "runs")))


def sarif_error(document: Any) -> int:
    """TG_SARIF_ERR: `[.runs[].results[] | select(.level=="error")] | length`."""
    count = 0
    for run in _iterate(_index(document, "runs")):
        for result in _iterate(_index(run, "results")):
            if _equal(_index(result, "level"), "error"):
                count += 1
    return count


def opengrep_error(document: Any) -> int:
    """
    TG_OPENGREP_ERR: `[.runs[] | .tool.driver.rules as $r | .results[] | .ruleId as $id |
    select($r[] | select(.id==$id and .defaultConfiguration.level=="error"))] | length`.

    Opengrep leaves result.level empty; the severity is on the rule. As in jq, a result
    counts once per matching rule (select emits its input for every true condition).
    """
    count = 0
    for run in _iterate(_index(document, "runs")):
        rules = _index(_index(_index(run, "tool"), "driver"), "rules")
        for result in _iterate(_index(run, "results")):
            rule_id = _index(result, "ruleId")
            for rule in _iterate(rules):
                # jq's `and` does not evaluate its right side when the left is false.
                if _equal(_index(rule, "id"), rule_id) and _equal(
                    _index(_index(rule, "defaultConfiguration"), "level"), "error"
                ):
                    count += 1
    return count


def cyclonedx_all(document: Any) -> int:
    """TG_CDX_ALL: `[.vulnerabilities[]?] | length`."""
    return len(_try_iterate(_index(document, "vulnerabilities")))


def cyclonedx_severe(document: Any) -> int:
    """
    TG_CDX_SEV: `[.vulnerabilities[]? | select(any(.ratings[]?; (.severity|ascii_downcase)
    as $s | $s=="critical" or $s=="high"))] | length`. `any` stops at the first match, so a
    malformed rating after a critical one is never looked at, as in jq.
    """
    count = 0
    for vulnerability in _try_iterate(_index(document, "vulnerabilities")):
        for rating in _try_iterate(_index(vulnerability, "ratings")):
            if _ascii_downcase(_index(rating, "severity")) in ("critical", "high"):
                count += 1
                break
    return count


# The tdxguard-lib.sh variable each function stands for. The tests run these filters.
FILTERS: Dict[str, Callable[[Any], Number]] = {
    "TG_SARIF_ALL": sarif_all,
    "TG_SARIF_ERR": sarif_error,
    "TG_OPENGREP_ERR": opengrep_error,
    "TG_CDX_ALL": cyclonedx_all,
    "TG_CDX_SEV": cyclonedx_severe,
}
LENGTH = "length"
