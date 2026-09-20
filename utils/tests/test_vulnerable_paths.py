"""Evaluation stage 1b: vulnerable paths on the handwritten unit tests.

`php-tests/expected-paths.json` records, for each fixture, whether TaintRadar is expected
to report a path of a given vulnerability -- the positive (vulnerable) and negative (secure)
cases the paper's stage 1 measures detection accuracy and false positives against.

An entry with a `lineNumber` is checked at that sink line; an entry without one is checked
at file granularity, which is what the catalogued corpora (web-app-v2) support. An entry
with an `xfail` key records a known limitation and its reason.
"""

import json

import pytest

from helpers import (
    PATH_ORACLE,
    UNIT_METRICS_BASELINE,
    classification_metrics,
    strip_root_prefix,
)

with open(PATH_ORACLE) as oracle_file:
    ORACLE = json.load(oracle_file)


def oracle_id(entry):
    location = entry["file"]
    if "lineNumber" in entry:
        location += f":L{entry['lineNumber']}"
    return f"{location}-{entry['vulnerability']}-{entry['expected']}"


def is_detected(findings, entry):
    """Did TaintRadar report a path node matching this expectation?"""
    for finding in findings:
        if strip_root_prefix(finding.get("filename")) != entry["file"]:
            continue
        if finding.get("vulnerability") != entry["vulnerability"]:
            continue
        if "lineNumber" in entry and finding.get("linenumber") != entry["lineNumber"]:
            continue
        return True
    return False


def describe(entry):
    lines = [f"  {key}: {entry[key]}" for key in ("file", "lineNumber", "code", "note") if key in entry]
    return "\n".join(lines)


@pytest.mark.parametrize("entry", ORACLE, ids=oracle_id)
def test_path_is_reported_as_expected(entry, request, php_tests_findings):
    if "xfail" in entry:
        request.node.add_marker(pytest.mark.xfail(reason=entry["xfail"], strict=False))

    detected = is_detected(php_tests_findings, entry)

    if entry["expected"] == "vulnerable":
        assert detected, (
            f"TaintRadar reported no {entry['vulnerability']} path where one is expected:\n"
            f"{describe(entry)}"
        )
    else:
        assert not detected, (
            f"TaintRadar reported a {entry['vulnerability']} path that is a false positive:\n"
            f"{describe(entry)}"
        )


def test_detection_metrics_have_not_regressed(php_tests_findings):
    """Aggregate stage-1 accuracy over the whole unit oracle, including known limitations.

    Every expectation counts, so the numbers describe TaintRadar as it actually behaves
    rather than only the cases that currently pass.
    """
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    misses = []
    for entry in ORACLE:
        detected = is_detected(php_tests_findings, entry)
        vulnerable = entry["expected"] == "vulnerable"
        if vulnerable and detected:
            counts["tp"] += 1
        elif vulnerable:
            counts["fn"] += 1
            misses.append(("FN", oracle_id(entry)))
        elif detected:
            counts["fp"] += 1
            misses.append(("FP", oracle_id(entry)))
        else:
            counts["tn"] += 1

    metrics = classification_metrics(**counts)
    report = "\n".join(
        [f"{key}: {value}" for key, value in counts.items()]
        + [f"{key}: {value:.4f}" for key, value in metrics.items()]
        + [f"{kind}: {name}" for kind, name in misses]
    )
    print("\nUnit-test detection summary:\n" + report)

    with open(UNIT_METRICS_BASELINE) as baseline_file:
        baseline = json.load(baseline_file)

    assert counts["fp"] <= baseline["fp"], (
        f"False positives regressed: {counts['fp']} > {baseline['fp']}\n{report}"
    )
    assert counts["tp"] >= baseline["tp"], (
        f"Detections regressed: {counts['tp']} < {baseline['tp']}\n{report}"
    )
