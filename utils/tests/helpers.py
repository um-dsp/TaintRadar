"""Shared helpers for the TaintRadar evaluation tests.

Two oracles live under `php-tests/`:

- `expected.json`       per-CPG-node sanitization tags, compared against `output/cpg.json`
- `expected-paths.json` per-file vulnerability verdicts, compared against
                        `output/paths/<name>-output.json`

A SARD corpus prepared by `utils/prepare_sard.py` carries an `expected.json` in the same
schema as the first one, keyed by the SARD/CWE message text rather than by a test
description. No SARD corpus is committed: see the README for how to build one.
"""

import json
from pathlib import Path

# utils/tests/helpers.py -> utils/tests -> utils -> repository root
REPO_ROOT = Path(__file__).resolve().parents[2]

PHP_TESTS_DIR = REPO_ROOT / "php-tests"

TAG_ORACLE = PHP_TESTS_DIR / "expected.json"
PATH_ORACLE = PHP_TESTS_DIR / "expected-paths.json"
UNIT_METRICS_BASELINE = PHP_TESTS_DIR / "expected-metrics.json"

# Tag names follow Utils.getTagName: "SAN_" + vulnerability.replace(" ", "_")
SAN_TAGS = ("SAN_XSS", "SAN_SQL_Injection")


def normalize_code(code):
    """Normalize code for flexible matching by:
    1. Removing parentheses
    2. Normalizing whitespace between function name and arguments
    3. Handling PHP function calls with and without parentheses
    """
    if code is None:
        return None

    # First remove all parentheses
    normalized = code.replace("(", " ").replace(")", "")

    # Normalize whitespace (collapse multiple spaces to single space)
    normalized = " ".join(normalized.split())

    return normalized


def normalize_file_name(file_name):
    """Normalize file names by removing leading directories."""
    return file_name.split("/")[-1] if file_name else None


def load_tag_oracle(path=TAG_ORACLE):
    """Flatten a tag oracle into a list of (group, entry) pairs.

    The oracle is a mapping of human-readable test description -> list of expected
    CPG nodes. Groups with no entries assert nothing and are skipped.
    """
    with open(path, "r") as f:
        oracle = json.load(f)
    return [(group, entry) for group, entries in oracle.items() for entry in entries]


def expected_vulnerability(entry):
    """Return the vulnerability a tag-oracle entry is about, or None if it has no tag."""
    if "SAN_SQL_Injection" in entry:
        return "SQL Injection"
    if "SAN_XSS" in entry:
        return "XSS"
    return None


def load_cpg_dump(path):
    """Load the node dump written by `cpg.toJson(...)` (see Utils.cpgToJson)."""
    with open(path, "r") as f:
        return json.load(f)


def index_cpg_dump(entries):
    """Index a CPG dump by (file basename, lineNumber) for O(1) oracle lookups.

    The unindexed scan in the original test re-parsed every node for every expectation;
    the oracle only ever matches on those two keys plus `code`, so an index is equivalent.
    """
    index = {}
    for entry in entries:
        key = (normalize_file_name(entry.get("file")), entry.get("lineNumber"))
        index.setdefault(key, []).append(entry)
    return index


def load_path_findings(path):
    """Load `output/paths/<name>-output.json` into a list of finding dicts.

    NavexMain.outputPaths builds this file by string concatenation, which leaves two
    quirks we have to absorb:
      * a run that found nothing writes a zero-byte file rather than `[]`
      * a node without a line number emits `"linenumber": ,`
    """
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return []

    raw = path.read_text()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Only the known missing-line-number quirk is repaired; anything else must surface.
        repaired = raw.replace('"linenumber": ,', '"linenumber": null,')
        try:
            findings = json.loads(repaired)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{path} is not valid JSON: {exc}") from exc
        return findings


def strip_root_prefix(filename):
    """Drop the CPG root directory that NavexMain prepends to every reported filename.

    `filename` is emitted as "<cpg-root-basename>/<path relative to the corpus>", e.g.
    "php-tests/sanitization/paperexample.php" or "sample/XSS/sanitized/281971.php".
    """
    if not filename:
        return filename
    head, sep, tail = filename.partition("/")
    return tail if sep else filename


def findings_by_file(findings):
    """Group findings by corpus-relative filename -> set of vulnerability names."""
    grouped = {}
    for finding in findings:
        name = strip_root_prefix(finding.get("filename"))
        grouped.setdefault(name, set()).add(finding.get("vulnerability"))
    return grouped


def classification_metrics(tp, tn, fp, fn):
    """Standard detection metrics over a confusion matrix, guarding empty denominators."""
    total = tp + tn + fp + fn

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "accuracy": ratio(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "specificity": ratio(tn, tn + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "f1": ratio(2 * precision * recall, precision + recall),
    }
