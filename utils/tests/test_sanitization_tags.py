"""Evaluation stage 1a: sanitization tags on the handwritten unit tests.

Each expectation in `php-tests/expected.json` names a node of the parsed corpus by file,
line and code, and states how TaintRadar's sanitization augmentation must label it
(`SAN_XSS` / `SAN_SQL_Injection`, "TRUE" = sanitized). The tests compare those
expectations against the augmented node dump written by `cpg.toJson`.

An expectation may carry an `"xfail"` key holding the reason a known analyzer limitation
keeps it from passing; those are reported as expected failures rather than errors.
"""

import pytest

from helpers import (
    index_cpg_dump,
    load_tag_oracle,
    normalize_code,
    normalize_file_name,
)

ORACLE = load_tag_oracle()


def oracle_id(case):
    _, entry = case
    return f"{entry['file']}:L{entry['lineNumber']}-{entry['code']}"


def required_keys(expected_entry):
    """The oracle keys to compare, ignoring tags the expectation does not pin down."""
    keys = ["file", "lineNumber", "code"]
    keys.extend(tag for tag in ("SAN_XSS", "SAN_SQL_Injection") if tag in expected_entry)
    return keys


def matches_key(cpg_entry, expected_entry, key):
    """Compare one oracle key, normalizing file names and code as the oracle intends."""
    if key == "file":
        return normalize_file_name(cpg_entry.get(key)) == normalize_file_name(expected_entry[key])
    if key == "code":
        return normalize_code(cpg_entry.get(key)) == normalize_code(expected_entry[key])
    return cpg_entry.get(key) == expected_entry[key]


@pytest.fixture(scope="session")
def cpg_index(cpg_dump):
    return index_cpg_dump(cpg_dump)


@pytest.mark.parametrize("case", ORACLE, ids=oracle_id)
def test_node_is_tagged_as_expected(case, request, cpg_index):
    group, expected_entry = case
    if "xfail" in expected_entry:
        request.node.add_marker(pytest.mark.xfail(reason=expected_entry["xfail"], strict=False))

    keys = required_keys(expected_entry)
    # `file` and `lineNumber` are exactly the index key, so only these nodes can match.
    candidates = cpg_index.get(
        (normalize_file_name(expected_entry["file"]), expected_entry["lineNumber"]), []
    )
    match_found = any(
        all(matches_key(candidate, expected_entry, key) for key in keys)
        for candidate in candidates
    )

    tags = ", ".join(
        f"{tag}: {expected_entry[tag]}"
        for tag in ("SAN_XSS", "SAN_SQL_Injection")
        if tag in expected_entry
    )
    closest = [
        {"code": candidate.get("code"), "normalized": normalize_code(candidate.get("code"))}
        for candidate in candidates
    ]

    assert match_found, (
        f"Missing CPG entry for:\n"
        f"Group: {group}\n"
        f"File: {expected_entry['file']}\n"
        f"Line: {expected_entry['lineNumber']}\n"
        f"Code: {expected_entry['code']}\n"
        f"Normalized: {normalize_code(expected_entry['code'])}\n"
        f"Expected {tags}\n"
        f"Closest matches: {closest if closest else 'None'}"
    )
