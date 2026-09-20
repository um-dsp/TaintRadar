#!/usr/bin/env python3
"""Turn the NIST SARD PHP test suite into a TaintRadar corpus and expectation file.

The suite ships one directory per test case plus a single `sarifs.json` manifest that
labels each case with a CWE, a sink location and a state ("good" = sanitized,
"bad" = unsanitized). This script reads that manifest and lays the cases out as

    <out-dir>/<vulnerability>/<sanitized|unsanitized>/<test case id>.php

alongside an `expected.json` in the same schema as `php-tests/expected.json`, which
`utils/sard_eval.py` and the evaluation tests score TaintRadar against.

The manifest is ~460 MB, so it is streamed rather than loaded; test case sources are read
straight out of the zip when the suite has not been extracted. Streaming an extracted
manifest costs about 15 MB of memory, while reading the same bytes through Python's
zipfile costs about 1.7 GB, so extract the suite first if memory is tight.

Usage:
    python3 utils/prepare_sard.py --download --sample 10 --seed 42 --out-dir sard-sample
    python3 utils/prepare_sard.py --sard sard/2022-05-12-php-test-suite-sqli-v1-0-0.zip
    python3 utils/prepare_sard.py --sard /path/to/extracted/suite --out-dir sard
"""

import argparse
import csv
import json
import os
import random
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

import ijson

SARD_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2022-05-12-php-test-suite-sqli-v1-0-0.zip"
MANIFEST_NAME = "sarifs.json"

# The suite labels cases by CWE message text; the notebook this script replaces keyed off
# the same strings rather than the rule id, and expected.json stays keyed by them.
VULNERABILITY_BY_MESSAGE = (
    ("SQL Injection", "SQL Injection"),
    ("Cross-site Scripting", "XSS"),
)

TAG_BY_VULNERABILITY = {
    "SQL Injection": "SAN_SQL_Injection",
    "XSS": "SAN_XSS",
}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--sard",
        default="sard",
        help="The SARD suite: a directory holding sarifs.json, or the downloaded .zip (default: %(default)s)",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help=f"Download the suite from {SARD_URL} (about 1 GB) if it is not already present",
    )
    parser.add_argument(
        "--out-dir",
        default="sard",
        help="Where to write the corpus and expected.json (default: %(default)s)",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        help="Emit a random sample of this many test cases instead of the whole suite",
    )
    parser.add_argument(
        "--first",
        type=int,
        default=None,
        help=(
            "Emit the first N test cases in manifest order instead of a random sample. "
            "This is what the paper used (the notebook's new_df.head(10000)), so use "
            "--first, not --sample, to reproduce its numbers"
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed used with --sample (default: %(default)s)",
    )
    return parser.parse_args()


def resolve_source(sard_path, download):
    """Return the .zip or directory holding the suite, downloading it if asked."""
    path = Path(sard_path).expanduser()

    if path.is_dir() and (path / MANIFEST_NAME).is_file():
        return path
    if path.is_file() and path.suffix == ".zip":
        return path

    # A directory that holds the zip but has not been extracted
    if path.is_dir():
        archives = sorted(path.glob("*.zip"))
        if archives:
            return archives[0]

    if not download:
        print(
            f"[error] No SARD suite at {path}. Pass --download to fetch it, point --sard at an "
            f"extracted copy containing {MANIFEST_NAME}, or symlink one into place.",
            file=sys.stderr,
        )
        sys.exit(1)

    path.mkdir(parents=True, exist_ok=True)
    archive = path / SARD_URL.rsplit("/", 1)[-1]
    print(f"[info] Downloading {SARD_URL}")
    print("[info] This is about 1 GB and is not tracked by git")
    with urllib.request.urlopen(SARD_URL) as response, open(archive, "wb") as handle:
        shutil.copyfileobj(response, handle)
    print(f"[ok] Wrote {archive}")
    return archive


class SuiteReader:
    """Read the manifest and test case sources from a zip or an extracted directory."""

    def __init__(self, source):
        self.source = source
        self.archive = zipfile.ZipFile(source) if source.is_file() else None

    def open_manifest(self):
        if self.archive:
            # Reading a 460 MB deflated member costs ~1.7 GB of buffers inside zipfile;
            # an extracted manifest streams in ~15 MB.
            print("[info] Reading the manifest from the archive; extract the suite to use less memory")
            return self.archive.open(MANIFEST_NAME)
        return open(self.source / MANIFEST_NAME, "rb")

    def read_source(self, uri):
        """Return a test case's source, read as bytes so line numbering stays byte-exact.

        These samples embed control characters (vertical tab, form feed, NEL) as XSS
        payload context. Text-mode reads and str.splitlines() both treat some of them as
        line breaks, which shifts every line number away from what the SARIF records.
        """
        if self.archive:
            raw = self.archive.read(uri)
        else:
            raw = (self.source / uri).read_bytes()
        return raw.decode("utf-8", errors="replace")

    def close(self):
        if self.archive:
            self.archive.close()


def classify_message(message):
    for needle, vulnerability in VULNERABILITY_BY_MESSAGE:
        if needle in message:
            return vulnerability
    return None


def iter_cases(reader, skipped=None):
    """Stream (case) dicts out of sarifs.json, skipping anything that is not XSS or SQLi.

    `skipped`, when given, is a one-element list that accumulates how many cases were
    dropped for having a vulnerability other than SQL Injection or XSS.
    """
    with reader.open_manifest() as manifest:
        for case in ijson.items(manifest, "testCases.item"):
            runs = case.get("sarif", {}).get("runs") or []
            if not runs:
                continue
            run = runs[0]
            results = run.get("results") or []
            if not results:
                continue
            result = results[0]
            locations = result.get("locations") or []
            if not locations:
                continue

            message = result.get("message", {}).get("text", "")
            vulnerability = classify_message(message)
            if vulnerability is None:
                if skipped is not None:
                    skipped[0] += 1
                continue

            physical = locations[0].get("physicalLocation", {})
            properties = run.get("properties", {})
            yield {
                "id": properties.get("id"),
                "message": message,
                "rule_id": result.get("ruleId"),
                "vulnerability": vulnerability,
                "is_sanitized": properties.get("state") == "good",
                "uri": physical.get("artifactLocation", {}).get("uri"),
                "start_line": physical.get("region", {}).get("startLine"),
            }


def collect(reader, sample, seed, first=None):
    """Collect every case, the first N of them, or a uniform sample, streaming throughout."""
    if first is not None:
        # Manifest order, matching the paper notebook's new_df.head(N). iter_cases drops
        # anything that is neither SQL Injection nor XSS, while the notebook kept those
        # rows as "Other" and scored them. Count them so the difference is visible: when
        # the tally is zero -- as expected for this SQLi suite -- the two agree exactly.
        skipped = [0]
        cases = []
        for case in iter_cases(reader, skipped=skipped):
            cases.append(case)
            if len(cases) >= first:
                break
        other = skipped[0]
        print(f"[info] Took the first {len(cases)} test cases in manifest order")
        if other:
            print(
                f"[warn] Skipped {other} case(s) in that prefix that are neither SQL Injection "
                f"nor XSS. The paper's notebook kept them as \"Other\" and scored them, so the "
                f"corpus differs from the paper's by that many cases.",
                file=sys.stderr,
            )
        else:
            print("[info] No non-SQLi/XSS cases in that prefix; matches the notebook's head(N)")
        return cases

    if sample is None:
        cases = list(iter_cases(reader))
        print(f"[info] Read {len(cases)} test cases from the manifest")
        return cases

    # Reservoir sampling: one pass, constant memory, independent of suite size.
    rng = random.Random(seed)
    reservoir = []
    for seen, case in enumerate(iter_cases(reader)):
        if seen < sample:
            reservoir.append(case)
        else:
            index = rng.randint(0, seen)
            if index < sample:
                reservoir[index] = case
    print(f"[info] Sampled {len(reservoir)} test cases (seed {seed})")
    return reservoir


def emit(reader, cases, out_dir):
    """Write the corpus, expected.json and manifest.csv; return the number of cases written."""
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    expected = {}
    manifest_rows = []
    written = 0
    skipped = 0

    for case in cases:
        if not case["uri"] or not case["start_line"] or case["id"] is None:
            skipped += 1
            continue
        try:
            code = reader.read_source(case["uri"])
        except (KeyError, FileNotFoundError):
            print(f"[warn] Missing source for test case {case['id']} at {case['uri']}", file=sys.stderr)
            skipped += 1
            continue

        status = "sanitized" if case["is_sanitized"] else "unsanitized"
        relative = f"{case['vulnerability']}/{status}/{case['id']}.php"
        destination = out_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(code.encode("utf-8"))

        # Split on newlines only, to match how the SARIF counts lines (see read_source).
        lines = code.split("\n")
        line_number = case["start_line"]
        # The sink line is the assertion's anchor; the trailing ';' is dropped so the text
        # lines up with the `code` property php2cpg puts on the call node.
        sink = lines[line_number - 1].strip().replace(";", "") if line_number <= len(lines) else ""

        entry = {
            "file": relative,
            "lineNumber": line_number,
            "code": sink,
            TAG_BY_VULNERABILITY[case["vulnerability"]]: "TRUE" if case["is_sanitized"] else "FALSE",
        }
        expected.setdefault(case["message"], []).append(entry)
        manifest_rows.append(
            [case["id"], case["rule_id"], case["vulnerability"], case["is_sanitized"], relative, line_number]
        )
        written += 1

    expected_file = out_dir / "expected.json"
    with open(expected_file, "w") as handle:
        json.dump(expected, handle, indent=4)
        handle.write("\n")
    print(f"[ok] Wrote {expected_file} ({written} expectations)")

    manifest_file = out_dir / "manifest.csv"
    with open(manifest_file, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "rule_id", "vulnerability", "is_sanitized", "file", "line_number"])
        writer.writerows(sorted(manifest_rows, key=lambda row: str(row[0])))
    print(f"[ok] Wrote {manifest_file}")

    if skipped:
        print(f"[warn] Skipped {skipped} test cases with no usable source or sink location", file=sys.stderr)

    print(f"[ok] Wrote {written} PHP files under {out_dir}")
    return written


def main():
    args = parse_args()

    source = resolve_source(args.sard, args.download)
    print(f"[info] Using SARD suite at {source}")

    if args.first is not None and args.sample is not None:
        print("[error] Pass --first or --sample, not both", file=sys.stderr)
        sys.exit(1)

    reader = SuiteReader(source)
    try:
        cases = collect(reader, args.sample, args.seed, args.first)
        if not cases:
            print("[error] The manifest yielded no XSS or SQL Injection test cases", file=sys.stderr)
            sys.exit(1)
        emit(reader, cases, args.out_dir)
    finally:
        reader.close()

    print()
    print("Next steps:")
    print(f"  <joern-cli>/joern-parse {args.out_dir} --language php -o output/tests/sard.bin")
    print(f"  ./taint-radar output/tests/sard.bin")
    print(f"  python3 utils/sard_eval.py --expected {os.path.join(args.out_dir, 'expected.json')} \\")
    print(f"                             --paths output/paths/sard-output.json")


if __name__ == "__main__":
    main()
