#!/usr/bin/env python3
"""Reproduce the paper's SARD table (RQ1 / Table VIII) from a TaintRadar paths file.

This mirrors navex_utils/test/sard/parse-php-test-suite.ipynb exactly, so the numbers it
prints are directly comparable with the published row:

  * ground truth is the FIRST N test cases in manifest order (the notebook's
    `new_df.head(10000)`), including cases whose vulnerability is neither SQL Injection
    nor XSS -- the notebook labelled those "Other" and still scored them;
  * a file counts as detected when TaintRadar reported any path in it, whatever the
    vulnerability type (the notebook's classify_predictions ignores vulnerability_y);
  * TP unsanitized+detected, FP sanitized+detected, TN sanitized+undetected,
    FN unsanitized+undetected.

Unlike utils/sard_eval.py this does not need an expected.json and does not care how the
corpus was laid out on disk, so it works against the original rsync-style corpus the
paper used as well as a prepare_sard.py one.

Both metric families are reported, because they differ enormously on this benchmark:
the positive (vulnerable) class alone, and the class-weighted average that the paper's
table uses. Weighted recall is identically accuracy, which is why the paper's Acc and
Rec columns hold the same number.

Usage:
    python3 utils/sard_reproduce.py \
        --sard ~/Desktop/Texas/2022-05-12-php-test-suite-sqli-v1-0-0 \
        --paths ../joern/taint-radar/output/paths/+database/sardsample-output.json
"""

import argparse
import csv
import json
import sys
from pathlib import Path

import ijson

MANIFEST_NAME = "sarifs.json"


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sard", help="Directory holding the suite's sarifs.json")
    source.add_argument(
        "--labels-csv",
        help=(
            "The notebook's normalised manifest instead of sarifs.json -- "
            "navex_utils/test/sard/sarifs.csv. Use this when the suite directory is "
            "unreadable; the row order is the same, so head(N) matches the notebook"
        ),
    )
    parser.add_argument("--paths", required=True, help="TaintRadar <name>-output.json for the SARD corpus")
    parser.add_argument("--first", type=int, default=10000, help="Test cases to score, in manifest order (default: %(default)s)")
    parser.add_argument(
        "--strip-prefix",
        default=None,
        help="Corpus directory name to strip from reported filenames (default: the first path component)",
    )
    parser.add_argument("--out-dir", default="output/sard", help="Where to write metrics and error lists (default: %(default)s)")
    return parser.parse_args()


def classify_message(message):
    if "SQL Injection" in message:
        return "SQL Injection"
    if "Cross-site Scripting" in message:
        return "XSS"
    return "Other"


def load_ground_truth_csv(csv_path, first):
    """Same ground truth, read from the notebook's saved new_df (sarifs.csv).

    Row order is whatever to_csv wrote, which is new_df's order, so taking the first N
    rows here is the same set the notebook's new_df.head(N) scored.
    """
    import pandas as pd

    columns = ["physicalLocation.artifactLocation.uri", "vulnerability", "is_sanitized"]
    frame = pd.read_csv(csv_path, usecols=columns, nrows=first)

    truth = {}
    counts = {}
    for uri, vulnerability, is_sanitized in frame.itertuples(index=False):
        if not isinstance(uri, str):
            continue
        # to_csv wrote booleans as the strings "True"/"False"; pandas may give either.
        sanitized = is_sanitized if isinstance(is_sanitized, bool) else str(is_sanitized) == "True"
        truth[uri] = (vulnerability, sanitized)
        counts[vulnerability] = counts.get(vulnerability, 0) + 1

    print(f"[info] Ground truth: {len(truth)} test cases from {csv_path} (first {first} rows)")
    print("       by vulnerability: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    sanitized_total = sum(1 for _, is_san in truth.values() if is_san)
    print(f"       sanitized (negative class): {sanitized_total}")
    print(f"       unsanitized (positive class): {len(truth) - sanitized_total}")
    if len(truth) != first:
        print(f"[warn] Wanted {first} cases but got {len(truth)}; duplicate URIs collapse in the mapping")
    return truth


def load_ground_truth(sard_dir, first):
    """First `first` test cases in manifest order: uri -> (vulnerability, is_sanitized)."""
    manifest = Path(sard_dir).expanduser() / MANIFEST_NAME
    if not manifest.is_file():
        sys.exit(f"[error] No {MANIFEST_NAME} in {sard_dir}")

    truth = {}
    counts = {"SQL Injection": 0, "XSS": 0, "Other": 0}
    with open(manifest, "rb") as handle:
        for case in ijson.items(handle, "testCases.item"):
            runs = case.get("sarif", {}).get("runs") or []
            if not runs:
                continue
            run = runs[0]
            results = run.get("results") or []
            locations = (results[0].get("locations") if results else None) or []
            if not results or not locations:
                continue

            uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            if not uri:
                continue

            vulnerability = classify_message(results[0].get("message", {}).get("text", ""))
            truth[uri] = (vulnerability, run.get("properties", {}).get("state") == "good")
            counts[vulnerability] += 1
            if len(truth) >= first:
                break

    print(f"[info] Ground truth: {len(truth)} test cases in manifest order")
    print(f"       by vulnerability: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    sanitized = sum(1 for _, is_san in truth.values() if is_san)
    print(f"       sanitized (negative class): {sanitized}")
    print(f"       unsanitized (positive class): {len(truth) - sanitized}")
    if counts["Other"]:
        print(
            f"[note] {counts['Other']} case(s) are neither SQLi nor XSS. The notebook kept and "
            f"scored them, so they are kept here too.",
        )
    return truth


def load_detections(paths_file, strip_prefix):
    """Files TaintRadar reported any path in, keyed the same way as the ground truth."""
    raw = Path(paths_file).expanduser().read_text()
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError:
        findings = json.loads(raw.replace('"linenumber": ,', '"linenumber": null,'))

    detected = set()
    for finding in findings:
        filename = finding.get("filename", "")
        if strip_prefix:
            marker = strip_prefix.rstrip("/") + "/"
            filename = filename.split(marker, 1)[1] if marker in filename else filename
        else:
            # Default: drop the CPG root directory that NavexMain prefixes.
            head, separator, tail = filename.partition("/")
            filename = tail if separator else filename
        detected.add(filename)

    print(f"[info] TaintRadar reported paths in {len(detected)} distinct files")
    return detected


def score(truth, detected):
    results = {}
    for uri, (vulnerability, is_sanitized) in truth.items():
        hit = uri in detected
        if is_sanitized:
            label = "FP" if hit else "TN"
        else:
            label = "TP" if hit else "FN"
        results[uri] = (vulnerability, is_sanitized, hit, label)

    matched = sum(1 for uri in detected if uri in truth)
    print(f"[info] {matched} of the {len(detected)} reported files are inside the scored set")
    if matched == 0 and detected:
        print(
            "[error] No reported file matched the ground truth. The filename keys do not line "
            "up -- pass --strip-prefix with the corpus directory name.",
            file=sys.stderr,
        )
        sys.exit(1)
    return results


def metrics(results):
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for _, _, _, label in results.values():
        counts[label] += 1
    tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]
    total = tp + tn + fp + fn

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    vuln_precision = ratio(tp, tp + fp)
    vuln_recall = ratio(tp, tp + fn)
    vuln_f1 = ratio(2 * vuln_precision * vuln_recall, vuln_precision + vuln_recall)

    safe_precision = ratio(tn, tn + fn)
    safe_recall = ratio(tn, tn + fp)
    safe_f1 = ratio(2 * safe_precision * safe_recall, safe_precision + safe_recall)

    safe_support, vuln_support = tn + fp, tp + fn

    def weighted(safe_value, vuln_value):
        return ratio(safe_support * safe_value + vuln_support * vuln_value, total)

    # The macro average weights the two classes equally instead of by support. On a corpus
    # that is 82% sanitized the weighted figures are dominated by the safe class, which is
    # why a detector that never fires still scores a weighted F1 in the seventies; the
    # macro figures fall to the low forties for that detector, so they are the ones that
    # say whether vulnerabilities are actually being found.
    def macro(safe_value, vuln_value):
        return (safe_value + vuln_value) / 2

    null_safe_f1 = ratio(2 * ratio(safe_support, total), ratio(safe_support, total) + 1)

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": total,
        "safe_support": safe_support, "vulnerable_support": vuln_support,
        "accuracy": ratio(tp + tn, total),
        "false_positive_rate": ratio(fp, fp + tn),
        "vuln_precision": vuln_precision, "vuln_recall": vuln_recall, "vuln_f1": vuln_f1,
        "safe_precision": safe_precision, "safe_recall": safe_recall, "safe_f1": safe_f1,
        "weighted_precision": weighted(safe_precision, vuln_precision),
        "weighted_recall": weighted(safe_recall, vuln_recall),
        "weighted_f1": weighted(safe_f1, vuln_f1),
        "macro_precision": macro(safe_precision, vuln_precision),
        "macro_recall": macro(safe_recall, vuln_recall),
        "macro_f1": macro(safe_f1, vuln_f1),
        # A detector that never fires, scored on the same data, for reference.
        "null_detector_accuracy": ratio(safe_support, total),
        "null_detector_weighted_f1": weighted(null_safe_f1, 0.0),
        "null_detector_macro_f1": macro(null_safe_f1, 0.0),
    }


def report(m):
    pct = lambda value: value * 100

    print()
    print(f"  TP {m['tp']:>6}   TN {m['tn']:>6}   FP {m['fp']:>6}   FN {m['fn']:>6}   total {m['total']}")
    print(f"  class balance: {m['safe_support']} sanitized / {m['vulnerable_support']} unsanitized")
    print()
    print(f"  {'':<24}{'precision':>11}{'recall':>9}{'f1':>9}{'support':>9}")
    print(f"  {'Safe (sanitized)':<24}{pct(m['safe_precision']):>11.2f}{pct(m['safe_recall']):>9.2f}"
          f"{pct(m['safe_f1']):>9.2f}{m['safe_support']:>9}")
    print(f"  {'Vulnerable':<24}{pct(m['vuln_precision']):>11.2f}{pct(m['vuln_recall']):>9.2f}"
          f"{pct(m['vuln_f1']):>9.2f}{m['vulnerable_support']:>9}")
    print(f"  {'macro avg':<24}{pct(m['macro_precision']):>11.2f}{pct(m['macro_recall']):>9.2f}"
          f"{pct(m['macro_f1']):>9.2f}{m['total']:>9}")
    print(f"  {'weighted avg':<24}{pct(m['weighted_precision']):>11.2f}{pct(m['weighted_recall']):>9.2f}"
          f"{pct(m['weighted_f1']):>9.2f}{m['total']:>9}")
    print()
    print(f"  Accuracy {pct(m['accuracy']):.2f}    FPR {pct(m['false_positive_rate']):.2f}")
    print()
    print("  Paper table row (weighted averages, as published):")
    print(f"    Approach       Acc      F1    Prec     Rec     FPR")
    print(f"    TaintRadar {pct(m['accuracy']):>8.2f}{pct(m['weighted_f1']):>8.2f}"
          f"{pct(m['weighted_precision']):>8.2f}{pct(m['weighted_recall']):>8.2f}"
          f"{pct(m['false_positive_rate']):>8.2f}")
    print()
    print("  Same run, macro averages (both classes weighted equally):")
    print(f"    TaintRadar {pct(m['accuracy']):>8.2f}{pct(m['macro_f1']):>8.2f}"
          f"{pct(m['macro_precision']):>8.2f}{pct(m['macro_recall']):>8.2f}"
          f"{pct(m['false_positive_rate']):>8.2f}")
    print()
    print("  Same run, positive (vulnerable) class only:")
    print(f"    TaintRadar {pct(m['accuracy']):>8.2f}{pct(m['vuln_f1']):>8.2f}"
          f"{pct(m['vuln_precision']):>8.2f}{pct(m['vuln_recall']):>8.2f}"
          f"{pct(m['false_positive_rate']):>8.2f}")
    print()
    print(f"  Reference: a detector that flags nothing scores accuracy "
          f"{pct(m['null_detector_accuracy']):.2f} with FPR 0.00 on this same data,")
    print(f"  for a weighted F1 of {pct(m['null_detector_weighted_f1']):.2f} "
          f"and a macro F1 of {pct(m['null_detector_macro_f1']):.2f}.")
    if m["null_detector_accuracy"] >= m["accuracy"]:
        print("  ^ that accuracy is HIGHER than the measured accuracy above.")
    if m["null_detector_weighted_f1"] >= m["weighted_f1"]:
        print("  ^ and its weighted F1 is HIGHER too -- which is what the macro row is for.")


def main():
    args = parse_args()
    if args.labels_csv:
        truth = load_ground_truth_csv(args.labels_csv, args.first)
    else:
        truth = load_ground_truth(args.sard, args.first)
    detected = load_detections(args.paths, args.strip_prefix)
    results = score(truth, detected)
    m = metrics(results)
    report(m)

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "reproduce_metrics.json", "w") as handle:
        json.dump(m, handle, indent=4)
        handle.write("\n")
    print(f"\n[ok] Wrote {out_dir / 'reproduce_metrics.json'}")

    for label, name in (("FN", "reproduce_false_negatives.csv"), ("FP", "reproduce_false_positives.csv")):
        rows = sorted((v, s, uri) for uri, (v, s, _, lab) in results.items() if lab == label)
        with open(out_dir / name, "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["vulnerability", "is_sanitized", "file"])
            writer.writerows(rows)
        print(f"[ok] Wrote {out_dir / name} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
