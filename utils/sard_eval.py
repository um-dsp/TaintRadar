#!/usr/bin/env python3
"""Score TaintRadar's output against a SARD expectation file.

This is evaluation stage 2 of the paper: every SARD test case is a single PHP file that
the benchmark labels good (sanitized) or bad (unsanitized), so a file is classified by
whether TaintRadar reported any vulnerable path in it.

    TP  unsanitized file, path reported        FN  unsanitized file, nothing reported
    FP  sanitized file, path reported          TN  sanitized file, nothing reported

No SARD corpus ships with the repository; build one with utils/prepare_sard.py first.

Usage:
    python3 utils/sard_eval.py --expected sard/sample/expected.json \
                               --paths output/paths/sample-output.json
"""

import argparse
import csv
import json
import sys
from pathlib import Path

# Tag keys in the expectation file, per Utils.getTagName ("SAN_" + vulnerability, spaces -> _)
TAG_TO_VULNERABILITY = {
    "SAN_SQL_Injection": "SQL Injection",
    "SAN_XSS": "XSS",
}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--expected",
        required=True,
        help="Expectation file written by prepare_sard.py, e.g. sard/sample/expected.json",
    )
    parser.add_argument(
        "--paths",
        required=True,
        help="TaintRadar path output for the same corpus, e.g. output/paths/sample-output.json",
    )
    parser.add_argument(
        "--out-dir",
        default="output/sard",
        help="Where to write metrics.json and false_negatives.csv (default: %(default)s)",
    )
    parser.add_argument(
        "--fail-under-recall",
        type=float,
        default=None,
        help="Exit non-zero if recall falls below this value",
    )
    parser.add_argument(
        "--fail-under-precision",
        type=float,
        default=None,
        help="Exit non-zero if precision falls below this value",
    )
    return parser.parse_args()


def load_ground_truth(expected_path):
    """Map each test case file to (vulnerability, is_sanitized).

    The expectation file is keyed by the SARD message text; each entry names the file and
    carries exactly one SAN_* tag, whose value is "TRUE" when the case is sanitized.
    """
    with open(expected_path, "r") as handle:
        expected = json.load(handle)

    ground_truth = {}
    for entries in expected.values():
        for entry in entries:
            for tag, vulnerability in TAG_TO_VULNERABILITY.items():
                if tag in entry:
                    ground_truth[entry["file"]] = (vulnerability, entry[tag] == "TRUE")
                    break
    return ground_truth


def load_detections(paths_file):
    """Map each file TaintRadar reported on to the set of vulnerabilities it reported.

    A run that found nothing writes a zero-byte file rather than an empty array, and a
    node without a line number emits `"linenumber": ,` -- both come from the hand-built
    JSON in NavexMain.outputPaths.
    """
    paths_file = Path(paths_file)
    if not paths_file.exists():
        print(f"[warn] {paths_file} does not exist; treating the run as having found nothing", file=sys.stderr)
        return {}
    if paths_file.stat().st_size == 0:
        print(f"[info] {paths_file} is empty; TaintRadar reported no paths")
        return {}

    raw = paths_file.read_text()
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError:
        try:
            findings = json.loads(raw.replace('"linenumber": ,', '"linenumber": null,'))
        except json.JSONDecodeError as error:
            print(f"[error] {paths_file} is not valid JSON: {error}", file=sys.stderr)
            sys.exit(1)

    detections = {}
    for finding in findings:
        # NavexMain prefixes every filename with the CPG root directory name.
        filename = finding.get("filename", "")
        head, separator, tail = filename.partition("/")
        relative = tail if separator else filename
        detections.setdefault(relative, set()).add(finding.get("vulnerability"))
    return detections


def classify(ground_truth, detections):
    """Return per-file classifications: file -> (vulnerability, is_sanitized, detected, label)."""
    results = {}
    for filename, (vulnerability, is_sanitized) in ground_truth.items():
        detected = bool(detections.get(filename))
        if is_sanitized:
            label = "FP" if detected else "TN"
        else:
            label = "TP" if detected else "FN"
        results[filename] = (vulnerability, is_sanitized, detected, label)
    return results


def compute_metrics(results):
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for _, _, _, label in results.values():
        counts[label] += 1

    tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]
    total = tp + tn + fp + fn

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)

    # The paper's table reports sklearn's *weighted average* over both classes, not the
    # positive class alone -- which is why its accuracy and recall are the same number
    # (weighted recall is identically accuracy). Reproduce that here so the table can be
    # read straight off this output, and keep the positive-class figures alongside.
    safe_support = tn + fp          # sanitized files, the negative class
    vuln_support = tp + fn          # unsanitized files, the positive class

    safe_precision = ratio(tn, tn + fn)
    safe_recall = ratio(tn, tn + fp)
    safe_f1 = ratio(2 * safe_precision * safe_recall, safe_precision + safe_recall)

    def weighted(safe_value, vuln_value):
        return ratio(safe_support * safe_value + vuln_support * vuln_value, total)

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "total": total,
        "accuracy": ratio(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "specificity": ratio(tn, tn + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "f1": f1,
        "weighted_precision": weighted(safe_precision, precision),
        "weighted_recall": weighted(safe_recall, recall),
        "weighted_f1": weighted(safe_f1, f1),
        "safe_precision": safe_precision,
        "safe_recall": safe_recall,
        "safe_f1": safe_f1,
        "safe_support": safe_support,
        "vulnerable_support": vuln_support,
    }


def print_report(metrics, results):
    print()
    print(f"{'Test cases':<24}{metrics['total']}")
    print(f"{'True positives':<24}{metrics['tp']}")
    print(f"{'True negatives':<24}{metrics['tn']}")
    print(f"{'False positives':<24}{metrics['fp']}")
    print(f"{'False negatives':<24}{metrics['fn']}")
    print()
    for name in ("accuracy", "precision", "recall", "specificity", "false_positive_rate", "f1"):
        print(f"{name.replace('_', ' ').capitalize():<24}{metrics[name]:.4f}")

    # The paper's evaluation table, as percentages, using the weighted averages it reports.
    print()
    print("Paper table (weighted averages over both classes):")
    print(f"  {'Approach':<12}{'Acc':>8}{'F1':>8}{'Prec':>8}{'Rec':>8}{'FPR':>8}")
    print(
        f"  {'TaintRadar':<12}"
        f"{metrics['accuracy'] * 100:>8.2f}"
        f"{metrics['weighted_f1'] * 100:>8.2f}"
        f"{metrics['weighted_precision'] * 100:>8.2f}"
        f"{metrics['weighted_recall'] * 100:>8.2f}"
        f"{metrics['false_positive_rate'] * 100:>8.2f}"
    )
    print()
    print("  LaTeX row:")
    print(
        f"  TaintRadar & {metrics['accuracy'] * 100:.2f} & {metrics['weighted_f1'] * 100:.2f}"
        f" & {metrics['weighted_precision'] * 100:.2f} & {metrics['weighted_recall'] * 100:.2f}"
        f" & {metrics['false_positive_rate'] * 100:.2f} \\\\"
    )

    per_vulnerability = {}
    for vulnerability, _, _, label in results.values():
        per_vulnerability.setdefault(vulnerability, {"TP": 0, "TN": 0, "FP": 0, "FN": 0})[label] += 1
    if len(per_vulnerability) > 1:
        print()
        print(f"{'Vulnerability':<20}{'TP':>6}{'TN':>6}{'FP':>6}{'FN':>6}")
        for vulnerability, counts in sorted(per_vulnerability.items()):
            print(
                f"{vulnerability:<20}{counts['TP']:>6}{counts['TN']:>6}"
                f"{counts['FP']:>6}{counts['FN']:>6}"
            )


def write_outputs(out_dir, metrics, results):
    out_dir = Path(out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    metrics_file = out_dir / "metrics.json"
    with open(metrics_file, "w") as handle:
        json.dump(metrics, handle, indent=4)
        handle.write("\n")
    print(f"\n[ok] Wrote {metrics_file}")

    for label, name in (("FN", "false_negatives.csv"), ("FP", "false_positives.csv")):
        rows = sorted(
            (vulnerability, is_sanitized, filename)
            for filename, (vulnerability, is_sanitized, _, entry_label) in results.items()
            if entry_label == label
        )
        output_file = out_dir / name
        with open(output_file, "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["vulnerability", "is_sanitized", "file"])
            writer.writerows(rows)
        print(f"[ok] Wrote {output_file} ({len(rows)} rows)")


def main():
    args = parse_args()

    ground_truth = load_ground_truth(args.expected)
    if not ground_truth:
        print(f"[error] {args.expected} contains no expectations", file=sys.stderr)
        sys.exit(1)
    print(f"[info] Loaded {len(ground_truth)} expected test cases from {args.expected}")

    detections = load_detections(args.paths)
    print(f"[info] TaintRadar reported paths in {len(detections)} files")

    unknown = set(detections) - set(ground_truth)
    if unknown:
        print(
            f"[warn] {len(unknown)} reported files are absent from the expectation file "
            f"and are ignored, e.g. {sorted(unknown)[:3]}",
            file=sys.stderr,
        )

    results = classify(ground_truth, detections)
    metrics = compute_metrics(results)
    print_report(metrics, results)
    write_outputs(args.out_dir, metrics, results)

    for name, threshold in (("recall", args.fail_under_recall), ("precision", args.fail_under_precision)):
        if threshold is not None and metrics[name] < threshold:
            print(f"[error] {name} {metrics[name]:.4f} is below the required {threshold:.4f}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
