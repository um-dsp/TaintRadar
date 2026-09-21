#!/usr/bin/env python3
"""Score TaintRadar on the paper's SARD benchmark and print the Table VIII row.

The benchmark is the first 10,000 test cases of the NIST PHP SQLi suite in manifest
order, each a single file the suite labels good (sanitized) or bad (unsanitized). A file
counts as detected when TaintRadar reported any path in it, whatever the vulnerability
type -- the same rule the original notebook used.

    TP  unsanitized, path reported        FN  unsanitized, nothing reported
    FP  sanitized,   path reported        TN  sanitized,   nothing reported

The reported figures are macro averages: the two classes count equally. The corpus is
82% sanitized, so a support-weighted average on it is dominated by the safe class and a
detector that flags nothing scores a weighted F1 in the seventies. The macro row is the
one that says whether vulnerabilities are actually being found, and the summary prints
the flags-nothing baseline next to it so the reader can see the difference.

Usage:
    python3 utils/sard_reproduce.py \
        --paths output/paths/sardsample-output.json \
        --labels ../navex_utils/test/sard/sarifs.csv
"""

import argparse
import json
import re
from pathlib import Path

CASES = 10000
OUT_FILE = Path("output/sard/reproduce_metrics.json")


def case_id(path):
    """The SARD test-case number, whichever corpus layout is on disk.

    The suite as distributed names a case `464064-v1.0.0/src/sample.php`, while
    prepare_sard.py writes `XSS/sanitized/464064.php`. The number is the only thing the
    two share, so keying on it lets one scorer read either. Scanning from the right
    keeps a corpus directory whose own name starts with a digit from being mistaken for
    the case number.
    """
    for part in reversed(path.split("/")):
        match = re.match(r"(\d+)", part)
        if match:
            return match.group(1)
    return path


def load_labels(source, skip=0):
    """uri -> is_sanitized for CASES cases in manifest order, skipping the first `skip`."""
    path = Path(source).expanduser()
    if path.is_dir():
        return load_labels_manifest(path / "sarifs.json", skip)
    return load_labels_csv(path, skip)


def load_labels_csv(csv_path, skip):
    """The notebook's saved manifest. Row order is new_df's, so head(N) is the same set."""
    import pandas as pd

    frame = pd.read_csv(
        csv_path,
        usecols=["physicalLocation.artifactLocation.uri", "is_sanitized"],
        skiprows=range(1, skip + 1),
        nrows=CASES,
    )
    labels = {}
    for uri, is_sanitized in zip(frame["physicalLocation.artifactLocation.uri"], frame["is_sanitized"]):
        if isinstance(uri, str):
            # to_csv wrote booleans as "True"/"False"; pandas may hand back either.
            labels[case_id(uri)] = is_sanitized if isinstance(is_sanitized, bool) else str(is_sanitized) == "True"
    return labels


def load_labels_manifest(manifest, skip):
    import ijson

    labels = {}
    seen = 0
    with open(manifest, "rb") as handle:
        for case in ijson.items(handle, "testCases.item"):
            seen += 1
            if seen <= skip:
                continue
            runs = case.get("sarif", {}).get("runs") or []
            results = (runs[0].get("results") if runs else None) or []
            locations = (results[0].get("locations") if results else None) or []
            if not locations:
                continue
            uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            if uri:
                labels[case_id(uri)] = runs[0].get("properties", {}).get("state") == "good"
            if len(labels) >= CASES:
                break
    return labels


def load_detections(paths_file):
    """Test cases TaintRadar reported a path in, keyed as the labels are."""
    raw = Path(paths_file).expanduser().read_text()
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError:
        findings = json.loads(raw.replace('"linenumber": ,', '"linenumber": null,'))
    return {case_id(finding.get("filename", "")) for finding in findings}


def metrics(labels, detected):
    tp = tn = fp = fn = 0
    for uri, is_sanitized in labels.items():
        hit = uri in detected
        if is_sanitized:
            fp, tn = (fp + 1, tn) if hit else (fp, tn + 1)
        else:
            tp, fn = (tp + 1, fn) if hit else (tp, fn + 1)

    def ratio(numerator, denominator):
        return 100 * numerator / denominator if denominator else 0.0

    def f1(precision, recall):
        return ratio(2 * precision * recall, precision + recall) / 100

    total = tp + tn + fp + fn
    safe = {"precision": ratio(tn, tn + fn), "recall": ratio(tn, tn + fp), "support": tn + fp}
    vuln = {"precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "support": tp + fn}
    safe["f1"] = f1(safe["precision"], safe["recall"])
    vuln["f1"] = f1(vuln["precision"], vuln["recall"])

    def macro(key):
        return (safe[key] + vuln[key]) / 2

    def weighted(key):
        return (safe["support"] * safe[key] + vuln["support"] * vuln[key]) / total

    # A detector that flags nothing, scored on this same data, as the reference point.
    null_recall = ratio(safe["support"], total)
    null_f1 = f1(100.0, null_recall)

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "total": total,
        "safe": safe, "vulnerable": vuln,
        "accuracy": ratio(tp + tn, total),
        "false_positive_rate": ratio(fp, fp + tn),
        "macro_precision": macro("precision"),
        "macro_recall": macro("recall"),
        "macro_f1": macro("f1"),
        "weighted_precision": weighted("precision"),
        "weighted_recall": weighted("recall"),
        "weighted_f1": weighted("f1"),
        "null_detector_accuracy": null_recall,
        "null_detector_macro_f1": null_f1 / 2,
        "null_detector_weighted_f1": null_f1 * safe["support"] / total,
    }


def report(m):
    row = lambda name, p, r, f, s: print(f"  {name:<20}{p:>11.2f}{r:>9.2f}{f:>9.2f}{s:>10}")

    print(f"\n  TP {m['tp']:>5}   TN {m['tn']:>5}   FP {m['fp']:>5}   FN {m['fn']:>5}"
          f"   ({m['safe']['support']} sanitized / {m['vulnerable']['support']} unsanitized)\n")
    print(f"  {'':<20}{'precision':>11}{'recall':>9}{'f1':>9}{'support':>10}")
    for name, cls in (("Safe (sanitized)", m["safe"]), ("Vulnerable", m["vulnerable"])):
        row(name, cls["precision"], cls["recall"], cls["f1"], cls["support"])
    row("macro avg", m["macro_precision"], m["macro_recall"], m["macro_f1"], m["total"])
    print(f"\n  Accuracy {m['accuracy']:.2f}    FPR {m['false_positive_rate']:.2f}\n")

    print("  Table VIII row (macro averages):\n")
    print(f"    & TaintRadar & \\textbf{{{m['accuracy']:.2f}}} & \\textbf{{{m['macro_f1']:.2f}}}"
          f" & {m['macro_precision']:.2f} & \\textbf{{{m['macro_recall']:.2f}}}"
          f" & {m['false_positive_rate']:.2f} \\\\\n")
    print(f"  For the erratum: the same run under support-weighted averaging scores"
          f" F1 {m['weighted_f1']:.2f},")
    print(f"  precision {m['weighted_precision']:.2f}, recall {m['weighted_recall']:.2f}"
          f" -- but a detector that flags nothing scores")
    print(f"  accuracy {m['null_detector_accuracy']:.2f} and weighted F1"
          f" {m['null_detector_weighted_f1']:.2f} here, against macro F1"
          f" {m['null_detector_macro_f1']:.2f}.")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--paths", required=True,
                        help="TaintRadar <name>-output.json for the SARD corpus")
    parser.add_argument("--labels", required=True,
                        help="navex_utils/test/sard/sarifs.csv, or the suite directory holding sarifs.json")
    parser.add_argument("--skip", type=int, default=0,
                        help="Score the %(default)s cases starting after this many, instead of the "
                             "first ones. --skip 10000 scores the held-out slice that "
                             "prepare_sard.py --skip 10000 builds")
    args = parser.parse_args()

    labels = load_labels(args.labels, args.skip)
    detected = load_detections(args.paths)
    matched = sum(1 for uri in detected if uri in labels)
    print(f"[info] {len(labels)} test cases scored; TaintRadar reported paths in {len(detected)}"
          f" files, {matched} of them in the scored set")
    if not matched:
        raise SystemExit("[error] No reported file matched a label -- the paths file and the "
                         "--skip window describe different test cases.")

    m = metrics(labels, detected)
    report(m)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps(m, indent=4) + "\n")
    print(f"\n[ok] Wrote {OUT_FILE}")


if __name__ == "__main__":
    main()
