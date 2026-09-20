"""Evaluation stage 2: the NIST SARD PHP test suite.

No SARD corpus is committed: the suite is a 1 GB public download, and
`utils/prepare_sard.py` turns it into a corpus plus an `expected.json` ground truth. Point
this test at one with `--sard-corpus DIR` (or `$SARD_CORPUS`); without it the stage is
skipped.

The scoring runs through the shipped `utils/sard_eval.py`, so the script a reviewer runs by
hand is the same code the test exercises. SARD labels each case good (sanitized) or bad
(unsanitized), which makes a case a true positive when TaintRadar reports any path in an
unsanitized file and a false positive when it reports one in a sanitized file.
"""

import pytest

sard_eval = pytest.importorskip("sard_eval")


@pytest.fixture(scope="session")
def sard_results(sard_corpus, sard_findings):
    """Classify every case of the prepared corpus, reusing the shipped evaluation script."""
    ground_truth = sard_eval.load_ground_truth(sard_corpus / "expected.json")
    detections = {}
    for finding in sard_findings:
        filename = finding.get("filename", "")
        head, separator, tail = filename.partition("/")
        detections.setdefault(tail if separator else filename, set()).add(finding.get("vulnerability"))
    return ground_truth, sard_eval.classify(ground_truth, detections)


def test_every_case_is_scored_exactly_once(sard_results):
    ground_truth, results = sard_results
    assert ground_truth, "The corpus ground truth is empty"
    assert set(results) == set(ground_truth), (
        "Every case in expected.json must be classified exactly once; "
        f"{len(set(ground_truth) - set(results))} were not scored"
    )


def test_sard_metrics_are_reported(sard_results):
    """Score the corpus and print the table the paper reports for this stage.

    There is no committed baseline to compare against, because the corpus is whatever the
    reviewer sampled. Use `utils/sard_eval.py --fail-under-recall/--fail-under-precision`
    to turn a chosen corpus into a pass/fail gate.
    """
    ground_truth, results = sard_results
    metrics = sard_eval.compute_metrics(results)

    counts = [metrics[key] for key in ("tp", "tn", "fp", "fn")]
    assert sum(counts) == len(ground_truth), (
        f"The confusion matrix counts {sum(counts)} cases but the corpus holds {len(ground_truth)}"
    )

    print(
        "\nSARD detection summary over %d cases:\n" % len(ground_truth)
        + "\n".join(
            [f"{key}: {metrics[key]}" for key in ("tp", "tn", "fp", "fn")]
            + [
                f"{key}: {metrics[key]:.4f}"
                for key in ("accuracy", "precision", "recall", "specificity", "false_positive_rate", "f1")
            ]
        )
    )
