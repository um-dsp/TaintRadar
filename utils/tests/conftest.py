"""Fixtures that drive TaintRadar end-to-end for the evaluation tests.

Each fixture shells out to the same commands the README documents -- `joern-parse`,
`./repl` and `./taint-radar` -- so the tests exercise the published workflow rather than
a private code path. Everything runs from the repository root, because the extension and
the `utils/` scripts resolve their inputs and outputs relative to the process working
directory.

Options:
  --joern-cli DIR   where joern-parse lives (default: $JOERN_CLI or ~/bin/joern/joern-cli)
  --reuse           reuse CPGs and outputs already present under output/ instead of rebuilding
  --module NAME     TaintRadar module to evaluate: vanilla, dataflow, sanitization, database
  --sard-corpus DIR a SARD corpus built by utils/prepare_sard.py; stage 2 is skipped
                    without it, because no SARD corpus is committed to the repository
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import (
    PHP_TESTS_DIR,
    REPO_ROOT,
    load_cpg_dump,
    load_path_findings,
)

# The tests score SARD through the shipped utils/sard_eval.py rather than a second copy
# of the same logic, so utils/ has to be importable.
sys.path.insert(0, str(REPO_ROOT / "utils"))

# Generous: parsing a corpus and running the dataflow traversals is minutes, not seconds.
COMMAND_TIMEOUT = 1800

TESTS_OUTPUT_DIR = REPO_ROOT / "output" / "tests"
CPG_DUMP = REPO_ROOT / "output" / "cpg.json"


def pytest_addoption(parser):
    group = parser.getgroup("taintradar")
    group.addoption(
        "--joern-cli",
        action="store",
        default=os.environ.get("JOERN_CLI", "~/bin/joern/joern-cli"),
        help="Directory containing joern-parse (default: $JOERN_CLI or ~/bin/joern/joern-cli)",
    )
    group.addoption(
        "--reuse",
        action="store_true",
        default=False,
        help="Reuse existing CPGs and TaintRadar outputs instead of regenerating them",
    )
    group.addoption(
        "--module",
        action="store",
        default="database",
        help="TaintRadar module to evaluate (vanilla, dataflow, sanitization, database)",
    )
    group.addoption(
        "--sard-corpus",
        action="store",
        default=os.environ.get("SARD_CORPUS"),
        help=(
            "Directory of a SARD corpus prepared by utils/prepare_sard.py, holding its "
            "expected.json. Stage 2 is skipped when this is not given."
        ),
    )


def run(command, cwd=REPO_ROOT, stdin=None):
    """Run a command from the repository root, failing the test with its output."""
    printable = " ".join(str(part) for part in command)
    result = subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Command failed with exit code {result.returncode}:\n"
            f"  {printable}\n"
            f"--- stdout (tail) ---\n{result.stdout[-4000:]}\n"
            f"--- stderr (tail) ---\n{result.stderr[-4000:]}"
        )
    return result


@pytest.fixture(scope="session")
def reuse(pytestconfig):
    return pytestconfig.getoption("--reuse")


@pytest.fixture(scope="session")
def module(pytestconfig):
    return pytestconfig.getoption("--module")


@pytest.fixture(scope="session")
def joern_parse(pytestconfig):
    """Path to joern-parse, or skip the session if Joern is not installed."""
    configured = os.path.expanduser(pytestconfig.getoption("--joern-cli"))
    candidates = [
        os.path.join(configured, "joern-parse"),
        # A Joern source checkout keeps the launcher one level above joern-cli/
        os.path.join(configured, "joern-cli", "joern-parse"),
        configured,
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    on_path = shutil.which("joern-parse")
    if on_path:
        return on_path

    tried = "\n".join(f"    {candidate}" for candidate in candidates + ["joern-parse (on $PATH)"])
    pytest.skip(
        f"joern-parse not found. Tried:\n{tried}\n"
        f"  Install Joern (see the README), then point the suite at it with "
        f"--joern-cli=/path/to/joern-cli or $JOERN_CLI. The default above is where the "
        f"README's install step puts it; an empty ~/bin/joern left over from an earlier "
        f"install looks the same as no install at all."
    )


@pytest.fixture(scope="session")
def taint_radar():
    """Path to the staged ./taint-radar launcher, or skip if the extension is not built."""
    executable = REPO_ROOT / "taint-radar"
    if not executable.exists():
        pytest.skip("./taint-radar not found. Build the extension first with `sbt stage`.")
    return executable


@pytest.fixture(scope="session")
def repl():
    """Path to the staged ./repl launcher, or skip if the extension is not built."""
    executable = REPO_ROOT / "repl"
    if not executable.exists():
        pytest.skip("./repl not found. Build the extension first with `sbt stage`.")
    return executable


def build_cpg(joern_parse_path, corpus_dir, reuse):
    """Parse a corpus directory into output/tests/<corpus>.bin."""
    TESTS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    cpg_bin = TESTS_OUTPUT_DIR / f"{corpus_dir.name}.bin"
    if reuse and cpg_bin.exists():
        return cpg_bin

    run([joern_parse_path, corpus_dir, "--language", "php", "-o", cpg_bin])
    if not cpg_bin.exists():
        pytest.fail(f"joern-parse reported success but did not write {cpg_bin}")
    return cpg_bin


def output_name(corpus_dir):
    """Reproduce the output naming in NavexMain.outputPaths.

    The CPG root directory name is truncated at the first '.', stripped of everything
    that is not a letter, and lowercased: "php-tests" -> "phptests".
    """
    stem = corpus_dir.name.split(".")[0]
    return "".join(character for character in stem if character.isalpha()).lower()


def run_taint_radar(taint_radar_path, cpg_bin, module):
    return run([taint_radar_path, cpg_bin, "--module", module])


def paths_output_for(corpus_dir):
    return REPO_ROOT / "output" / "paths" / f"{output_name(corpus_dir)}-output.json"


@pytest.fixture(scope="session")
def php_tests_schema():
    """Parse the schema of the paper's second-order example into output/db-schemas/.

    The database module finds an application's schema by the name of its root directory, so
    php-tests/ needs output/db-schemas/php-tests-database.csv. Without it TaintRadar falls
    back to the empty schema, no query has known columns, and the flow from insert.php to
    display.php cannot be linked. The file lives under the gitignored output/ directory, so
    the suite regenerates it the same way the README tells a reviewer to.
    """
    schema_csv = REPO_ROOT / "output" / "db-schemas" / f"{PHP_TESTS_DIR.name}-database.csv"
    run(
        [
            sys.executable,
            REPO_ROOT / "utils" / "extract_schema.py",
            PHP_TESTS_DIR / "paper" / "blog.sql",
            "--out-file",
            schema_csv.name,
        ]
    )
    if not schema_csv.exists():
        pytest.fail(f"extract_schema.py finished but did not write {schema_csv}")
    return schema_csv


@pytest.fixture(scope="session")
def php_tests_cpg(joern_parse, reuse):
    """CPG of the handwritten unit corpus in php-tests/."""
    return build_cpg(joern_parse, PHP_TESTS_DIR, reuse)


@pytest.fixture(scope="session")
def sard_corpus(pytestconfig):
    """Directory of a prepared SARD corpus, or skip stage 2.

    The SARD suite is a 1 GB public download rather than something the repository carries,
    so this points at whatever `utils/prepare_sard.py` wrote. See the README for the two
    commands that produce one.
    """
    configured = pytestconfig.getoption("--sard-corpus")
    if not configured:
        pytest.skip(
            "No SARD corpus given. Build one with "
            "`python3 utils/prepare_sard.py --download --sample 100 --seed 42 --out-dir sard/sample` "
            "and rerun with --sard-corpus=sard/sample (or set $SARD_CORPUS)."
        )

    corpus = Path(configured).expanduser().resolve()
    if not (corpus / "expected.json").is_file():
        pytest.fail(
            f"{corpus} does not look like a prepared SARD corpus: no expected.json in it. "
            f"Build one with utils/prepare_sard.py --out-dir {corpus}"
        )
    return corpus


@pytest.fixture(scope="session")
def sard_tests_cpg(joern_parse, sard_corpus, reuse):
    """CPG of the prepared SARD corpus."""
    return build_cpg(joern_parse, sard_corpus, reuse)


@pytest.fixture(scope="session")
def cpg_dump(php_tests_cpg, php_tests_schema, repl, reuse):
    """The augmented node dump of php-tests/, as written by `cpg.toJson`.

    `toJson` applies the sanitization and query tags before dumping, so every node in the
    result carries the SAN_* tags the oracle asserts on.
    """
    if not (reuse and CPG_DUMP.exists()):
        script = (
            f'importCpg("{php_tests_cpg}", "{php_tests_cpg.name}")\n'
            f'cpg.toJson("cpg.json")\n'
            f"exit\n"
        )
        run([repl, "--nocolors"], stdin=script)
        if not CPG_DUMP.exists():
            pytest.fail(
                f"./repl finished but did not write {CPG_DUMP}. "
                f"Check that `sbt stage` is up to date with the current sources."
            )
    return load_cpg_dump(CPG_DUMP)


@pytest.fixture(scope="session")
def php_tests_findings(php_tests_cpg, php_tests_schema, taint_radar, module, reuse):
    """Vulnerable paths TaintRadar reports for the handwritten unit corpus."""
    output_file = paths_output_for(PHP_TESTS_DIR)
    if not (reuse and output_file.exists()):
        run_taint_radar(taint_radar, php_tests_cpg, module)
    return load_path_findings(output_file)


@pytest.fixture(scope="session")
def sard_findings(sard_tests_cpg, sard_corpus, taint_radar, module, reuse):
    """Vulnerable paths TaintRadar reports for the prepared SARD corpus."""
    output_file = paths_output_for(sard_corpus)
    if not (reuse and output_file.exists()):
        run_taint_radar(taint_radar, sard_tests_cpg, module)
    return load_path_findings(output_file)
