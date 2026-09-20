# TaintRadar

**Semantic-Aware Taint-Style Vulnerability Detection via Augmented Code Property Graphs**

TaintRadar is a static analysis framework for PHP applications. It detects taint-style vulnerabilities by analyzing Code Property Graphs (CPGs) that it first augments with:

- **Object dependency modeling**
- **Schema-aware database analysis**
- **Sanitization tracking**

These augmentations make the analysis more precise and cut down on false positives.

This project is a fork of the [standalone Joern extension](https://github.com/joernio/standalone-ext) sample repository. It adds the TaintRadar traversals, plus utility and evaluation scripts.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [1. (Optional) Parse the database schema](#1-optional-parse-the-database-schema)
  - [2. Parse the application into a CPG](#2-parse-the-application-into-a-cpg)
  - [3. Run TaintRadar](#3-run-taintradar)
- [Reproducing the paper's results](#reproducing-the-papers-results)
  - [Generate the whitelist of safe PHP functions](#generate-the-whitelist-of-safe-php-functions)
  - [Color an AST by sanitization](#color-an-ast-by-sanitization)
  - [Match vulnerable paths with public CVEs](#match-vulnerable-paths-with-public-cves)

## Requirements

| Component | Requirements |
| --- | --- |
| TaintRadar Joern extension | JDK 21 (other versions may work but haven't been tested), [sbt](https://www.scala-sbt.org/download/) (macOS: `brew install sbt`; Debian/Ubuntu: add sbt's apt repository first, as described on the download page) |
| Joern (CPG generation) | PHP 7.1 or later on your `PATH` (Joern's PHP frontend runs it), GNU coreutils on macOS (`brew install coreutils`), about 4 GB of free disk space for the installation |
| Data preparation & evaluation scripts | Python 3.10 or later, [Graphviz](https://graphviz.org/) (only for AST coloring) |

## Installation

### Joern

TaintRadar needs Joern's `joern-parse` to build CPGs. Download and run the Joern installer outside this repository:

```bash
curl -L "https://github.com/joernio/joern/releases/download/v4.0.629/joern-install.sh" -o joern-install.sh
chmod u+x joern-install.sh
./joern-install.sh --version=v4.0.629
```

TaintRadar has been tested with CPGs from Joern v4.0.629, so the commands above pin that release.

- Joern is installed in `~/bin/joern`, so `joern-parse` is at `~/bin/joern/joern-cli/joern-parse`. The installer doesn't add it to your `PATH`.
- The installer leaves the downloaded archive (`joern-cli-<platform>.zip`, about 1.7 GB) in the current directory. You can delete it once the installation completes.

### TaintRadar extension

Compile the extension from the repository root:

```bash
sbt stage
```

This creates the `./taint-radar` executable.

### Python environment

Set up the Python environment for the scripts in `utils/`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r utils/requirements.txt
```

## Usage

Run all commands from the repository root. The scripts and the extension read and write files under `output/` using relative paths.

### 1. (Optional) Parse the database schema

To use the database integration module, first give the SQL script that creates the application's tables to the schema parser:

```bash
python3 utils/extract_schema.py /path/to/app.sql --out-file <app-root-dir>-database.csv
```

The parsed schema is written to `output/db-schemas/`.

> [!IMPORTANT]
> TaintRadar finds an application's schema by filename. The file must be named after the application's **root directory**, followed by `-database.csv`. For example, for Tailor:
>
> ```bash
> python3 utils/extract_schema.py applications/tailor/tailor.sql --out-file tailor-database.csv
> ```
>
> If you leave out `--out-file`, the name comes from the SQL file (`<sql-file-name>-database.csv`). That name often matches the application, but check it.

**To turn off database integration**, skip this step. Also make sure that `output/db-schemas/` has no schema file already parsed for that application (delete or move it).

### 2. Parse the application into a CPG

Use Joern's `joern-parse` (see [Installation](#joern)) to build the application's Code Property Graph:

```bash
~/bin/joern/joern-cli/joern-parse /path/to/application --language php -o /path/to/cpg.bin
```

Without `-o`, the CPG is written to `cpg.bin` in the current directory.

### 3. Run TaintRadar

Pass the path to the `cpg.bin` from step 2 (or to the directory that contains it):

```bash
./taint-radar /path/to/cpg.bin
```

If you leave out the path, TaintRadar asks for it. It then applies its augmentations and runs vulnerability detection. TaintRadar works on a copy of the CPG in `workspace/`. Running it again on the same CPG file replaces that copy and the previous outputs.

**Choosing a module.** By default, TaintRadar runs all its modules. To run only part of the approach (for an ablation study, for example), pass `--module` (or `-m`) with one of the modules below. Each module builds on the ones above it:

| `--module` | Approach | What runs |
| --- | --- | --- |
| `vanilla` | Vanilla Joern | Joern's own data flow engine (`reachableByFlows`), with no TaintRadar augmentation |
| `dataflow` | +Dataflow | TaintRadar's data flow traversal. Every sink counts as unsanitized. |
| `sanitization` | +Sanitization | Adds the sanitization tags, so sanitized sinks and paths are filtered out |
| `database` (default) | +Database | Adds the database schema and query tags, and paths that go through the database |

```bash
./taint-radar /path/to/cpg.bin --module sanitization
```

**Outputs:**

| File | Contents |
| --- | --- |
| `output/paths/<name>-output.json` | Detected vulnerable paths |
| `output/stats.csv` | One row appended per run: the approach, language and application, then the CPG size, number of sources, sinks and paths per vulnerability, execution time, … A header row is written when the file is created. |
| `output/db-schemas/<app-root-dir>.csv` | Database queries found in the application, with their parsed tables and columns and whether they are safe (`database` module only) |

`<name>` is derived from the application's root directory: everything from the first `.` is dropped, only letters are kept, and the result is lowercased. For example, `my_app-2.0` becomes `myapp`, and `tailor` stays `tailor`.

## Reproducing the paper's results

Complete the Python environment setup in [Installation](#installation) before running these steps.

### Generate the whitelist of safe PHP functions

TaintRadar's `PHPConstants.scala` configuration includes functions whose output is guaranteed to be safe. We find type-safe and hash functions by parsing the PHP function stubs.

1. Clone JetBrains' PHP stubs into the **parent** directory of this repository (the script looks for them in `../phpstorm-stubs/`):

   ```bash
   git clone https://github.com/JetBrains/phpstorm-stubs.git ../phpstorm-stubs
   ```

2. Run the extraction script:

   ```bash
   python3 utils/get_safe_php_functions.py
   ```

   The type-safe and hash functions are written to `output/safe_functions.json`.

We use these functions together with the ones from the [NAVEX repository](https://github.com/aalhuz/navex.git) in `PHPConstants.scala`. We did not tune the safe functions for any specific application.

### Color an AST by sanitization

This step shows how the sanitization augmentation labels AST nodes for XSS. It uses the two example scripts from the paper, which differ only in whether the user input is sanitized:

| [`sanitized_echo.php`](php-tests/sanitization/sanitized_echo.php) | [`unsanitized_echo.php`](php-tests/sanitization/unsanitized_echo.php) |
| --- | --- |
| `echo("Hello ". htmlentities($name));` | `echo("Hello ". $name);` |

For each script, the commands below:

1. Parse the script into a CPG with `joern-parse`.
2. In the TaintRadar REPL, export the AST of the `<global>` method as a dot graph, add sanitization tags to every node, and write each node's `SAN_XSS` label to `output/graph/tags.txt`.
3. Color the dot graph by those labels (`utils/color_graph.py`) and render it to `output/graph/<script>.png`.

Run them from the repository root, with the Python environment activated:

```bash
JOERN_CLI=~/bin/joern/joern-cli   # see Installation
mkdir -p output/graph

for APP in sanitized_echo unsanitized_echo; do
  "$JOERN_CLI/joern-parse" "php-tests/sanitization/$APP.php" --language php -o "output/graph/$APP.bin"

  ./repl --nocolors <<EOF
importCpg("output/graph/$APP.bin", "$APP.bin")
cpg.method("<global>").dotAst.l #> "output/graph/ast_unsan.dot"
cpg.utils.augmentWithSanTag()
cpg.astNode.map(x => x.id.toString + "," + x.tag.filter(_.name == "SAN_XSS").headOption.value.headOption.getOrElse("FALSE").toString).l #> "output/graph/tags.txt"
exit
EOF

  python3 utils/color_graph.py
  dot -Tpng output/graph/ast_unsan_colored.dot -o "output/graph/$APP.png"
done
```

Green nodes are labeled sanitized for XSS, and red nodes are labeled unsanitized. In `sanitized_echo`, the `htmlentities` call and the nodes above it (the concatenation and `echo`) are sanitized. In `unsanitized_echo`, the same nodes stay unsanitized.

**`sanitized_echo.php`**

![Sanitization-colored AST of sanitized_echo.php](docs/images/sanitized_echo.png)

**`unsanitized_echo.php`**

![Sanitization-colored AST of unsanitized_echo.php](docs/images/unsanitized_echo.png)

### Match vulnerable paths with public CVEs

This script queries the NVD for CVEs about an application and matches them against the paths TaintRadar found:

```bash
python3 utils/cve_matching.py <app_name> [--app-version VERSION] [--app-dir DIR] [--use-cached-cve]
```

The script uses `<app_name>` in three ways:

- **NVD search:** it is the keyword used to search the NVD. This needs an internet connection.
- **Paths file:** it reads `output/paths/<app_name>-output.json`, so `<app_name>` must be the `<name>` from [step 3](#3-run-taintradar).
- **Source code:** it reads the application's source from `applications/<app_name>/`. If the source is somewhere else, pass `--app-dir`. If the directory is missing, every CVE is filtered out and the script reports 0 CVEs without an error.

For example, for an application in `applications/my_app-2.0`:

```bash
python3 utils/cve_matching.py myapp --app-dir applications/my_app-2.0
```

Results are written to `output/cve/`. `--use-cached-cve` reuses the CVEs saved by a previous run instead of querying the NVD again. Run `python3 utils/cve_matching.py --help` to see all options.
