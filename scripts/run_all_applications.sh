#!/usr/bin/env bash
#
# Run TaintRadar over every PHP application in applications/.
#
# For each application this script:
#   1. extracts its database schema to output/db-schemas/<app>-database.csv
#   2. builds a CPG with joern-parse
#   3. runs ./taint-radar on that CPG
#   4. deletes the CPG and its workspace copy
#
# Results land in output/paths/<name>-output.json and output/stats.csv (one row per
# application). A per-application log and a machine-readable summary are written to
# output/batch-logs/.
#
# Usage:
#   scripts/run_all_applications.sh              # all applications, small to large
#   scripts/run_all_applications.sh tailor keerti # only the named applications
#   scripts/run_all_applications.sh -v            # stream TaintRadar's own output
#
# -v/--verbose (or VERBOSE=1) echoes joern-parse's and TaintRadar's output to the
# terminal as it is produced, so a long run shows progress instead of going quiet for
# minutes. The per-application log files are written either way, and stay unprefixed.
#
# Environment overrides: see the Configuration block below.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CPG_DIR="${CPG_DIR:-output/cpgs}"
LOG_DIR="${LOG_DIR:-output/batch-logs}"
SCHEMA_DIR="${SCHEMA_DIR:-output/db-schemas}"
MODULE="${MODULE:-database}"

# TaintRadar sets no -Xmx of its own; give the JVM a usable heap for the big applications.
export JAVA_OPTS="${JAVA_OPTS:--Xmx12G}"

PARSE_TIMEOUT="${PARSE_TIMEOUT:-3600}"
RUN_TIMEOUT="${RUN_TIMEOUT:-3600}"
MIN_FREE_GB="${MIN_FREE_GB:-5}"
KEEP_CPG="${KEEP_CPG:-0}"          # 1 keeps each CPG, and reuses one that is
                                   # already present instead of re-parsing.
                                   # Set this for an ablation: the four modules
                                   # then share a single parse per application.
VERBOSE="${VERBOSE:-0}"            # 1 streams joern-parse and TaintRadar output

# collabtive ships no .sql; its schema comes from the NAVEX corpus outside this repo.
# If the file is absent the application simply runs on the empty schema.
COLLABTIVE_SQL="${COLLABTIVE_SQL:-$REPO_ROOT/../navex_tests/php/collabtive-31/pgsql.sql}"

# ---------------------------------------------------------------------------
# Applications, ordered by PHP file count so that failures on the two large
# applications cost nothing already earned.
# ---------------------------------------------------------------------------

ALL_APPS=(
    keerti                           #    8 php
    visitormanagementsystem          #   15
    dailyexpensetrackerproject       #   22
    codeastro                        #   25
    dairyfarmshop                    #   26
    loansystem                       #   34
    covid19tms                       #   35
    bloodbanksystem                  #   65
    advocateoffice                   #   73
    tailor                           #   82
    hospitalmanagementsystemproject  #   85
    ecommercefruitsbazarmaster       #   93
    automatedenrollment              #  112
    fantasticblog                    #  140
    engineersonlineportal            #  284
    collabtive                       #  891
    clansphere                       #  982
    seopanel                         # 2015
)

# Per-application SQL schema source, relative to applications/<app>/.
# Transcribed from navex_utils/src/db-constraint.py (the FIXX USENIX 2025 paths).
# collabtive is absent there and is handled separately via $COLLABTIVE_SQL.
sql_source_for() {
    case "$1" in
        advocateoffice)                  echo "db/kortex_lite.sql" ;;
        automatedenrollment)             echo "db/bilal.sql" ;;
        bloodbanksystem)                 echo "Database/bloodbank.sql" ;;
        clansphere)                      echo "updates/all_updates.sql" ;;
        codeastro)                       echo "DATABASE FILE/membershiphp.sql" ;;
        covid19tms)                      echo "SQL File/covidtmsdb.sql" ;;
        dailyexpensetrackerproject)      echo "SQL File/detsdb.sql" ;;
        dairyfarmshop)                   echo "SQL File/dfsms.sql" ;;
        ecommercefruitsbazarmaster)      echo "ecommerce.sql" ;;
        engineersonlineportal)           echo "db/capstone.sql" ;;
        fantasticblog)                   echo "databasefile/blog_admin_db.sql" ;;
        hospitalmanagementsystemproject) echo "SQL File/hms.sql" ;;
        keerti)                          echo "login.sql" ;;
        loansystem)                      echo "Database/loan_system96.sql" ;;
        seopanel)                        echo "install/data/seopanel_all.sql" ;;
        tailor)                          echo "tailor.sql" ;;
        visitormanagementsystem)         echo "db_vms.sql" ;;
        *)                               echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '%s [warn] %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }
die()  { printf '[error] %s\n' "$*" >&2; exit 1; }

rule() { printf '%s\n' "------------------------------------------------------------"; }

free_gb() { df -g . | awk 'NR==2 {print $4}'; }

# TaintRadar derives the output name from the application's root directory:
# everything from the first '.' is dropped, only letters are kept, lowercased.
output_name_for() {
    printf '%s' "${1%%.*}" | tr -cd '[:alpha:]' | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

# joern-parse: honour $JOERN_PARSE, else the documented install, else the local build.
if [[ -n "${JOERN_PARSE:-}" ]]; then
    [[ -x "$JOERN_PARSE" ]] || die "JOERN_PARSE is set but not executable: $JOERN_PARSE"
else
    for candidate in \
        "$HOME/bin/joern/joern-cli/joern-parse" \
        "$REPO_ROOT/../joern/joern-cli/target/universal/stage/bin/joern-parse"
    do
        if [[ -x "$candidate" ]]; then JOERN_PARSE="$candidate"; break; fi
    done
fi
[[ -n "${JOERN_PARSE:-}" ]] || die "joern-parse not found. Install Joern (see README) or set JOERN_PARSE."

[[ -x ./taint-radar ]] || die "./taint-radar not found. Run 'sbt stage' first."

# GNU coreutils' timeout: 'timeout' on Linux, either name on macOS with Homebrew.
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN=timeout
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN=gtimeout
else die "timeout/gtimeout not found. On macOS: brew install coreutils"
fi

# Pick the repo's own virtualenv if it exists; 'python3' on PATH may be another project's.
if [[ -x .venv/bin/python3 ]]; then PYTHON=.venv/bin/python3; else PYTHON=python3; fi

mkdir -p "$CPG_DIR" "$LOG_DIR" "$SCHEMA_DIR" output/paths

# The empty schema is DBConstraint's fallback for applications without one.
[[ -f "$SCHEMA_DIR/empty-database.csv" ]] || : > "$SCHEMA_DIR/empty-database.csv"

APPS=()
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        -*)           die "unknown option: $arg" ;;
        *)            APPS+=("$arg") ;;
    esac
done

if [[ ${#APPS[@]} -eq 0 ]]; then
    APPS=("${ALL_APPS[@]}")
    FULL_RUN=1
else
    FULL_RUN=0
fi

SUMMARY="$LOG_DIR/summary.csv"

# stats.csv and summary.csv accumulate one row per run. A full batch starts a clean
# table; naming individual applications (a retry of the ones that failed) appends to
# what the batch already collected instead of discarding it.
if [[ $FULL_RUN -eq 1 ]]; then
    if [[ -s output/stats.csv ]]; then
        stats_backup="output/stats.csv.$(date '+%Y%m%d-%H%M%S').bak"
        mv output/stats.csv "$stats_backup"
        log "Archived previous stats.csv to $stats_backup"
    fi
    echo "application,status,parse_seconds,analysis_seconds" > "$SUMMARY"
elif [[ ! -s "$SUMMARY" ]]; then
    echo "application,status,parse_seconds,analysis_seconds" > "$SUMMARY"
fi

rule
log "TaintRadar batch run"
log "  applications : ${#APPS[@]}"
log "  module       : $MODULE"
log "  joern-parse  : $JOERN_PARSE"
log "  python       : $PYTHON"
log "  JAVA_OPTS    : $JAVA_OPTS"
log "  free disk    : $(free_gb) GB"
java -version 2>&1 | head -1 | sed 's/^/           java : /'
rule

# ---------------------------------------------------------------------------
# Per-application pipeline
# ---------------------------------------------------------------------------

ok_count=0
fail_count=0

for app in "${APPS[@]}"; do
    app_dir="applications/$app"
    cpg="$CPG_DIR/$app.bin"
    parse_log="$LOG_DIR/$app.parse.log"
    run_log="$LOG_DIR/$app.analysis.log"
    parse_secs=""
    run_secs=""

    rule
    log "[$app] starting"

    if [[ ! -d "$app_dir" ]]; then
        warn "[$app] no such application directory: $app_dir — skipping"
        echo "$app,missing,," >> "$SUMMARY"
        fail_count=$((fail_count + 1))
        continue
    fi

    if [[ "$(free_gb)" -lt "$MIN_FREE_GB" ]]; then
        warn "[$app] only $(free_gb) GB free (need $MIN_FREE_GB) — skipping"
        echo "$app,skipped_disk,," >> "$SUMMARY"
        fail_count=$((fail_count + 1))
        continue
    fi

    # --- 1. schema ---------------------------------------------------------
    # DBConstraint looks the schema up by filename: <app root dir>-database.csv.
    schema_csv="$SCHEMA_DIR/$app-database.csv"
    if [[ -s "$schema_csv" ]]; then
        log "[$app] schema already extracted, reusing $schema_csv"
    else
        if [[ "$app" == "collabtive" ]]; then
            sql_path="$COLLABTIVE_SQL"
        else
            rel_sql="$(sql_source_for "$app")"
            sql_path="${rel_sql:+$app_dir/$rel_sql}"
        fi

        if [[ -z "$sql_path" ]]; then
            warn "[$app] no SQL source mapped — running on the empty schema"
        elif [[ ! -f "$sql_path" ]]; then
            warn "[$app] SQL source not found: $sql_path — running on the empty schema"
        else
            log "[$app] extracting schema from $sql_path"
            if ! "$PYTHON" utils/extract_schema.py "$sql_path" \
                    --out-dir "$SCHEMA_DIR" --out-file "$app-database.csv"
            then
                warn "[$app] schema extraction failed — running on the empty schema"
            elif [[ ! -s "$schema_csv" ]]; then
                warn "[$app] schema extraction produced no rows — running on the empty schema"
            fi
        fi
    fi

    # --- 2. parse ----------------------------------------------------------
    # Every application gets a distinct CPG filename: Main.scala names the workspace
    # project after the file, so a shared name would clobber the previous run's copy.
    if [[ "$KEEP_CPG" == "1" && -s "$cpg" ]]; then
        log "[$app] reusing existing CPG $cpg ($(du -h "$cpg" | cut -f1))"
        parse_secs=0
        parse_status=0
    else
        log "[$app] parsing into $cpg (timeout ${PARSE_TIMEOUT}s)"
        parse_start=$SECONDS
        if [[ "$VERBOSE" == "1" ]]; then
            # tee writes the log, sed prefixes only what reaches the terminal, so the
            # log file stays identical to the non-verbose one. PIPESTATUS[0] is the
            # parser's status; $? would be sed's.
            "$TIMEOUT_BIN" "$PARSE_TIMEOUT" "$JOERN_PARSE" "$app_dir" --language php -o "$cpg" \
                2>&1 </dev/null | tee "$parse_log" | sed "s/^/    [$app parse] /"
            parse_status=${PIPESTATUS[0]}
        else
            "$TIMEOUT_BIN" "$PARSE_TIMEOUT" "$JOERN_PARSE" "$app_dir" --language php -o "$cpg" \
                > "$parse_log" 2>&1 </dev/null
            parse_status=$?
        fi
        parse_secs=$((SECONDS - parse_start))
    fi

    if [[ $parse_status -ne 0 ]]; then
        if [[ $parse_status -eq 124 ]]; then
            warn "[$app] joern-parse timed out after ${PARSE_TIMEOUT}s (see $parse_log)"
            echo "$app,parse_timeout,$parse_secs," >> "$SUMMARY"
        else
            warn "[$app] joern-parse failed with status $parse_status (see $parse_log)"
            echo "$app,parse_failed,$parse_secs," >> "$SUMMARY"
        fi
        rm -f "$cpg"
        fail_count=$((fail_count + 1))
        continue
    fi
    if [[ $parse_secs -gt 0 ]]; then log "[$app] parsed in ${parse_secs}s ($(du -h "$cpg" | cut -f1))"; fi

    # --- 3. analyse --------------------------------------------------------
    # stdin is closed: Main.scala prompts on stdin when given no path, which would
    # otherwise hang an unattended batch.
    log "[$app] running TaintRadar --module $MODULE (timeout ${RUN_TIMEOUT}s)"
    run_start=$SECONDS
    if [[ "$VERBOSE" == "1" ]]; then
        "$TIMEOUT_BIN" "$RUN_TIMEOUT" ./taint-radar "$cpg" --module "$MODULE" \
            2>&1 </dev/null | tee "$run_log" | sed "s/^/    [$app $MODULE] /"
        run_status=${PIPESTATUS[0]}
    else
        "$TIMEOUT_BIN" "$RUN_TIMEOUT" ./taint-radar "$cpg" --module "$MODULE" \
            > "$run_log" 2>&1 </dev/null
        run_status=$?
    fi
    run_secs=$((SECONDS - run_start))

    # --- 4. clean ----------------------------------------------------------
    if [[ "$KEEP_CPG" != "1" ]]; then rm -f "$cpg"; fi
    rm -rf "workspace/$app.bin"

    # --- 5. record ---------------------------------------------------------
    if [[ $run_status -eq 0 ]]; then
        if grep -q "No database schema found for $app" "$run_log"; then
            warn "[$app] TaintRadar fell back to the empty schema — check $schema_csv"
        fi
        log "[$app] done in ${run_secs}s -> output/paths/$(output_name_for "$app")-output.json"
        echo "$app,ok,$parse_secs,$run_secs" >> "$SUMMARY"
        ok_count=$((ok_count + 1))
    elif [[ $run_status -eq 124 ]]; then
        warn "[$app] TaintRadar timed out after ${RUN_TIMEOUT}s (see $run_log)"
        echo "$app,run_timeout,$parse_secs,$run_secs" >> "$SUMMARY"
        fail_count=$((fail_count + 1))
    else
        warn "[$app] TaintRadar failed with status $run_status (see $run_log)"
        echo "$app,run_failed,$parse_secs,$run_secs" >> "$SUMMARY"
        fail_count=$((fail_count + 1))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

rule
log "Finished: $ok_count succeeded, $fail_count failed"
log "  per-run stats : output/stats.csv"
log "  paths         : output/paths/"
log "  batch summary : $SUMMARY"
rule
column -s, -t "$SUMMARY" 2>/dev/null || cat "$SUMMARY"

[[ $fail_count -eq 0 ]]
