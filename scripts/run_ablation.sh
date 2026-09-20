#!/usr/bin/env bash
#
# Run the ablation study: every TaintRadar module over the named applications.
#
# Each application is parsed once and its CPG reused across all four modules, so the
# cost is one parse plus four analyses per application rather than four parses.
#
# Usage:
#   scripts/run_ablation.sh                  # the default six applications
#   scripts/run_ablation.sh tailor codeastro # only the named ones
#
# Environment:
#   MODULES   space-separated module list (default: vanilla dataflow sanitization database)
#   APPEND    1 to add to an existing ablation table instead of starting a new one, and
#             to keep the CPGs afterwards. Use it to resume a run that was interrupted:
#               APPEND=1 MODULES=dataflow scripts/run_ablation.sh collabtive
#   VERBOSE   1, or the -v/--verbose flag, to stream TaintRadar's own output as it
#             runs instead of only writing it to output/batch-logs/
#   plus everything run_all_applications.sh accepts (JAVA_OPTS, RUN_TIMEOUT, ...)
#
# Results:
#   output/stats_ablation_study.csv              one row per application per module
#   output/paths/ablation/<name>-<module>.json   paths, kept per module
#
# TaintRadar always appends to output/stats.csv (the path is hardcoded in NavexMain),
# so this script sets that file aside for the duration of the run, collects the
# ablation's rows into stats_ablation_study.csv, and puts the original back afterwards.
# An unrelated output/stats.csv is therefore left exactly as it was found.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

MODULES="${MODULES:-vanilla dataflow sanitization database}"

ABLATION_STATS="${ABLATION_STATS:-output/stats_ablation_study.csv}"
LIVE_STATS=output/stats.csv
APPEND="${APPEND:-0}"
VERBOSE="${VERBOSE:-0}"

DEFAULT_APPS=(
    codeastro                   #  25 php
    advocateoffice              #  73
    tailor                      #  82
    ecommercefruitsbazarmaster  #  93
    engineersonlineportal       # 284
    collabtive                  # 891
)

APPS=()
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        -*)           echo "[error] unknown option: $arg" >&2; exit 1 ;;
        *)            APPS+=("$arg") ;;
    esac
done
if [[ ${#APPS[@]} -eq 0 ]]; then APPS=("${DEFAULT_APPS[@]}"); fi

# run_all_applications.sh reads this from the environment.
export VERBOSE

# Parse once, reuse across modules.
export KEEP_CPG=1

# Validate before touching anything: a typo must not archive a good stats.csv.
for app in "${APPS[@]}"; do
    if [[ ! -d "applications/$app" ]]; then
        echo "[error] no such application: applications/$app" >&2
        exit 1
    fi
done

ABLATION_DIR=output/paths/ablation
mkdir -p "$ABLATION_DIR" output/cpgs

# A fresh run keeps any previous ablation table aside rather than silently growing it.
# APPEND=1 instead adds to it, which is what resuming an interrupted run needs.
if [[ "$APPEND" == "1" ]]; then
    if [[ -s "$ABLATION_STATS" ]]; then
        echo "Appending to existing $ABLATION_STATS ($(($(wc -l < "$ABLATION_STATS") - 1)) rows)"
    fi
elif [[ -s "$ABLATION_STATS" ]]; then
    backup="$ABLATION_STATS.$(date '+%Y%m%d-%H%M%S').bak"
    mv "$ABLATION_STATS" "$backup"
    echo "Archived previous ablation table to $backup"
fi

# TaintRadar appends to output/stats.csv unconditionally. Set an existing one aside so
# this run collects only its own rows, and restore it when the run ends -- including on
# interrupt, so an aborted ablation never leaves the original lost or half-merged.
STASHED_STATS=""
if [[ -f "$LIVE_STATS" ]]; then
    STASHED_STATS="output/.stats.csv.ablation-stash.$$"
    mv "$LIVE_STATS" "$STASHED_STATS"
fi

# Runs both explicitly at the end and from the EXIT trap, so it must be idempotent:
# a second pass would otherwise move the just-restored original onto the results.
STATS_FINALIZED=0
finalize_stats() {
    if [[ $STATS_FINALIZED -eq 1 ]]; then return 0; fi
    STATS_FINALIZED=1
    if [[ -f "$LIVE_STATS" ]]; then
        if [[ -s "$ABLATION_STATS" ]]; then
            # Only reachable under APPEND=1: a fresh run has already moved any table
            # aside. Drop this run's header row so the combined file keeps just one.
            tail -n +2 "$LIVE_STATS" >> "$ABLATION_STATS"
            rm -f "$LIVE_STATS"
        else
            mv "$LIVE_STATS" "$ABLATION_STATS"
        fi
    fi
    if [[ -n "$STASHED_STATS" && -f "$STASHED_STATS" ]]; then
        mv "$STASHED_STATS" "$LIVE_STATS"
    fi
}
trap finalize_stats EXIT

# Ctrl-C reaches this script, but the analysis runs several levels down
# (run_all_applications.sh -> timeout -> taint-radar -> java). If those are left behind
# they keep a 12G-heap JVM alive with no parent, which is what happened on 2026-09-20.
# Walk the tree and stop every descendant before finalizing.
kill_descendants() {
    local pid=$1 child
    for child in $(pgrep -P "$pid" 2>/dev/null); do
        kill_descendants "$child"
        kill -TERM "$child" 2>/dev/null
    done
}

interrupted() {
    trap '' INT TERM
    echo >&2
    echo "Interrupted - stopping analysis processes..." >&2
    kill_descendants $$
    sleep 2
    kill_descendants $$
    finalize_stats
    echo "Stopped. Results so far are in $ABLATION_STATS" >&2
    echo "CPGs kept in output/cpgs/ - resume with APPEND=1." >&2
    exit 130
}
trap interrupted INT TERM

# Same derivation TaintRadar uses for the output filename.
output_name_for() {
    printf '%s' "${1%%.*}" | tr -cd '[:alpha:]' | tr '[:upper:]' '[:lower:]'
}

echo "Ablation over ${#APPS[@]} applications x $(echo "$MODULES" | wc -w | tr -d ' ') modules"
echo "  applications : ${APPS[*]}"
echo "  modules      : $MODULES"
echo

for module in $MODULES; do
    echo "############################################################"
    echo "# module: $module"
    echo "############################################################"

    MODULE="$module" scripts/run_all_applications.sh "${APPS[@]}"

    # outputPaths overwrites output/paths/<name>-output.json every run, so keep a
    # per-module copy before the next module overwrites it.
    for app in "${APPS[@]}"; do
        name="$(output_name_for "$app")"
        src="output/paths/$name-output.json"
        if [[ -f "$src" ]]; then
            cp "$src" "$ABLATION_DIR/$name-$module.json"
        fi
    done
done

# The CPGs were only retained to be shared between modules. While resuming, later
# commands still need them, so keep them and let the last one clean up.
if [[ "$APPEND" == "1" ]]; then
    echo "APPEND=1: keeping output/cpgs/ ($(du -sh output/cpgs 2>/dev/null | cut -f1)) for the next resume step."
    echo "Remove them with 'rm -f output/cpgs/*.bin' once the ablation is complete."
else
    rm -f output/cpgs/*.bin
fi

# Move the collected rows into place now so the summary below can read them; the EXIT
# trap then only has the original stats.csv left to restore.
finalize_stats

echo
echo "Ablation complete."
echo "  stats  : $ABLATION_STATS"
echo "  paths  : $ABLATION_DIR/"
if [[ -s "$ABLATION_STATS" ]]; then
    echo
    awk -F, 'NR==1{next} {print "  "$3"  "$1}' "$ABLATION_STATS" | sort | uniq -c
fi
