#!/bin/bash

# ========== Usage Check ==========
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <cpg_bin_dir> <joern_path> [log_file]"
  exit 1
fi

# ========== Read Arguments ==========
CPG_BIN_DIR="$1"
JOERN_PATH="$2"
LOG_FILE="${3:-$JOERN_PATH/joern_analysis.log}"  # Use 3rd argument or default

# ========== Ensure Joern is executable ==========
cd "$JOERN_PATH" || { echo "Failed to access Joern directory: $JOERN_PATH"; exit 1; }

# ========== Loop over .bin files ==========
for CPG_BINARY_PATH in "$CPG_BIN_DIR"/*.bin; do
  if [[ -f "$CPG_BINARY_PATH" ]]; then
    APP_NAME=$(basename "$CPG_BINARY_PATH" .bin)

    echo " Processing CPG file: $CPG_BINARY_PATH"
    
    # Run Joern REPL
    ./repl <<EOF
importCpg("$CPG_BINARY_PATH")
val n=NavexMain(cpg, false)
n.outputPaths(false)
exit
EOF

    echo " Completed processing $CPG_BINARY_PATH"

  else
    echo "  No .bin files found in $CPG_BIN_DIR"
  fi
done | tee -a "$LOG_FILE"
