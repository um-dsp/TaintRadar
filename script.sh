#!/bin/bash

# Usage info
if [[ "$#" -ne 3 ]]; then
  echo "Usage: $0 <cpg_bin_dir> <joern_path> <output_dir>"
  echo "Example: ./analyze_cpg.sh /path/to/cpgs /path/to/joern /path/to/output"
  exit 1
fi

# Read arguments
CPG_BIN_DIR="$1"
JOERN_PATH="$2"
OUTPUT_DIR="$3"
LOG_FILE="$JOERN_PATH/joern_analysis.log"

# Ensure Joern is executable
cd "$JOERN_PATH" || { echo "Failed to access Joern directory: $JOERN_PATH"; exit 1; }

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Loop over each .bin file in the directory
for CPG_BINARY_PATH in "$CPG_BIN_DIR"/*.bin; do
  if [[ -f "$CPG_BINARY_PATH" ]]; then
    APP_NAME=$(basename "$CPG_BINARY_PATH" .bin)
    JSON_OUTPUT="$OUTPUT_DIR/${APP_NAME}-output.json"

    echo "Processing CPG file: $CPG_BINARY_PATH"
    
    # Run Joern REPL and execute commands
    ./repl <<EOF
importCpg("$CPG_BINARY_PATH")
val n=NavexMain(cpg, false)
n.outputPaths(false)
exit
EOF

    echo "Completed processing $CPG_BINARY_PATH. JSON output saved at: $JSON_OUTPUT"
  else
    echo "No .bin files found in $CPG_BIN_DIR"
  fi
done | tee -a "$LOG_FILE"

