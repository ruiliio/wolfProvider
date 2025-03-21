#!/bin/sh
# Custom test log capture script
# Used to capture test output to the top-level test-suite.log file

# Find the top-level directory by looking for configure.ac
find_top_dir() {
  local dir="$PWD"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/configure.ac" ]; then
      echo "$dir"
      return 0
    fi
    dir=$(dirname "$dir")
  done
  echo "$PWD"  # Fallback to current directory
}

# Get the top-level directory
TOP_DIR=$(find_top_dir)
TOP_LOG="$TOP_DIR/test-suite.log"

# Run the test and capture output to the top-level log
"$@" 2>&1 | tee -a "$TOP_LOG"
exit ${PIPESTATUS[0]}
