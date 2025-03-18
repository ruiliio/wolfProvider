#!/bin/bash
# Script to simulate the GitHub Actions environment for reproducing the issue

# Create a temporary directory for the test
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR" || exit 1

echo "Working in temporary directory: $TEMP_DIR"

# Clone wolfProvider
git clone https://github.com/wolfSSL/wolfProvider.git
cd wolfProvider || exit 1

# Set up environment similar to GitHub Actions
export GITHUB_ACTIONS=true
export GITHUB_WORKFLOW=CI
export GITHUB_REPOSITORY=wolfSSL/wolfProvider
export GITHUB_SHA=$(git rev-parse HEAD)

# Build wolfProvider with default settings (similar to GitHub Actions)
./autogen.sh
./configure
make

# Run the tests multiple times to catch intermittent failures
for i in {1..10}; do
    echo "=== Test run $i ==="
    if ! make check; then
        echo "Test failed on run $i"
        # Save the failure logs
        mkdir -p ~/repos/wolfProvider/test/reproduce/github_actions_env
        cp test/*.log ~/repos/wolfProvider/test/reproduce/github_actions_env/
        break
    fi
done

# Clean up
cd ~ || exit 1
rm -rf "$TEMP_DIR"

echo "Test completed. Check ~/repos/wolfProvider/test/reproduce/github_actions_env/ for failure logs."
