#!/bin/bash
# Master script to run all tests and generate comprehensive reports

# Source the common configuration file
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "$SCRIPT_DIR/common/config.sh"

# Create output directories
mkdir -p results/standard
mkdir -p results/debug
mkdir -p results/system_openssl
mkdir -p results/failures

# Run standard configuration tests
echo "=== Running standard configuration tests ==="
./reproduce_x931_issue.sh --iterations 100 --output results/standard

# Run debug configuration tests
echo "=== Running debug configuration tests ==="
./reproduce_x931_issue.sh --iterations 100 --debug --output results/debug

# Run system OpenSSL tests
echo "=== Running system OpenSSL tests ==="
./reproduce_x931_issue.sh --iterations 100 --system-openssl --output results/system_openssl

# Generate summary report
echo "=== Generating summary report ==="
{
    echo "# RSA X931 Signature Verification Test Results"
    echo ""
    echo "## Standard Configuration"
    echo "Failure rate: $(grep -c "Test failed" results/standard/*.log) / $(grep -c "Completed" results/standard/*.log | tail -1)"
    echo ""
    echo "## Debug Configuration"
    echo "Failure rate: $(grep -c "Test failed" results/debug/*.log) / $(grep -c "Completed" results/debug/*.log | tail -1)"
    echo ""
    echo "## System OpenSSL Configuration"
    echo "Failure rate: $(grep -c "Test failed" results/system_openssl/*.log) / $(grep -c "Completed" results/system_openssl/*.log | tail -1)"
    echo ""
    echo "## Error Patterns"
    echo "Most common error patterns:"
    grep -A 3 "Test failed" results/*/*.log | sort | uniq -c | sort -nr | head -10
} > results/summary_report.md

echo "All tests completed. Summary report generated at results/summary_report.md"
