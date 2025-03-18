#!/bin/bash
# Script to reproduce the RSA X931 signature verification issue

# Source the common configuration file
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "$SCRIPT_DIR/common/config.sh"

# Default settings
ITERATIONS=100
DEBUG=0
SYSTEM_OPENSSL=0
OUTPUT_DIR="results"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --iterations|-i)
            ITERATIONS="$2"
            shift
            shift
            ;;
        --debug|-d)
            DEBUG=1
            shift
            ;;
        --system-openssl|-s)
            SYSTEM_OPENSSL=1
            shift
            ;;
        --output|-o)
            OUTPUT_DIR="$2"
            shift
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --iterations, -i N    Run N iterations (default: 100)"
            echo "  --debug, -d           Enable debug mode (WOLFPROV_DEBUG=1)"
            echo "  --system-openssl, -s  Use system OpenSSL instead of local build"
            echo "  --output, -o DIR      Output directory for results (default: results)"
            echo "  --help, -h            Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Set up environment
if [ $SYSTEM_OPENSSL -eq 1 ]; then
    echo "Using system OpenSSL"
    export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
    export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/engines-3
else
    echo "Using local OpenSSL build"
    # Use the environment setup function from the common configuration
    setup_environment
    # Add wolfSSL and OpenSSL libraries to LD_LIBRARY_PATH
    export LD_LIBRARY_PATH="$WOLFPROV_DIR/wolfssl-install/lib:$WOLFPROV_DIR/openssl-install/lib64:$LD_LIBRARY_PATH"
fi

# Set debug mode if requested
if [ $DEBUG -eq 1 ]; then
    echo "Debug mode enabled"
    export WOLFPROV_DEBUG=1
fi

# Compile the test program
echo "Compiling test program..."
gcc -o rsa_x931_wolf_openssl_test rsa_x931_wolf_openssl_test.c -I"$WOLFPROV_DIR/include" -I"$WOLFPROV_DIR/openssl-install/include" -L"$WOLFPROV_DIR/openssl-install/lib64" -L"$WOLFPROV_INSTALL_DIR/lib" -lcrypto -g -O1

# Run the test
echo "Running $ITERATIONS iterations..."
./rsa_x931_wolf_openssl_test $ITERATIONS 2>&1 | tee "$OUTPUT_DIR/run_$(date +%Y%m%d_%H%M%S).log"

# Analyze results
echo "Test completed. Results saved to $OUTPUT_DIR/"
