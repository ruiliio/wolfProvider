#!/bin/bash

# Script to reproduce the RSA X931 signature verification issue
# This script tries different environment configurations to trigger the issue

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFPROV_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Compile the test if it doesn't exist
if [ ! -f "$SCRIPT_DIR/rsa_x931_repro" ]; then
    echo "Compiling test case..."
    gcc -o "$SCRIPT_DIR/rsa_x931_repro" "$SCRIPT_DIR/rsa_x931_repro.c" \
        -I"$WOLFPROV_DIR/include" \
        -L"$WOLFPROV_DIR/wolfprov-install/lib" \
        -lwolfprov -lcrypto -lwolfssl \
        -Wl,-rpath,"$WOLFPROV_DIR/wolfprov-install/lib"
fi

# Function to run test with specific environment
run_test() {
    local config_name=$1
    local openssl_lib=$2
    local wolfssl_lib=$3
    local wolfprov_lib=$4
    local debug=$5
    local iterations=$6
    
    echo "=== Testing configuration: $config_name ==="
    echo "OpenSSL lib: $openssl_lib"
    echo "wolfSSL lib: $wolfssl_lib"
    echo "wolfProvider lib: $wolfprov_lib"
    echo "Debug: $debug"
    echo "Iterations: $iterations"
    
    export LD_LIBRARY_PATH="$wolfprov_lib:$wolfssl_lib:$openssl_lib:$LD_LIBRARY_PATH"
    export OPENSSL_MODULES="$wolfprov_lib"
    
    if [ "$debug" = "1" ]; then
        export WOLFPROV_DEBUG=1
    else
        unset WOLFPROV_DEBUG
    fi
    
    echo "Running test..."
    "$SCRIPT_DIR/rsa_x931_repro" $iterations
    local result=$?
    
    if [ $result -eq 0 ]; then
        echo "Test PASSED"
    else
        echo "Test FAILED with exit code $result"
    fi
    echo ""
    
    return $result
}

# Try different configurations to reproduce the issue
echo "Attempting to reproduce RSA X931 signature verification issue..."

# Configuration 1: System OpenSSL with local wolfSSL and wolfProvider
run_test "System OpenSSL" \
    "/lib/x86_64-linux-gnu" \
    "$WOLFPROV_DIR/wolfssl-install/lib" \
    "$WOLFPROV_DIR/wolfprov-install/lib" \
    "1" \
    "100"

# Configuration 2: Local OpenSSL with local wolfSSL and wolfProvider
run_test "Local OpenSSL" \
    "$WOLFPROV_DIR/openssl-install/lib64" \
    "$WOLFPROV_DIR/wolfssl-install/lib" \
    "$WOLFPROV_DIR/wolfprov-install/lib" \
    "1" \
    "100"

# Configuration 3: Local OpenSSL with local wolfSSL and wolfProvider (no debug)
run_test "No Debug" \
    "$WOLFPROV_DIR/openssl-install/lib64" \
    "$WOLFPROV_DIR/wolfssl-install/lib" \
    "$WOLFPROV_DIR/wolfprov-install/lib" \
    "0" \
    "100"

# Configuration 4: High iteration count to increase chance of reproducing
run_test "High Iterations" \
    "$WOLFPROV_DIR/openssl-install/lib64" \
    "$WOLFPROV_DIR/wolfssl-install/lib" \
    "$WOLFPROV_DIR/wolfprov-install/lib" \
    "1" \
    "1000"

echo "Test script completed."
