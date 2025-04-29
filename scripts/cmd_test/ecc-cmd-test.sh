#!/bin/bash
# ecc-cmd-test.sh
# ECC key generation test for wolfProvider
#
# Copyright (C) 2006-2024 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd "${SCRIPT_DIR}/../.." &> /dev/null && pwd )"
UTILS_DIR="${REPO_ROOT}/scripts"
export LOG_FILE="${SCRIPT_DIR}/ecc-test.log"
touch "$LOG_FILE"

# Source wolfProvider utilities
source "${UTILS_DIR}/utils-general.sh"
source "${UTILS_DIR}/utils-openssl.sh"
source "${UTILS_DIR}/utils-wolfssl.sh"
source "${UTILS_DIR}/utils-wolfprovider.sh"

# Initialize the environment
init_wolfprov

# Fail flag
FAIL=0

# Verify wolfProvider is properly loaded
echo -e "\nVerifying wolfProvider configuration:"
if ! $OPENSSL_BIN list -providers | grep -q "libwolfprov"; then
    echo "[FAIL] wolfProvider not found in OpenSSL providers!"
    echo "Current provider list:"
    $OPENSSL_BIN list -providers
    exit 1
fi
echo "[PASS] wolfProvider is properly configured"

# Print environment for verification
echo "Environment variables:"
echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
echo "OPENSSL_BIN: ${OPENSSL_BIN}"

# Create test directories
mkdir -p ecc_outputs

# Create test data for signing
echo "This is test data for ECC signing and verification." > ecc_outputs/test_data.txt

# Array of ECC curves and providers to test
CURVES=("prime256v1" "secp384r1" "secp521r1")
PROVIDER_ARGS=("-provider-path $WOLFPROV_PATH -provider libwolfprov" "-provider default")

# Function to use default provider only
use_default_provider() {
    unset OPENSSL_MODULES
    unset OPENSSL_CONF
    echo "Switched to default provider"
}

# Function to use wolf provider only
use_wolf_provider() {
    export OPENSSL_MODULES=$WOLFPROV_PATH
    export OPENSSL_CONF=${WOLFPROV_CONFIG}
    echo "Switched to wolfProvider"
}

echo "=== Running ECC Key Generation Tests ==="

# Function to validate key
validate_key() {
    local curve=$1
    local key_file=${2:-"ecc_outputs/ecc_${curve}.pem"}
    local provider_args=$3
    echo -e "\n=== Validating ECC Key (${curve}) ==="
    
    # First check if file exists
    if [ ! -f "$key_file" ]; then
        echo "[FAIL] ECC key (${curve}) file does not exist"
        FAIL=1
        return 1
    fi
    
    # Then check if file is empty (has size 0)
    if [ ! -s "$key_file" ]; then
        echo "[FAIL] ECC key (${curve}) file is empty"
        FAIL=1
        return 1
    fi
    echo "[PASS] ECC key file exists and has content"
    
    # Try to extract public key
    local pub_key_file="ecc_outputs/ecc_${curve}_pub.pem"
    if $OPENSSL_BIN pkey -in "$key_file" -pubout -out "$pub_key_file" \
        ${provider_args} -passin pass: >/dev/null; then
        echo "[PASS] ECC Public key extraction successful"
    else
        echo "[FAIL] ECC Public key extraction failed"
        FAIL=1
        return 1
    fi
}

# Function to sign data with ECC
sign_ecc() {
    local key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Signing data with ECC..."
    $OPENSSL_BIN pkeyutl -sign -inkey "$key_file" \
        ${provider_args} -passin pass: \
        -in "$data_file" \
        -out "$sig_file"
    return $?
}

# Function to verify ECC signature
verify_ecc() {
    local pub_key_file=$1
    local data_file=$2
    local sig_file=$3
    local provider_args=$4
    
    echo "Verifying ECC signature..."
    $OPENSSL_BIN pkeyutl -verify -pubin -inkey "$pub_key_file" \
        ${provider_args} -passin pass: \
        -in "$data_file" \
        -sigfile "$sig_file"
    return $?
}

# Generic function to test sign/verify interoperability using pkeyutl
test_sign_verify_pkeyutl() {
    local curve=$1
    local provider_args=$2
    
    # Print the provider args
    if [ "$provider_args" = "-provider default" ]; then
        provider_name="default"
    else
        provider_name="wolfProvider"
    fi
    
    local key_file="ecc_outputs/ecc_${curve}.pem"
    local pub_key_file="ecc_outputs/ecc_${curve}_pub.pem"
    local data_file="ecc_outputs/test_data.txt"
    
    echo -e "\n=== Testing ECC (${curve}) Sign/Verify with pkeyutl Using ${provider_name} ==="
    
    # Test 1: Sign and verify with OpenSSL default
    use_default_provider
    echo "Test 1: Sign and verify with OpenSSL default"
    local default_sig_file="ecc_outputs/ecc_${curve}_default_sig.bin"
    if sign_ecc "$key_file" "$data_file" "$default_sig_file" "$provider_args"; then
        echo "[PASS] Signing with OpenSSL default successful"
        if verify_ecc "$pub_key_file" "$data_file" "$default_sig_file" "$provider_args"; then
            echo "[PASS] Default provider verify successful"
        else
            echo "[FAIL] Default provider verify failed"
            FAIL=1
        fi
    else
        echo "[FAIL] Default provider signing failed"
        FAIL=1
    fi

    # Test 2: Sign and verify with wolfProvider
    use_wolf_provider
    echo "Test 2: Sign and verify with wolfProvider"
    local wolf_sig_file="ecc_outputs/ecc_${curve}_wolf_sig.bin"
    if sign_ecc "$key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
        echo "[PASS] Signing with wolfProvider successful"
        if verify_ecc "$pub_key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
            echo "[PASS] wolfProvider sign/verify successful"
        else
            echo "[FAIL] wolfProvider verify failed"
            FAIL=1
        fi
    else
        echo "[FAIL] wolfProvider signing failed"
        FAIL=1
    fi
    
    # Test 3: Cross-provider verification (default sign, wolf verify)
    if [ $FAIL -eq 0 ]; then # only verify if previous tests passed
        use_wolf_provider
        echo "Test 3: Cross-provider verification (default sign, wolf verify)"
        if verify_ecc "$pub_key_file" "$data_file" "$default_sig_file" "$provider_args"; then
            echo "[PASS] wolfProvider can verify OpenSSL default signature"
        else
            echo "[FAIL] wolfProvider cannot verify OpenSSL default signature"
            FAIL=1
        fi
        
        # Test 4: Cross-provider verification (wolf sign, default verify)
        use_default_provider
        echo "Test 4: Cross-provider verification (wolf sign, default verify)"
        if verify_ecc "$pub_key_file" "$data_file" "$wolf_sig_file" "$provider_args"; then
            echo "[PASS] OpenSSL default can verify wolfProvider signature"
        else
            echo "[FAIL] OpenSSL default cannot verify wolfProvider signature"
            FAIL=1
        fi
    else 
        echo "[INFO] Cannot verify cross-provider signatures - no key available"
    fi
}

# Function to generate and test ECC keys
generate_and_test_key() {
    local curve=$1
    local provider_args=$2
    local output_file="ecc_outputs/ecc_${curve}.pem"
    
    echo -e "\n=== Testing ECC Key Generation (${curve}) with provider default ==="
    echo "Generating ECC key (${curve})..."
    
    if $OPENSSL_BIN ecparam -name $curve -genkey \
        ${provider_args} \
        -out "$output_file" 2>/dev/null; then
        echo "[PASS] ECC key generation successful"
    else
        echo "[FAIL] ECC key generation failed"
        FAIL=1
    fi

    # Verify the key was generated
    if [ -s "$output_file" ]; then
        echo "[PASS] ECC key generation successful"
    else
        echo "[FAIL] ECC key generation failed"
        FAIL=1
    fi
    
    # Validate key
    validate_key "$curve" "$output_file" "$provider_args"

    # Try to use the key with provider default
    echo -e "\n=== Testing ECC Key (${curve}) with provider default ==="
    echo "Checking if provider default can use the key..."
    
    # Try to use the key with wolfProvider (just check if it loads)
    if $OPENSSL_BIN pkey -in "$output_file" -check \
        ${provider_args} -passin pass: >/dev/null; then
        echo "[PASS] provider default can use ECC key (${curve})"
    else
        echo "[FAIL] provider default cannot use ECC key (${curve})"
        FAIL=1
    fi
}

# Test key generation for each curve and provider
for curve in "${CURVES[@]}"; do
    # Generate with default provider
    test_provider="-provider default"
    generate_and_test_key "$curve" "$test_provider"

    # Test sign/verify interoperability with appropriate function
    for test_provider in "${PROVIDER_ARGS[@]}"; do
        test_sign_verify_pkeyutl "$curve" "$test_provider"
    done
done

if [ $FAIL -eq 0 ]; then
    echo -e "\n=== All ECC key generation tests completed successfully ==="
    exit 0
else
    echo -e "\n=== ECC key generation tests completed with failures ==="
    exit 1
fi
