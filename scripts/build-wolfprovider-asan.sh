#!/bin/bash
# This script builds wolfProvider with Address Sanitizer (ASAN) enabled
# for detecting memory errors and undefined behavior

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_FILE=${SCRIPT_DIR}/build-asan.log
source ${SCRIPT_DIR}/utils-wolfprovider-asan.sh

show_help() {
  echo "Usage: $0"
  echo ""
  echo "This script builds wolfProvider with Address Sanitizer (ASAN) enabled"
  echo ""
  echo "Environment Variables:"
  echo "  OPENSSL_TAG          OpenSSL tag to use (e.g., openssl-3.2.0)"
  echo "  WOLFSSL_TAG          wolfSSL tag to use (e.g., v5.7.4-stable)"
  echo "  WOLFSSL_FIPS_BUNDLE  Directory containing the wolfSSL FIPS bundle to use instead of cloning from GitHub"
  echo "  WOLFSSL_FIPS_VERSION Version of wolfSSL FIPS bundle (v5, v6, ready), used as an argument for --enable-fips when configuring wolfSSL"
  echo ""
  echo "ASAN Options:"
  echo "  ASAN_OPTIONS         Additional ASAN runtime options (default: detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1)"
  echo ""
}

if [[ "$1" == "--help" || "$1" == "-h" || "$1" == "-help" ]]; then
  show_help
  exit 0
fi

echo "Building wolfProvider with Address Sanitizer (ASAN)"
echo "Using openssl: $OPENSSL_TAG, wolfssl: $WOLFSSL_TAG"

# Initialize wolfProvider with ASAN
init_wolfprov_asan

exit $?
