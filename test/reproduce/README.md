# RSA X931 Signature Verification Issue - Reproduction

This directory contains test files and scripts to reproduce the intermittent RSA X931 signature verification issue in wolfProvider.

## Issue Description

The wolfProvider `make check` fails intermittently during GitHub Actions with an error in the RSA X931 signature verification test. The specific failure occurs when:

1. wolfProvider signs data using RSA X931 padding
2. OpenSSL attempts to verify the signature
3. The verification fails with "Signature not verified" error

## Key Findings

1. The issue occurs specifically when wolfProvider signs and OpenSSL verifies
2. The failure is intermittent, with a 1-7% failure rate depending on configuration
3. The error message is consistently "invalid header" and "padding check failed" in the final verification step
4. The issue occurs across different hash algorithms (SHA-1, SHA-256, SHA-384, SHA-512)
5. No memory-related issues were detected by Address Sanitizer (ASAN)
6. The failure occurs in the X931 padding implementation, particularly in the handling of the RSA key and signature format

## Test Files

1. `rsa_x931_asan_test.c` - Test case for RSA X931 signature verification with ASAN
2. `rsa_x931_asan_test2.c` - Modified test case with separate sign and verify steps
3. `rsa_x931_wolf_openssl_test.c` - Test case that uses wolfProvider for signing and OpenSSL for verification

## Reproduction Steps

1. Build wolfProvider with ASAN:
   ```bash
   cd ~/repos/wolfProvider
   ./scripts/build-wolfprovider-asan.sh
   ```

2. Run the test cases:
   ```bash
   cd ~/repos/wolfProvider/test/reproduce
   gcc -o rsa_x931_asan_test rsa_x931_asan_test.c -I../../include -I/path/to/openssl/include -L/path/to/openssl/lib -lcrypto -fsanitize=address -g -O1
   export LD_LIBRARY_PATH=/path/to/wolfprov/lib:/path/to/wolfssl/lib:/path/to/openssl/lib
   export OPENSSL_MODULES=/path/to/wolfprov/lib
   ./rsa_x931_asan_test 100
   ```

## Analysis

The X931 padding verification in wolfProvider's `wp_rsa_verify_x931` function has specific requirements for the signature format. The intermittent failures occur when there's a mismatch between how wolfProvider formats the signature and how OpenSSL expects it.

The key issue appears to be in the handling of the RSA modulus and the X931 padding format, particularly in the `wp_remove_x931_padding` function. No memory corruption or undefined behavior was detected by ASAN, suggesting the issue is in the padding implementation logic rather than memory-related.
