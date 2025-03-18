#!/bin/bash

# Test script that rapidly switches between providers to try to trigger race conditions
# This simulates the GitHub Actions environment where multiple tests run in parallel

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
WOLFPROV_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Number of iterations
ITERATIONS=${1:-100}

# Compile the test if it doesn't exist
cat > "$SCRIPT_DIR/rsa_x931_switch_test.c" << 'EOC'
/* Test case to reproduce RSA X931 signature verification issue by switching providers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

/* RSA key in PEM format */
static const char rsa_key_pem[] = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLcKZRLqjyaiAC\n"
"BS0HGIFzQJQV9Kn5h4NlKD/AoN1O6rdZHMBDG9Z4HaH3yP3xnJ6pUhpQGX/zbYBW\n"
"Iq2QJm2JCiMZqPOp+K7vwGHMxz80RjJzxYbZpZYRZZ0YZXRBEf1Y+bRZ1gGpYgAK\n"
"v2w3WxbEgqQxOm9jn75WGYzK8fk/MVKo3Fz6Ty9pGBQdZ9lhOBNS2m8wqxqB2yUv\n"
"rUXvr4hEPX/ZYP0lMUEkiMNMKDPh4MQQvHfRlKFwFLYYbHK3CG+ESiRFUUgTYoQs\n"
"eJFLRHlKe5j0Yz+NqL5Xxl/OUVlG/QTLicCXNgLIHEXZqbxKCn9dqKzJVKJKRKKu\n"
"pv8jeQ/XAgMBAAECggEAHdIGcJOX5Bj8qPudxZ1S6uplYan+RHoZdDz6bAEIGIbY\n"
"0wUJY5fEqz0YqhLyqBdxIIgWQFMVGJXyrJxQZP+XVqwJRZlNz0aBELcF5h4YtSEH\n"
"wLg/D6aSJGO5FSdqXNy1XUbLkP5QgBDOFrGm7QBX0+NCzLX3fH6jXAsXZ9+3QxXn\n"
"xOuXXZj5RKnTCEQXoJKdZIJY23MQYLVDiK1xFD3vZpZWBUU5/0XhpTpBy6ttMPVL\n"
"5jWxT4cWwQ9MFG5LXR/XqkJlwx7zNGBhwgLo1Z4LNQX2QQEoYT6iKDCLx9UEH7b6\n"
"2+3jQbXUJORJxAOl6S+FUBEA5jnAwbAYRHKwmJEYAQKBgQDmWgbT/0+lfJQcWpQW\n"
"5WPE6XjsUBKqy8FXVEsDTnIcqIiSXV6QdqoBOgxKUGxLqjgLIQMqbOF1EKRqDX5i\n"
"in0n5tQKTgGcnDu50UQ5QJ6H9G7vQjITZqV94Rb9OKQAZfkwqDQySVNUXxOL9TBG\n"
"chJxz7yUTbYpQHK1fVYm5C/UAQKBgQDiSH1qBcxFAkzOgLX3tMVWmpvGj7SWPGDK\n"
"XVTJwTTVOYfyQ0W5dL0oNZJZYxk5pXNKQmRFomxKD9bNJPRIUTTGbvBU4+H4yDei\n"
"ZnS3Dn5bGanTZ3LgKEHcQbKaz3RqVEervsRv3/VDRmRQw/NYCkYgkTMv5ePqOH0w\n"
"1QeNsHfX1wKBgQCwZ3/1wLo/xvOdBswBqTzS8F+LMCV0SZbNL3shgJLrknZLZYkY\n"
"CPDYKQHNOw+wTiMnKfYI8TjJKEYyOYgZ+jQO/wNzOkNTcFzGKCnSz1Ic8tOR2nXY\n"
"8RFY7BtPNOKydABwmG5/1iMRZUlYd0dJ9BqQDcJMRL1qxJbs8Dn4AQMAAQKBgQCZ\n"
"Ks5g/5ov9jvDR4aRbmXXV6iQJBxQmWsUMvZ4nE9KUjRMdcqEuKFCpVstRCMOlvI5\n"
"ZFg/Nw5JS698nmBUYFMoHVRr0xRtYVxZEYoIMRBJnSE8nYb/quaKJJPEWzYcyWKZ\n"
"NlTKzHbgY8H2NAFmOcbfnHVyjYEymXF2uZKDplgUBQKBgFSAzaGqljUNcY1fqthQ\n"
"OoK5HCpjwOcYNpSEi0F4qRXKRNqy1k9Mk0KcUPJJbTLLB2N/MrPnN8QYZTvbJD9Z\n"
"Vy/BYR2wqrODCEj//MpSEzsXGnEEb6YVCe4qdDmVJZ7CnXJnFRDvxmLKxPnxSLbK\n"
"zPYJRkUWfF8UwmEQY0xmXaYR\n"
"-----END PRIVATE KEY-----\n";

/* Function to check OpenSSL errors */
static void check_openssl_errors(void) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char *err_str = ERR_error_string(err, NULL);
        fprintf(stderr, "OpenSSL error: %s\n", err_str);
    }
}

/* Test RSA X931 signature with rapid provider switching */
static int test_rsa_x931_provider_switch(int iterations) {
    int ret = 0;
    OSSL_PROVIDER *defProv = NULL;
    OSSL_PROVIDER *wolfProv = NULL;
    OSSL_LIB_CTX *libCtx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *keyBio = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;
    unsigned char *sig = NULL;
    size_t sigLen = 0;
    unsigned char data[32];
    int i, failures = 0;
    
    /* Create a new library context */
    libCtx = OSSL_LIB_CTX_new();
    if (!libCtx) {
        fprintf(stderr, "Failed to create library context\n");
        goto cleanup;
    }

    /* Load providers */
    defProv = OSSL_PROVIDER_load(libCtx, "default");
    if (!defProv) {
        fprintf(stderr, "Failed to load default provider\n");
        check_openssl_errors();
        goto cleanup;
    }

    wolfProv = OSSL_PROVIDER_load(libCtx, "libwolfprov");
    if (!wolfProv) {
        fprintf(stderr, "Failed to load wolfProvider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Load RSA key from PEM */
    keyBio = BIO_new_mem_buf(rsa_key_pem, -1);
    if (!keyBio) {
        fprintf(stderr, "Failed to create key BIO\n");
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Failed to load RSA key\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Create message digest context */
    mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        fprintf(stderr, "Failed to create message digest context\n");
        goto cleanup;
    }

    /* Generate random data */
    if (RAND_bytes(data, sizeof(data)) != 1) {
        fprintf(stderr, "Failed to generate random data\n");
        goto cleanup;
    }

    printf("Testing RSA X931 signature verification with provider switching (%d iterations)\n", 
           iterations);
    
    /* Run the test multiple times, switching providers rapidly */
    for (i = 0; i < iterations; i++) {
        /* Alternate between providers for signing */
        const char *signProvider = (i % 2 == 0) ? "default" : "libwolfprov";
        const char *verifyProvider = (i % 2 == 0) ? "libwolfprov" : "default";
        
        /* Initialize for signing */
        EVP_MD_CTX_reset(mdCtx);
        if (EVP_DigestSignInit_ex(mdCtx, &pkeyCtx, "SHA256", libCtx, signProvider, pkey, NULL) != 1) {
            fprintf(stderr, "Failed to initialize signing with %s (iteration %d)\n", 
                    signProvider, i);
            check_openssl_errors();
            failures++;
            continue;
        }

        /* Set padding mode to X931 */
        if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_X931_PADDING) != 1) {
            fprintf(stderr, "Failed to set padding mode (iteration %d)\n", i);
            check_openssl_errors();
            failures++;
            continue;
        }

        /* Determine signature size */
        if (EVP_DigestSign(mdCtx, NULL, &sigLen, data, sizeof(data)) != 1) {
            fprintf(stderr, "Failed to determine signature size (iteration %d)\n", i);
            check_openssl_errors();
            failures++;
            continue;
        }

        /* Allocate memory for signature */
        if (sig != NULL) {
            OPENSSL_free(sig);
        }
        sig = OPENSSL_malloc(sigLen);
        if (!sig) {
            fprintf(stderr, "Failed to allocate memory for signature (iteration %d)\n", i);
            failures++;
            continue;
        }

        /* Sign the data */
        if (EVP_DigestSign(mdCtx, sig, &sigLen, data, sizeof(data)) != 1) {
            fprintf(stderr, "Failed to sign data with %s (iteration %d)\n", 
                    signProvider, i);
            check_openssl_errors();
            failures++;
            continue;
        }

        /* Reset the context for verification */
        EVP_MD_CTX_reset(mdCtx);
        
        /* Initialize for verification with the other provider */
        if (EVP_DigestVerifyInit_ex(mdCtx, &pkeyCtx, "SHA256", libCtx, verifyProvider, pkey, NULL) != 1) {
            fprintf(stderr, "Failed to initialize verification with %s (iteration %d)\n", 
                    verifyProvider, i);
            check_openssl_errors();
            failures++;
            continue;
        }

        /* Set padding mode to X931 */
        if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_X931_PADDING) != 1) {
            fprintf(stderr, "Failed to set padding mode for verification (iteration %d)\n", i);
            check_openssl_errors();
            failures++;
            continue;
        }

        /* Verify the signature */
        if (EVP_DigestVerify(mdCtx, sig, sigLen, data, sizeof(data)) != 1) {
            fprintf(stderr, "Signature verification failed (%s->%s, iteration %d)\n", 
                    signProvider, verifyProvider, i);
            check_openssl_errors();
            failures++;
            continue;
        }
        
        /* Print progress indicator */
        if ((i + 1) % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        if ((i + 1) % 100 == 0) {
            printf(" %d/%d\n", i + 1, iterations);
            fflush(stdout);
        }
    }

    if (failures > 0) {
        fprintf(stderr, "\nTest failed with %d failures out of %d iterations\n", 
                failures, iterations);
    } else {
        printf("\nAll %d iterations passed successfully\n", iterations);
        ret = 1;
    }

cleanup:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);
    BIO_free(keyBio);
    OSSL_PROVIDER_unload(wolfProv);
    OSSL_PROVIDER_unload(defProv);
    OSSL_LIB_CTX_free(libCtx);
    return ret;
}

int main(int argc, char *argv[]) {
    int iterations = 100;
    
    /* Parse command line arguments */
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            iterations = 100;
        }
    }
    
    return test_rsa_x931_provider_switch(iterations) ? 0 : 1;
}
EOC

# Compile the test
gcc -o "$SCRIPT_DIR/rsa_x931_switch_test" "$SCRIPT_DIR/rsa_x931_switch_test.c" -lcrypto

# Run the test
"$SCRIPT_DIR/rsa_x931_switch_test" $ITERATIONS

# Return the exit code
exit $?
