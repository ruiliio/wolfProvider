/* rsa_x931_env_test.c - Test case to reproduce RSA X931 signature verification issue
 * focusing on environment variables and library loading */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

/* Test with different environment configurations */
#define TEST_ITERATIONS 10
#define HASH_TYPES 4

/* Test with different hash algorithms */
static const char* hashNames[HASH_TYPES] = {
    "SHA1", "SHA256", "SHA384", "SHA512"
};

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

/* Print environment variables */
static void print_environment(void) {
    printf("Environment variables:\n");
    printf("LD_LIBRARY_PATH: %s\n", getenv("LD_LIBRARY_PATH") ? getenv("LD_LIBRARY_PATH") : "not set");
    printf("OPENSSL_MODULES: %s\n", getenv("OPENSSL_MODULES") ? getenv("OPENSSL_MODULES") : "not set");
    printf("OPENSSL_CONF: %s\n", getenv("OPENSSL_CONF") ? getenv("OPENSSL_CONF") : "not set");
    printf("WOLFPROV_DEBUG: %s\n", getenv("WOLFPROV_DEBUG") ? getenv("WOLFPROV_DEBUG") : "not set");
}

/* Test RSA X931 signature with different hash algorithms */
static int test_rsa_x931_sign_verify(OSSL_LIB_CTX *libCtx, EVP_PKEY *pkey, 
                                    const char *hashName, int iteration) {
    int ret = 0;
    EVP_MD_CTX *mdCtx = NULL;
    EVP_PKEY_CTX *pkeyCtx = NULL;
    unsigned char *sig = NULL;
    size_t sigLen = 0;
    unsigned char data[32];
    
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

    /* Initialize for signing with OpenSSL default provider */
    if (EVP_DigestSignInit_ex(mdCtx, &pkeyCtx, hashName, libCtx, "default", pkey, NULL) != 1) {
        fprintf(stderr, "Failed to initialize signing with default provider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Set padding mode to X931 */
    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_X931_PADDING) != 1) {
        fprintf(stderr, "Failed to set padding mode\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Determine signature size */
    if (EVP_DigestSign(mdCtx, NULL, &sigLen, data, sizeof(data)) != 1) {
        fprintf(stderr, "Failed to determine signature size\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Allocate memory for signature */
    sig = OPENSSL_malloc(sigLen);
    if (!sig) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        goto cleanup;
    }

    /* Sign the data with OpenSSL default provider */
    if (EVP_DigestSign(mdCtx, sig, &sigLen, data, sizeof(data)) != 1) {
        fprintf(stderr, "Failed to sign data with default provider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Reset the context for verification with wolfProvider */
    EVP_MD_CTX_reset(mdCtx);
    
    /* Initialize for verification with wolfProvider */
    if (EVP_DigestVerifyInit_ex(mdCtx, &pkeyCtx, hashName, libCtx, "libwolfprov", pkey, NULL) != 1) {
        fprintf(stderr, "Failed to initialize verification with wolfProvider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Set padding mode to X931 */
    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_X931_PADDING) != 1) {
        fprintf(stderr, "Failed to set padding mode for verification\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Verify the signature with wolfProvider */
    if (EVP_DigestVerify(mdCtx, sig, sigLen, data, sizeof(data)) != 1) {
        fprintf(stderr, "Signature verification failed (iteration %d, hash %s)\n", 
                iteration, hashName);
        check_openssl_errors();
        goto cleanup;
    }

    /* Now test the reverse: sign with wolfProvider, verify with OpenSSL */
    EVP_MD_CTX_reset(mdCtx);
    
    /* Initialize for signing with wolfProvider */
    if (EVP_DigestSignInit_ex(mdCtx, &pkeyCtx, hashName, libCtx, "libwolfprov", pkey, NULL) != 1) {
        fprintf(stderr, "Failed to initialize signing with wolfProvider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Set padding mode to X931 */
    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_X931_PADDING) != 1) {
        fprintf(stderr, "Failed to set padding mode for signing\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Reset signature length */
    sigLen = 0;
    
    /* Determine signature size */
    if (EVP_DigestSign(mdCtx, NULL, &sigLen, data, sizeof(data)) != 1) {
        fprintf(stderr, "Failed to determine signature size with wolfProvider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Free previous signature and allocate new memory */
    OPENSSL_free(sig);
    sig = OPENSSL_malloc(sigLen);
    if (!sig) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        goto cleanup;
    }

    /* Sign the data with wolfProvider */
    if (EVP_DigestSign(mdCtx, sig, &sigLen, data, sizeof(data)) != 1) {
        fprintf(stderr, "Failed to sign data with wolfProvider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Reset the context for verification with OpenSSL default provider */
    EVP_MD_CTX_reset(mdCtx);
    
    /* Initialize for verification with OpenSSL default provider */
    if (EVP_DigestVerifyInit_ex(mdCtx, &pkeyCtx, hashName, libCtx, "default", pkey, NULL) != 1) {
        fprintf(stderr, "Failed to initialize verification with default provider\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Set padding mode to X931 */
    if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_X931_PADDING) != 1) {
        fprintf(stderr, "Failed to set padding mode for verification\n");
        check_openssl_errors();
        goto cleanup;
    }

    /* Verify the signature with OpenSSL default provider */
    if (EVP_DigestVerify(mdCtx, sig, sigLen, data, sizeof(data)) != 1) {
        fprintf(stderr, "Signature verification failed (wolfProvider->OpenSSL, iteration %d, hash %s)\n", 
                iteration, hashName);
        check_openssl_errors();
        goto cleanup;
    }

    ret = 1; /* Success */

cleanup:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(mdCtx);
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = 1;
    OSSL_PROVIDER *defProv = NULL;
    OSSL_PROVIDER *wolfProv = NULL;
    OSSL_LIB_CTX *libCtx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *keyBio = NULL;
    int iterations = TEST_ITERATIONS;
    int failures = 0;
    int i, h;

    /* Parse command line arguments */
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            iterations = TEST_ITERATIONS;
        }
    }

    /* Print environment variables */
    print_environment();

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

    printf("Testing RSA X931 signature verification with %d iterations per hash algorithm\n", 
           iterations);
    
    /* Run the test multiple times to try to reproduce the intermittent failure */
    for (i = 0; i < iterations; i++) {
        for (h = 0; h < HASH_TYPES; h++) {
            if (!test_rsa_x931_sign_verify(libCtx, pkey, hashNames[h], i)) {
                failures++;
                fprintf(stderr, "Test failed with hash %s (iteration %d)\n", hashNames[h], i);
            }
            
            /* Print progress indicator */
            if ((i * HASH_TYPES + h + 1) % 10 == 0) {
                printf(".");
                fflush(stdout);
            }
            if ((i * HASH_TYPES + h + 1) % 100 == 0) {
                printf(" %d/%d\n", i * HASH_TYPES + h + 1, iterations * HASH_TYPES);
                fflush(stdout);
            }
        }
    }

    if (failures > 0) {
        fprintf(stderr, "\nTest failed with %d failures out of %d iterations\n", 
                failures, iterations * HASH_TYPES);
    } else {
        printf("\nAll %d iterations passed successfully\n", iterations * HASH_TYPES);
        ret = 0;
    }

cleanup:
    EVP_PKEY_free(pkey);
    BIO_free(keyBio);
    OSSL_PROVIDER_unload(wolfProv);
    OSSL_PROVIDER_unload(defProv);
    OSSL_LIB_CTX_free(libCtx);
    return ret;
}
