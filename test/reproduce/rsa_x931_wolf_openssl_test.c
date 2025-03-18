/* rsa_x931_wolf_openssl_test.c - Test case for RSA X931 signature verification with ASAN */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define TEST_ITERATIONS 100
#define MAX_SIGNATURE_SIZE 512

/* RSA key in PEM format */
static const char rsa_key_pem[] = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLcKZRLqjyaiAC\n"
"BS0HGIFzQJQV9Kn5h4NlKD/AoN1O6rdZHMBDG9Z4HaH3yP3xnJ6pUhpQGX/zbYBW\n"
"Iq2QJm2JCiMZqPOp+K7vwGHMxz80RjJzxYbZpZYRZZ0YZXRBEf1Y+bRZ1gGpYgAK\n"
"Vy6jLQz0rXGiMk8Z7JmvqUfGbXm+qPWgCnrYHX7eSXq7M5VKjGXcMZZ6QEYu76OB\n"
"RbwQZ2QD9j5hfXKQPmcPwpvnVJQhfVKbpKdJ+mIlark6jyLznT0oRJOtSvWYmZca\n"
"YgFbNxzZQGqKgGdZSv9J7h5YDPVx9S9q3A+/ib+3+xRqHRkV9aMp/Fx9ykKe7bcp\n"
"ZFAc4a0HAgMBAAECggEABWzxS1Y2/aKYVEgdSZjv5OLEiOLcLVYHyP6+/OfKPqgJ\n"
"6lyZXg/TUOhECw8Owqn1ZCKxBBK0F5TvIeQ3+HR7HGxZd+m2cZqCfVoWxdv/hHQC\n"
"6e/Al9/jfQDcx/hqgyVoRK8QMFc6yCzCN/QQkWI4bvQ/Hd7H8mJYpQ3EkZDDJQEL\n"
"6PM3y0VkjK9xXSZLZ4v2Mvx7M/SvxUf9FA/CJY5h5fZGFw7NdQxzFMwLHLZRHJcH\n"
"9oeO+U/uNwdTKQlgJOFNrYQPN0jR6EvhZ5lfJyA1PBubKs3XZspcYKIWZtg5sBQB\n"
"LjkfR+iHFLdGgYRsP+1WLFYEsWLyXxtFYlT8Qh8QAQKBgQD0XO7BPsMgN3yKXkH3\n"
"Oa/3Rw5HQVV7ak8C3o4yyB+hW5q5Wd8iz1P1RFQCbGHCzk1BVMtZNmQKpYjIBDEo\n"
"lVNYLUGwMzW8jZYeWKQCQJMYRMNWKJWZuJ5r+MfVVLYs1V0GSUmTZ3kCUxKEzgyL\n"
"3ArbfjB+UKoJeD8T6JC7FZXgAQKBgQDVCNbTK2BXMcKiLLQbC8xJhQMYxTsyh3DB\n"
"OPEATLwuHKQ5KtIZVKnZMDEXhGkPZAZ8wFAuPXXHkyNX8iEkEu2oFZHFNRCTRDbl\n"
"4ULlS1cNBm9TxMmCjlXWpjQkRp2/2KsgbfcD8gXJXy/jYfweGX8SLaGLxQnEWXpq\n"
"0jZUetsHBwKBgQCXs2KmFcH0YjEFJKuL2nALl6J3FnmTsQNyM7VGJxnm/yCVCTxA\n"
"ZMDw+CBfPuWYtDcJJ3hxQrTkEzdh8uqG+qXww7BBfwAMh9WGa0dqg2vherBILY9I\n"
"XY2XrVZh4IG1FUILZHjmPwHcNRRZ7kf/5xj6SfwwYVBzq6HKlJsx9xIAAQKBgCke\n"
"MKJ1FGBGLBgkpNdl9c4RXnBJP4NQm5GKcRDhLJLYI4Bl5NRbJgLVvnlNgpBdQQzj\n"
"N8EhP3RJIXYxAOLwXKsK2BRqbLvPcYIRZKvXGHY0GLEwEr4ZRvimep1JsLZ/iNQ/\n"
"TgZ3l+fO5uAQgXKJrWq0VKTEv9jHBTVgBNndTLQJAoGBAO5eKFrMbS/1kVVgtVJK\n"
"NpoMvSHDBqyLmFQf3ulUmPn+C4KYVb6xvJNF0GqzABJO6jbsubiJTYWRyqGGDXCw\n"
"HvxAnxy4t3Hh4CCCu1vKe9y+O2ZxUHqMHKMGQKnwxwRgEJYX0VaR5MFU4iCpFcxJ\n"
"yJbRXcqYXTGTatvTIY5K2naG\n"
"-----END PRIVATE KEY-----\n";

/* Function to print OpenSSL errors */
static void print_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char *str = ERR_error_string(err, NULL);
        fprintf(stderr, "OpenSSL error: %s\n", str);
    }
}

/* Function to test RSA X931 signature verification with wolfProvider signing and OpenSSL verifying */
static int test_wolf_openssl_x931(const EVP_MD *md, const unsigned char *data, size_t data_len)
{
    OSSL_PROVIDER *wolf_provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_LIB_CTX *wolf_libctx = NULL;
    OSSL_LIB_CTX *openssl_libctx = NULL;
    EVP_PKEY *wolf_pkey = NULL;
    EVP_PKEY *openssl_pkey = NULL;
    BIO *bio = NULL;
    EVP_MD_CTX *sign_ctx = NULL;
    EVP_MD_CTX *verify_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);
    int ret = 0;
    
    /* Create separate library contexts for wolfProvider and OpenSSL */
    wolf_libctx = OSSL_LIB_CTX_new();
    openssl_libctx = OSSL_LIB_CTX_new();
    if (!wolf_libctx || !openssl_libctx) {
        fprintf(stderr, "Failed to create library contexts\n");
        goto cleanup;
    }
    
    /* Load providers */
    wolf_provider = OSSL_PROVIDER_load(wolf_libctx, "libwolfprov");
    if (!wolf_provider) {
        fprintf(stderr, "Failed to load wolfProvider\n");
        print_errors();
        goto cleanup;
    }
    
    default_provider = OSSL_PROVIDER_load(openssl_libctx, "default");
    if (!default_provider) {
        fprintf(stderr, "Failed to load default provider\n");
        print_errors();
        goto cleanup;
    }
    
    /* Load the RSA key for both contexts */
    bio = BIO_new_mem_buf(rsa_key_pem, -1);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        goto cleanup;
    }
    
    wolf_pkey = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, NULL, wolf_libctx, NULL);
    if (!wolf_pkey) {
        fprintf(stderr, "Failed to load private key for wolfProvider\n");
        print_errors();
        goto cleanup;
    }
    
    BIO_reset(bio);
    openssl_pkey = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, NULL, openssl_libctx, NULL);
    if (!openssl_pkey) {
        fprintf(stderr, "Failed to load private key for OpenSSL\n");
        print_errors();
        goto cleanup;
    }
    
    /* Create message digest contexts */
    sign_ctx = EVP_MD_CTX_new();
    verify_ctx = EVP_MD_CTX_new();
    if (!sign_ctx || !verify_ctx) {
        fprintf(stderr, "Failed to create message digest context\n");
        goto cleanup;
    }
    
    /* Sign the data using wolfProvider with X931 padding */
    if (EVP_DigestSignInit_ex(sign_ctx, &pkey_ctx, EVP_MD_get0_name(md), wolf_libctx, NULL, wolf_pkey, NULL) != 1) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed for wolfProvider\n");
        print_errors();
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_X931_PADDING) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed for wolfProvider\n");
        print_errors();
        goto cleanup;
    }
    
    if (EVP_DigestSign(sign_ctx, signature, &sig_len, data, data_len) != 1) {
        fprintf(stderr, "EVP_DigestSign failed for wolfProvider\n");
        print_errors();
        goto cleanup;
    }
    
    printf("Signature created with wolfProvider (length: %zu)\n", sig_len);
    
    /* Verify the signature using OpenSSL */
    if (EVP_DigestVerifyInit_ex(verify_ctx, &pkey_ctx, EVP_MD_get0_name(md), openssl_libctx, NULL, openssl_pkey, NULL) != 1) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed for OpenSSL\n");
        print_errors();
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_X931_PADDING) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed for OpenSSL\n");
        print_errors();
        goto cleanup;
    }
    
    ret = EVP_DigestVerify(verify_ctx, signature, sig_len, data, data_len);
    if (ret != 1) {
        fprintf(stderr, "EVP_DigestVerify failed for OpenSSL\n");
        print_errors();
        goto cleanup;
    }
    
    printf("Signature verified successfully with OpenSSL\n");
    ret = 1;
    
cleanup:
    EVP_MD_CTX_free(sign_ctx);
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(wolf_pkey);
    EVP_PKEY_free(openssl_pkey);
    BIO_free(bio);
    OSSL_PROVIDER_unload(wolf_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(wolf_libctx);
    OSSL_LIB_CTX_free(openssl_libctx);
    
    return ret;
}

int main(int argc, char *argv[])
{
    int iterations = (argc > 1) ? atoi(argv[1]) : TEST_ITERATIONS;
    int success_count = 0;
    int i;
    unsigned char data[32];
    
    /* Initialize OpenSSL */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    
    printf("Running %d iterations of RSA X931 signature verification test with ASAN\n", iterations);
    printf("Testing wolfProvider signing and OpenSSL verifying\n");
    
    /* Run the test multiple times to catch intermittent issues */
    for (i = 0; i < iterations; i++) {
        /* Generate random data to sign */
        if (RAND_bytes(data, sizeof(data)) != 1) {
            fprintf(stderr, "Failed to generate random data\n");
            return 1;
        }
        
        /* Test with SHA-1 */
        if (test_wolf_openssl_x931(EVP_sha1(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-1\n", i);
        }
        
        /* Test with SHA-256 */
        if (test_wolf_openssl_x931(EVP_sha256(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-256\n", i);
        }
        
        /* Test with SHA-384 */
        if (test_wolf_openssl_x931(EVP_sha384(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-384\n", i);
        }
        
        /* Test with SHA-512 */
        if (test_wolf_openssl_x931(EVP_sha512(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-512\n", i);
        }
        
        /* Print progress */
        if (i % 10 == 0 || i == iterations - 1) {
            printf("Completed %d/%d iterations, %d/%d successful verifications\n", 
                   i+1, iterations, success_count, (i+1) * 4);
        }
    }
    
    printf("Test completed: %d/%d successful verifications (%.2f%%)\n", 
           success_count, iterations * 4, (float)success_count / (iterations * 4) * 100);
    
    return (success_count == iterations * 4) ? 0 : 1;
}
