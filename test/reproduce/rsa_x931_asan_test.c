/* rsa_x931_asan_test.c - Test case for RSA X931 signature verification with ASAN */
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

/* Function to test RSA X931 signature verification */
static int test_rsa_x931_sign_verify(EVP_MD_CTX *mdctx, EVP_PKEY *pkey, 
                                    const EVP_MD *md, const unsigned char *data, 
                                    size_t data_len)
{
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);
    int ret = 0;
    
    /* Sign the data using X931 padding */
    if (EVP_DigestSignInit_ex(mdctx, NULL, EVP_MD_get0_name(md), NULL, NULL, pkey, NULL) != 1) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed\n");
        print_errors();
        return 0;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mdctx), RSA_X931_PADDING) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
        print_errors();
        return 0;
    }
    
    if (EVP_DigestSign(mdctx, signature, &sig_len, data, data_len) != 1) {
        fprintf(stderr, "EVP_DigestSign failed\n");
        print_errors();
        return 0;
    }
    
    /* Verify the signature */
    if (EVP_DigestVerifyInit_ex(mdctx, NULL, EVP_MD_get0_name(md), NULL, NULL, pkey, NULL) != 1) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed\n");
        print_errors();
        return 0;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(mdctx), RSA_X931_PADDING) != 1) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed\n");
        print_errors();
        return 0;
    }
    
    ret = EVP_DigestVerify(mdctx, signature, sig_len, data, data_len);
    if (ret != 1) {
        fprintf(stderr, "EVP_DigestVerify failed\n");
        print_errors();
        return 0;
    }
    
    return 1;
}

int main(int argc, char *argv[])
{
    int iterations = (argc > 1) ? atoi(argv[1]) : TEST_ITERATIONS;
    int success_count = 0;
    int i;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char data[32];
    
    /* Initialize OpenSSL */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    
    /* Load the RSA key */
    bio = BIO_new_mem_buf(rsa_key_pem, -1);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        goto cleanup;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Failed to load private key\n");
        print_errors();
        goto cleanup;
    }
    
    /* Create message digest context */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create message digest context\n");
        goto cleanup;
    }
    
    printf("Running %d iterations of RSA X931 signature verification test with ASAN\n", iterations);
    
    /* Run the test multiple times to catch intermittent issues */
    for (i = 0; i < iterations; i++) {
        /* Generate random data to sign */
        if (RAND_bytes(data, sizeof(data)) != 1) {
            fprintf(stderr, "Failed to generate random data\n");
            goto cleanup;
        }
        
        /* Test with SHA-1 */
        if (test_rsa_x931_sign_verify(mdctx, pkey, EVP_sha1(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-1\n", i);
        }
        
        /* Test with SHA-256 */
        if (test_rsa_x931_sign_verify(mdctx, pkey, EVP_sha256(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-256\n", i);
        }
        
        /* Test with SHA-384 */
        if (test_rsa_x931_sign_verify(mdctx, pkey, EVP_sha384(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-384\n", i);
        }
        
        /* Test with SHA-512 */
        if (test_rsa_x931_sign_verify(mdctx, pkey, EVP_sha512(), data, sizeof(data))) {
            success_count++;
        } else {
            fprintf(stderr, "Test failed at iteration %d with SHA-512\n", i);
        }
        
        /* Print progress */
        if (i % 10 == 0) {
            printf("Completed %d iterations\n", i);
        }
    }
    
    printf("Test completed: %d/%d successful verifications\n", 
           success_count, iterations * 4);
    
cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    
    return (success_count == iterations * 4) ? 0 : 1;
}
