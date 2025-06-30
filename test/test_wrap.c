/* test_wrap.c*/

#include "unit.h"

#if defined(HAVE_AES_KEYWRAP) || defined(HAVE_AES_KEYWRAPPAD)

static int test_aes_wrap(const EVP_CIPHER *cipher, unsigned char *kek, const unsigned char *iv,
                    unsigned char *plaintext_key, int plaintext_key_len, 
                    unsigned char *wrapped_key, int *wrappedLen) 
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int wrapped_len = 0;
    int fLen = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_EncryptInit(ctx, cipher, kek, iv) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptUpdate(ctx, wrapped_key, &wrapped_len, plaintext_key, plaintext_key_len) != 1;
    }
    if (err == 0) {
        err = EVP_EncryptFinal_ex(ctx, wrapped_key + wrapped_len, &fLen) != 1;
    }

    wrapped_len = wrapped_len+fLen;
    *wrappedLen = wrapped_len;

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_unwrap(const EVP_CIPHER *cipher, unsigned char *kek, const unsigned char *iv,
                    unsigned char *wrapped_key, int wrapped_len, unsigned char *unwrapped_key, int *unwrappedLen) 
{
    int err = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int unwrapped_len = 0;
    int fLen = 0;

    err = (ctx = EVP_CIPHER_CTX_new()) == NULL;
    if (err == 0) {
        err = EVP_DecryptInit(ctx, cipher, kek, iv) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptUpdate(ctx, unwrapped_key, &unwrapped_len, wrapped_key, wrapped_len) != 1;
    }
    if (err == 0) {
        err = EVP_DecryptFinal_ex(ctx, unwrapped_key + unwrapped_len, &fLen) != 1;
    }

    unwrapped_len = unwrapped_len+fLen;
    *unwrappedLen = unwrapped_len;

    EVP_CIPHER_CTX_free(ctx);

    return err;
}

static int test_aes_wrap_unwrap(void *data, const char *cipher, int keyLen, int ivLen, int plaintextLen)
{
    int err = 0;

    const unsigned char plaintext_key[] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };
   
    unsigned char kek[32]; // 256-bit KEK 
    unsigned char ivbuf[16];
    const unsigned char *iv = NULL;

    unsigned char wrapped_key1[plaintextLen + 16];
    unsigned char wrapped_key2[plaintextLen + 16];
    int wrapped_len1 = 0;
    int wrapped_len2 = 0;

    unsigned char unwrapped_key[plaintextLen + 16];
    int unwrapped_len = 0;

    EVP_CIPHER *ocipher = NULL;
    EVP_CIPHER *wcipher = NULL;

    (void)data;

    ocipher = EVP_CIPHER_fetch(osslLibCtx, cipher, "");
    wcipher = EVP_CIPHER_fetch(wpLibCtx, cipher, "");

    if (RAND_bytes(kek, keyLen) != 1) {
        err = 1;
    }
    if (err == 0) {
       if (ivLen != 0) {
           if (RAND_bytes(ivbuf, ivLen) != 1) {
           err = 1;
           }
           iv = (const unsigned char*)ivbuf;
       } 
    }
    if (err == 0) {
        PRINT_BUFFER("Key", kek, keyLen);
        PRINT_BUFFER("IV", iv, ivLen);
        PRINT_BUFFER("Plaintext_Key", plaintext_key, plaintextLen);
    }

    if (err == 0) {
        PRINT_MSG("Wrap with OpenSSL");
        err = test_aes_wrap(ocipher, kek, iv, (unsigned char *)plaintext_key, plaintextLen, wrapped_key1, &wrapped_len1);
    }
    if (err == 0) {
        PRINT_MSG("Wrap with wolfprovider");
        err = test_aes_wrap(wcipher, kek, iv, (unsigned char *)plaintext_key, plaintextLen, wrapped_key2, &wrapped_len2);
    }
    
    if (err == 0) {
        PRINT_MSG("Compare the Wrapped output length");
        if (wrapped_len1 != wrapped_len2) {
            err = 1;
        }
    }
    if (err == 0) {
        PRINT_MSG("Compare the Wrapped output content");
        err = memcmp(wrapped_key1, wrapped_key2, wrapped_len1) != 0;
    }

    if (err == 0) {
        PRINT_MSG("Unwrap OpenSSL wrapped key with wolfprovider");
        err = test_aes_unwrap(wcipher, kek, iv, wrapped_key1, wrapped_len1, unwrapped_key, &unwrapped_len);
    }

    if (err == 0) {
        if (unwrapped_len != plaintextLen) {
            err = 1;
        }
    }
    if (err == 0) {
        err = memcmp(plaintext_key, unwrapped_key, plaintextLen) != 0;
    }

    if (err == 0) {
        printf("Unwrapped key matches original!\n");
    } else {
        printf("Unwrapped key does NOT match original.\n");
    }

    EVP_CIPHER_free(wcipher);
    EVP_CIPHER_free(ocipher);

    return err;
}


int test_wrap(void *data)
{ 
    int err = 0;

    err = test_aes_wrap_unwrap(data, "AES-256-WRAP", 32, 0, 16);
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-192-WRAP", 24, 0, 16);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-128-WRAP", 16, 0, 16);
    }

    return err;
}

int test_wrap_pad(void *data)
{ 
    int err = 0;

    err = test_aes_wrap_unwrap(data, "AES-256-WRAP-PAD", 32, 0, 8);
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-256-WRAP-PAD", 32, 0, 16);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-256-WRAP-PAD", 32, 0, 14);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-192-WRAP-PAD", 24, 0, 8);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-192-WRAP-PAD", 24, 0, 16);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-192-WRAP-PAD", 24, 0, 14);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-128-WRAP-PAD", 16, 0, 8);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-128-WRAP-PAD", 16, 0, 16);
    }
    if (err == 0) {
        err = test_aes_wrap_unwrap(data, "AES-128-WRAP-PAD", 16, 0, 13);
    }

    return err;
}

#endif /* HAVE_AES_KEYWRAPPAD */ /* HAVE_AES_KEYWRAP */
