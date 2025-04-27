#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/prov_ssl.h>

#include <wolfprovider/alg_funcs.h>

#ifdef HAVE_AES_KEYWRAPPAD

/** RFC 5649 section 3 Alternative Initial Value 32-bit constant */
static const unsigned char default_aiv[] = {
    0xA6, 0x59, 0x59, 0xA6
};

/** Input size limit: lower than maximum of standards but far larger than
 *  anything that will be used in practice.
 */
#define AES_KEY_WRAP_MAX (1UL << 31)

/**
 * Data structure for AES ciphers that wrap.
 */
typedef struct wp_AesWrapPadCtx {
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    Aes aes;
#endif

    unsigned int wrap:1;
    unsigned int ivSet:1;
    unsigned int pad:1;

    size_t keyLen;
    size_t ivLen;
    unsigned char iv[AES_IV_SIZE];
#if LIBWOLFSSL_VERSION_HEX < 0x05000000
    unsigned char key[AES_256_KEY_SIZE];
#endif
} wp_AesWrapPadCtx;
    

/* Prototype for initialization to call. */
static int wp_aes_wrap_pad_set_ctx_params(wp_AesWrapPadCtx *ctx,
    const OSSL_PARAM params[]);

int wp_aes_wrap_pad(wp_AesWrapPadCtx *ctx, unsigned char* iv, 
                    unsigned char *out, word32 outSz, size_t *outLen,
                    const unsigned char *in, size_t inLen);

int wp_aes_unwrap_pad(wp_AesWrapPadCtx *ctx, unsigned char* iv, 
                    unsigned char *out, size_t *outLen, 
                    const unsigned char *in, size_t inLen);

int wp_AesKeyUnWrapPad_ex(Aes *aes, unsigned char *iv, unsigned char *out,
    const unsigned char *in, size_t inLen);

/**
 * Free the AES wrap context object.
 *
 * @param [in, out] ctx  AES wrap context object.
 */
static void wp_aes_wrap_pad_freectx(wp_AesWrapPadCtx *ctx)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    wc_AesFree(&ctx->aes);
#else
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
#endif
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/**
 * Duplicate the AES wrap context object.
 *
 * @param [in] src  AES wrap context object to copy.
 * @return  NULL on failure.
 * @return  AES wrap context object.
 */
static void *wp_aes_wrap_pad_dupctx(wp_AesWrapPadCtx *src)
{
    wp_AesWrapPadCtx *dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_malloc(sizeof(*dst));
    }
    if (dst != NULL) {
        /* TODO: copying Aes may not work if it has pointers in it. */
        XMEMCPY(dst, src, sizeof(*src));
    }

    return dst;
}

/**
 * Returns the parameters that can be retrieved.
 *
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_aes_wrap_pad_gettable_params(
    WOLFPROV_CTX *provCtx)
{
    /**
     * Parameters able to be retrieved for an AES wrap operation.
     */
    static const OSSL_PARAM wp_aes_wrap_pad_supported_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_aes_wrap_pad_supported_gettable_params;
}

/**
 * Get the values from the AES wrap context for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      mode    AES cipher mode.
 * @param [in]      kBits   Number of bits in key.
 * @param [in]      ivBits  Number of bits in IV.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_aes_wrap_pad_get_params(OSSL_PARAM params[], unsigned int mode,
    size_t kBits, size_t ivBits)
{
    int ok = 1;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, mode))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, kBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ivBits / 8))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of a cipher context that can be retrieved.
 *
 * @param [in] ctx      AES wrap context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_aes_wrap_pad_gettable_ctx_params(wp_AesWrapPadCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters able to be retrieved for a cipher context.
     */
    static const OSSL_PARAM wp_aes_wrap_pad_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_wrap_pad_supported_gettable_ctx_params;
}

/**
 * Returns the parameters of a cipher context that can be set.
 *
 * @param [in] ctx      AES wrap context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_aes_wrap_pad_settable_ctx_params(wp_AesWrapPadCtx* ctx,
    WOLFPROV_CTX *provCtx)
{
    /*
     * Parameters able to be set into a cipher context.
     */
    static const OSSL_PARAM wp_aes_wrap_pad_supported_settable_ctx_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_wrap_pad_supported_settable_ctx_params;
}

/**
 * Initialization of an AES wrap.
 *
 * Internal. Handles both wrap and unwrap.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES wrap context object.
 * @param [in]      wrap    Initializing for wrap.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_pad_init(wp_AesWrapPadCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int wrap)
{
    int ok = 1;

    ctx->wrap = wrap;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (iv != NULL)) {
        if (ivLen != ctx->ivLen) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, iv, ivLen);
        }
    }

    if (ok && (key != NULL)) {
        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        if (ok) {
        #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
            int rc = wc_AesSetKey(&ctx->aes, key, (word32)ctx->keyLen, iv,
                wrap ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                ok = 0;
            }
        #else
            XMEMCPY(ctx->key, key, keyLen);
        #endif
        }
    }

    if (ok) {
        ok = wp_aes_wrap_pad_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an AES wrapping.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES wrap context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_pad_einit(wp_AesWrapPadCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_wrap_pad_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialization of an AES unwrapping.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES wrap context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_pad_dinit(wp_AesWrapPadCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_wrap_pad_init(ctx, key, keyLen, iv, ivLen, params, 0);
}


/** 
 * KeyWrapPad: Wrapping according to RFC 5649 section 4.1.
 * 
 * @param [in]  ctx     AES wrap context object. 
 * @param [in]  iv      IV data. May be NULL.
 * @param [out] out     Buffer to hold ciphertext. 
 * @param [in]  outSz   Size of output buffer in bytes.
 * @param [out] outLen  Output length in bytes.
 * @param [in]  in      Plaintext as n 64-bit blocks, n >= 2.
 * @param [in]  inLen   Length of input data in bytes.
 * @return              0 on failure(inLen is out of range [1, AES_KEY_WRAP_MAX]).
 * @return              1 on success.       
 */
int wp_aes_wrap_pad(wp_AesWrapPadCtx *ctx, unsigned char* iv, unsigned char *out, word32 outSz, 
                    size_t *outLen, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int ret = 0;
    /* 
     * If length of plain text is not a multiple of 8, pad the plain text octet
     * string on the right with octets of zeros, where final length is the
     * smallest multiple of 8 that is greater than length of plain text.
     * If length of plain text is a multiple of 8, then there is no padding. */
    const size_t blocks_padded = (inLen + 7) / 8; /* CEILING(m/8) */
    // blocks_padded = inLen / 8 + 2;
    // if inLen % 8 == 1; blocks_padded = inLen / 8 + 1;
    const size_t padded_len = blocks_padded * 8;
    const size_t padding_len = padded_len - inLen;

    /* RFC 5649 section 3: Alternative Initial Value */
    unsigned char aiv[8];

    /* Section 1: use 32-bit fixed field for plaintext octet length */
    if (inLen == 0 || inLen >= AES_KEY_WRAP_MAX) {
        return 0; 
    }

    /* Section 3: Alternative Initial Value */
    if (!iv)
        memcpy(aiv, default_aiv, 4);
    else
        memcpy(aiv, iv, 4);    /* Standard doesn't mention this. */
    aiv[4] = (inLen >> 24) & 0xFF;
    aiv[5] = (inLen >> 16) & 0xFF;
    aiv[6] = (inLen >> 8) & 0xFF;
    aiv[7] = inLen & 0xFF;
   
    if (padded_len == 8) {
        /*
         * Section 4.1 - special case in step 2: If the padded plaintext
         * contains exactly eight octets, then prepend the AIV and encrypt
         * the resulting 128-bit block using AES in ECB mode.
         */
        memmove(out + 8, in, inLen);
        memcpy(out, aiv, 8);
        memset(out + 8 + inLen, 0, padding_len);
       
        ret = wc_AesEncryptDirect(&ctx->aes, out, out);  
        if (ret != 0 ){
            ok = 0;
        }
        
        *outLen = 16;  /* AIV + padded input */  
                     
    } else {
        ret = wc_AesKeyWrap_ex(&ctx->aes, in, (word32)padded_len, out, outSz, aiv);
        if (ret <= 0 ){
            ok = 0;
        }
        
        *outLen = ret;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);

    return ok;
}


/** 
 * KeyUnWrapPad: Unwrapping according to RFC 5649 section 4.1.
 * 
 * @param [in]  ctx     AES wrap context object. 
 * @param [in]  iv      IV data. May be NULL.
 * @param [out] out     Buffer to hold plaintext.
 * @param [out] outLen  Output length in bytes.
 * @param [in]  in      Plaintext as n 64-bit blocks, n >= 2.
 * @param [in]  inLen   Length of input data in bytes.
 * @return              0 on failure(inLen is out of range [1, AES_KEY_WRAP_MAX]).
 * @return              1 on success.       
 */
int wp_aes_unwrap_pad(wp_AesWrapPadCtx *ctx, unsigned char* iv, unsigned char *out, size_t *outLen, 
     const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int ret = 0;
    
    /* n: number of 64-bit blocks in the padded key data */
    size_t n = inLen / 8 - 1;
    size_t padded_len = 0;
    size_t padding_len = 0;
    size_t ptext_len = 0;

    /* RFC 5649 section 3: Alternative Initial Value */
    unsigned char aiv[8];
    static unsigned char zeros[8] = { 0x0 };
    
    /* Section 4.2: Ciphertext length has to be (n+1) 64-bit blocks. */
    // if inLen is out of range [16, AES_KEY_WRAP_MAX], or 
    // if inLen is not a multiple of 8: (inLen & 0x7) != 0
    if ((inLen & 0x7) != 0 || inLen < 16 || inLen >= AES_KEY_WRAP_MAX) {
        return 0;
    }

    if (inLen == 16) {
        /*
         * Section 4.2 - special case in step 1: When n=1, the ciphertext
         * contains exactly two 64-bit blocks and they are decrypted as a
         * single AES block using AES in ECB mode: AIV | P[1] = DEC(K, C[0] |
         * C[1])
         */
        unsigned char buff[16];
        ret = wc_AesDecryptDirect(&ctx->aes, (byte*)buff, (const byte*)in);
        if ( ret != 0){
            ok = 0;
        }

        memcpy(aiv, buff, 8);
        /* Remove AIV */
        memcpy(out, buff + 8, 8); 
        padded_len = 8;
        OPENSSL_cleanse(buff, inLen);
    } else {
        padded_len = inLen - 8;

        ret = wp_AesKeyUnWrapPad_ex(&ctx->aes, aiv, out, in, inLen);
        if (ret <= 0) {
            ok = 0;
        }
        if (padded_len != ret) {
            OPENSSL_cleanse(out, inLen);
            ok = 0; 
        }
        //*outLen = ret; 
    }

    if (ok) {
        /*
         * Section 3: AIV checks: Check that MSB(32,A) = A65959A6. Optionally a
         * user-supplied value can be used (even if standard doesn't mention
         * this).
         */
        if ((!iv && CRYPTO_memcmp(aiv, default_aiv, 4))
            || (iv && CRYPTO_memcmp(aiv, iv, 4))) {
            OPENSSL_cleanse(out, inLen);
            ok = 0; 
        }
    }
    
    if (ok) {
         /*
         * Check that 8*(n-1) < LSB(32,AIV) <= 8*n. If so, let ptext_len =
         * LSB(32,AIV).
         */

        ptext_len =   ((unsigned int)aiv[4] << 24)
                    | ((unsigned int)aiv[5] << 16)
                    | ((unsigned int)aiv[6] <<  8)
                    |  (unsigned int)aiv[7];
        if (8 * (n - 1) >= ptext_len || ptext_len > 8 * n) {
            OPENSSL_cleanse(out, inLen);
            ok = 0; 
        }
    }

    if (ok) {
        /*
         * Check that the rightmost padding_len octets of the output data are
         * zero.
         */
        padding_len = padded_len - ptext_len;
        if (CRYPTO_memcmp(out + ptext_len, zeros, padding_len) != 0) {
            OPENSSL_cleanse(out, inLen);
            ok = 0;
        }
    }
   
    /* Section 4.2 step 3: Remove padding */
    *outLen = ptext_len;
   
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);

    return ok;
}

/** 
 * Unwrapping according to RFC 3394 section 2.2.2 steps 1-2.
 *  The IV check (step 3) is responsibility of the caller.
 *
 *  @param [in]  ctx    AES wrap context object.
 *  @param [out] iv     Unchecked IV value. Minimal buffer length = 8 bytes.
 *  @param [out] out    Plaintext without IV.
 *                      Minimal buffer length = (inlen - 8) bytes.
 *                      Input and output buffers can overlap if block function
 *                      supports that.
 *  @param [in]  in     Ciphertext as n 64-bit blocks.
 *  @param [in]  inLen  Length of in.
 *  @return             0 if inlen is out of range [24, AES_KEY_WRAP_MAX]
 *                      or if inlen is not a multiple of 8.
 *                      Output length otherwise.
 */
int wp_AesKeyUnWrapPad_ex(Aes *aes, unsigned char *iv, unsigned char *out,
                            const unsigned char *in, size_t inLen)
{
    unsigned char *A, B[16], *R;
    size_t i, j, t;
    inLen -= 8;
    if ((inLen & 0x7) || (inLen < 16) || (inLen > AES_KEY_WRAP_MAX))
        return 0;
    A = B;
    t = 6 * (inLen >> 3);
    memcpy(A, in, 8);
    memmove(out, in + 8, inLen);
    for (j = 0; j < 6; j++) {
        R = out + inLen - 8;
        for (i = 0; i < inLen; i += 8, t--, R -= 8) {
            A[7] ^= (unsigned char)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (unsigned char)((t >> 8) & 0xff);
                A[5] ^= (unsigned char)((t >> 16) & 0xff);
                A[4] ^= (unsigned char)((t >> 24) & 0xff);
            }
            memcpy(B + 8, R, 8);
            int ret = wc_AesDecryptDirect(aes, (byte*)B, (const byte*)B);
            if (ret != 0){
                return 0;
            }
            memcpy(R, B + 8, 8);
        }
    }
    memcpy(iv, A, 8);
    return inLen;
}

/**
 * One-shot wrap/unwrap.
 *
 * @param [in]  ctx      AES wrap context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */

static int wp_aes_wrap_pad_update(wp_AesWrapPadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    size_t outl = 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    printf("inLen=%ld\n", inLen);
    printf("buffer len outSize=%ld\n", outSize);

    if (ok && (inLen == 0)) {
        *outLen = 0;
    }
    else if (ok) {
        int rc;
        word32 outSz = (word32)outSize;
        unsigned char* iv;

        if (ctx->ivSet) {
            iv = ctx->iv;
        }
        else {
            iv = NULL;
        }

    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        (void)rc;
        if (ctx->wrap) {
            ok = wp_aes_wrap_pad(ctx, iv, out, outSz, &outl, in, inLen) != 0; 
        }
        else {
            ok = wp_aes_unwrap_pad(ctx, iv, out, &outl, in, inLen) != 0;
        }
    #else
        printf("KEYWRAPPAD is not supported by LIBWOLFSSL_VERSION_HEX < 0x05000000");
    #endif
        if (ok) {
            *outLen = outl;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);

    return ok;

}

/**
 * Finalize AES wrap/unwrap. Nothing to do.
 *
 * @param [in]  ctx      AES wrap context object.
 * @param [out] out      Buffer to hold encrypted/decrypted data.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_pad_final(wp_AesWrapPadCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    (void)ctx;
    (void)out;
    (void)outSize;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok) {
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put values from the AES wrap context object into parameters objects.
 *
 * @param [in]      ctx     AES wrap context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_pad_get_ctx_params(wp_AesWrapPadCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->ivLen))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        /* padding implementation available in wolfSSL. */
        if ((p != NULL) && (!OSSL_PARAM_set_uint(p, ctx->pad))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivLen)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivLen))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->keyLen))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into AES wrap context object.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_aes_wrap_pad_set_ctx_params(wp_AesWrapPadCtx *ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        size_t keyLen = ctx->keyLen;
        unsigned int pad = 0;

        if (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_PADDING, &pad,
                NULL)) {
            ok = 0;
        }

        if (ok && (pad == 0)) {
            ok = 0;
        }

        if (ok && (!wp_params_get_size_t(params, OSSL_CIPHER_PARAM_KEYLEN,
                &keyLen))) {
            ok = 0;
        }
        if (ok && (keyLen != ctx->keyLen)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize the AES wrap context object.
 *
 * @param [in, out] ctx      AES wrap context object.
 * @param [in]      kBits    Number of bits in a valid key.
 * @param [in]      ivBits   Number of bits in a valid IV.
 * @return  1 on success.
 * @return  0 on failure.
 */
static void wp_aes_wrap_pad_init_ctx(wp_AesWrapPadCtx* ctx, size_t kBits,
    size_t ivBits)
{
    ctx->keyLen = ((kBits) / 8);
    ctx->ivLen = ((ivBits) / 8);
    ctx->pad = 1; 
}

/** Implement the get params API for a block cipher. */
#define IMPLEMENT_AES_WRAP_PAD_GET_PARAMS(lcmode, UCMODE, kBits, ivBits)       \
/**                                                                            \
 * Get the values from the AES wrap context for the parameters.                \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_aes_##kBits##_##lcmode##_get_params(OSSL_PARAM params[])         \
{                                                                              \
    return wp_aes_wrap_pad_get_params(params, EVP_CIPH_##UCMODE##_MODE, kBits, \
        ivBits);                                                               \
}
#if 1
/** Implement the new context API for a block cipher. */
#define IMPLEMENT_AES_WRAP_PAD_NEWCTX(lcmode, UCMODE, kBits, ivBits)           \
/**                                                                            \
 * Create a new block cipher context object.                                   \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AEAD context object on success.                                    \
 */                                                                            \
static wp_AesWrapPadCtx* wp_aes_wrap_pad_##kBits##_##lcmode##_newctx(          \
    WOLFPROV_CTX *provCtx)                                                     \
{                                                                              \
    wp_AesWrapPadCtx *ctx = NULL;                                              \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        wp_aes_wrap_pad_init_ctx(ctx, kBits, ivBits);                          \
    }                                                                          \
    return ctx;                                                                \
}
#endif


/** Implement the dispatch table for a block cipher. */
#define IMPLEMENT_AES_WRAP_PAD_DISPATCH(fname, kBits, ivBits)                       \
const OSSL_DISPATCH wp_aes##kBits##fname##pad_functions[] = {                       \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                      \
                               (DFUNC)wp_aes_wrap_pad_##kBits##_##fname##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX, (DFUNC)wp_aes_wrap_pad_freectx },                   \
    { OSSL_FUNC_CIPHER_DUPCTX, (DFUNC)wp_aes_wrap_pad_dupctx },                     \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (DFUNC)wp_aes_wrap_pad_einit },                \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (DFUNC)wp_aes_wrap_pad_dinit },                \
    { OSSL_FUNC_CIPHER_UPDATE, (DFUNC)wp_aes_wrap_pad_update },                     \
    { OSSL_FUNC_CIPHER_FINAL, (DFUNC)wp_aes_wrap_pad_final },                       \
    { OSSL_FUNC_CIPHER_GET_PARAMS, (DFUNC)wp_aes_##kBits##_##fname##_get_params },  \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (DFUNC)wp_aes_wrap_pad_get_ctx_params },     \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (DFUNC)wp_aes_wrap_pad_set_ctx_params },     \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_aes_wrap_pad_gettable_params },   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                         \
                                    (DFUNC)wp_aes_wrap_pad_gettable_ctx_params },   \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                         \
                                    (DFUNC)wp_aes_wrap_pad_settable_ctx_params },   \
    { 0, NULL }                                                                     \
};


/** Implements the functions calling base functions for a block cipher. */
#define IMPLEMENT_AES_WRAP_PAD(lcmode, fname, UCMODE, kBits, ivBits)               \
IMPLEMENT_AES_WRAP_PAD_GET_PARAMS(fname, UCMODE, kBits, ivBits)                    \
IMPLEMENT_AES_WRAP_PAD_NEWCTX(fname, UCMODE, kBits, ivBits)                        \
IMPLEMENT_AES_WRAP_PAD_DISPATCH(fname, kBits, ivBits)

/*
 * AES Key Wrap padded
 */
#if 1
/** wp_aes256wrappad_functions */
IMPLEMENT_AES_WRAP_PAD(wrap, wrap, WRAP, 256, 128)
/** wp_aes192wrappad_functions */
IMPLEMENT_AES_WRAP_PAD(wrap, wrap, WRAP, 192, 128)
/** wp_aes128wrappad_functions */
IMPLEMENT_AES_WRAP_PAD(wrap, wrap, WRAP, 128, 128)
#endif

#endif