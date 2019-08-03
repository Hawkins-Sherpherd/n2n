#ifdef N2N_HAVE_AES

#include "aes.h"

/* Return the best acceptable AES key size (in bytes) given an input keysize. 
 *
 * The value returned will be one of AES128_KEY_BYTES, AES192_KEY_BYTES or
 * AES256_KEY_BYTES.
 */
#if USE_OPENSSL
static const EVP_CIPHER* n2n_aes_best_keysize(size_t numBytes)
{
    if (numBytes >= AES256_KEY_BYTES )
    {
        return EVP_aes_256_cbc();
    }
    else if (numBytes >= AES192_KEY_BYTES)
    {
        return EVP_aes_192_cbc();
    }
    else
    {
        return EVP_aes_128_cbc();
    }
}
#elif USE_GCRYPT
static int n2n_aes_best_keysize(size_t numBytes) {
    if (numBytes >= AES256_KEY_BYTES )
    {
        return GCRY_CIPHER_AES256;
    }
    else if (numBytes >= AES192_KEY_BYTES)
    {
        return GCRY_CIPHER_AES192;
    }
    else
    {
        return GCRY_CIPHER_AES128;
    }
}
#elif USE_BCRYPT || USE_NETTLE || USE_MBEDTLS || USE_ELL
static uint32_t n2n_aes_best_keysize(size_t numBytes) {
    if (numBytes >= AES256_KEY_BYTES )
    {
        return 32;
    }
    else if (numBytes >= AES192_KEY_BYTES)
    {
        return 24;
    }
    else
    {
        return 16;
    }
}
#endif

void n2n_aes_init(cipher_ctx_t ctx) {
#if USE_OPENSSL
    memset(ctx->key, 0, sizeof(ctx->key));
    ctx->ctx = EVP_CIPHER_CTX_new();
#elif USE_NETTLE
#elif USE_GCRYPT
    ctx->cipher = NULL;
#elif USE_MBEDTLS
    mbedtls_cipher_init( &ctx->enc_ctx );
    mbedtls_cipher_init( &ctx->dec_ctx );
#elif USE_ELL
    ctx->cipher = NULL;
#elif USE_BCRYPT
    BCryptOpenAlgorithmProvider ( &ctx->hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0 );
    BCryptSetProperty ( ctx->hAlgorithm, BCRYPT_CHAINING_MODE,
                        (uint8_t*) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0 );
    ctx->hKey = NULL;
#endif
}

void n2n_aes_free(cipher_ctx_t ctx) {
#if USE_OPENSSL
    EVP_CIPHER_CTX_free( ctx->ctx );
#elif USE_GCRYPT
    if (ctx->cipher)
        gcry_cipher_close( ctx->cipher );
#elif USE_MBEDTLS
    mbedtls_cipher_free( &ctx->enc_ctx );
    mbedtls_cipher_free( &ctx->dec_ctx );
#elif USE_ELL
    if ( ctx->cipher )
        l_cipher_free( ctx->cipher );
#elif USE_BCRYPT
    if ( ctx->hKey )
        BCryptDestroyKey( ctx->hKey );
    BCryptCloseAlgorithmProvider( ctx->hAlgorithm, 0 );
#endif
}

uint8_t n2n_aes_set_key(cipher_ctx_t ctx, const uint8_t* key, size_t length) {
#if USE_OPENSSL
    ctx->cipher = n2n_aes_best_keysize(length);
    unsigned int key_length = EVP_CIPHER_key_length(ctx->cipher);
    memcpy(ctx->key, key, key_length);
#elif USE_NETTLE
    uint32_t key_length = n2n_aes_best_keysize(length);
    switch (key_length) {
    case 32:
        aes256_set_encrypt_key((struct aes256_ctx*) &ctx->enc_ctx, key);
        aes256_set_decrypt_key((struct aes256_ctx*) &ctx->dec_ctx, key);
        ctx->enc_fun = (nettle_cipher_func*) aes256_encrypt;
        ctx->dec_fun = (nettle_cipher_func*) aes256_decrypt;
        break;
    case 24:
        aes192_set_encrypt_key((struct aes192_ctx*) &ctx->enc_ctx, key);
        aes192_set_decrypt_key((struct aes192_ctx*) &ctx->dec_ctx, key);
        ctx->enc_fun = (nettle_cipher_func*) aes192_encrypt;
        ctx->dec_fun = (nettle_cipher_func*) aes192_decrypt;
        break;
    case 16:
        aes128_set_encrypt_key((struct aes128_ctx*)  &ctx->enc_ctx, key);
        aes128_set_decrypt_key((struct aes128_ctx*) &ctx->dec_ctx, key);
        ctx->enc_fun = (nettle_cipher_func*) aes128_encrypt;
        ctx->dec_fun = (nettle_cipher_func*) aes128_decrypt;
        break;
    default:
        break;
    }
#elif USE_GCRYPT
    if (ctx->cipher)
        gcry_cipher_close( ctx->cipher );
    int _algo = n2n_aes_best_keysize(length);
    unsigned int key_length = gcry_cipher_get_algo_keylen ( _algo );
    gcry_cipher_open ( &ctx->cipher, _algo, GCRY_CIPHER_MODE_CBC, 0 );
    gcry_cipher_setkey ( ctx->cipher, key, key_length );
#elif USE_MBEDTLS
    uint32_t key_length = n2n_aes_best_keysize(length);
    const mbedtls_cipher_info_t* _algo = mbedtls_cipher_info_from_values(
        MBEDTLS_CIPHER_ID_AES, (int) key_length, MBEDTLS_MODE_CBC);
    mbedtls_cipher_reset( &ctx->enc_ctx );
    mbedtls_cipher_setup( &ctx->enc_ctx, _algo );
    mbedtls_cipher_setkey( &ctx->enc_ctx, key, (int) key_length, MBEDTLS_ENCRYPT );
    mbedtls_cipher_set_padding_mode( &ctx->enc_ctx, MBEDTLS_PADDING_NONE );
    mbedtls_cipher_reset( &ctx->dec_ctx );
    mbedtls_cipher_setup( &ctx->dec_ctx, _algo );
    mbedtls_cipher_setkey( &ctx->dec_ctx, key, (int) key_length, MBEDTLS_DECRYPT );
    mbedtls_cipher_set_padding_mode( &ctx->dec_ctx, MBEDTLS_PADDING_NONE );
#elif USE_ELL
    uint32_t key_length = n2n_aes_best_keysize(length);
    ctx->cipher = l_cipher_new( L_CIPHER_AES_CBC, key, key_length );
#elif USE_BCRYPT
    if (ctx->hKey != NULL)
        BCryptDestroyKey ( ctx->hKey );
    uint32_t key_length = n2n_aes_best_keysize(length) * 8;
    BCryptSetProperty( ctx->hAlgorithm, BCRYPT_KEY_LENGTH, (uint8_t*) &key_length, sizeof(uint32_t), 0 );
    key_length /= 8;
    BCryptGenerateSymmetricKey( ctx->hAlgorithm, &ctx->hKey, NULL, 0, (uint8_t*) key, key_length, 0 );
#endif
    return key_length;
}

void n2n_aes_encrypt(cipher_ctx_t ctx, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t length) {
#if USE_OPENSSL
    int res_length = -1;
    EVP_CIPHER_CTX_reset( ctx->ctx );
    EVP_EncryptInit( ctx->ctx, ctx->cipher, ctx->key, iv );
    EVP_CIPHER_CTX_set_padding( ctx->ctx, 0 );
    EVP_EncryptUpdate( ctx->ctx, out, &res_length, in, length );
    EVP_EncryptFinal( ctx->ctx, out + res_length, &res_length );
#elif USE_NETTLE
    cbc_encrypt(&ctx->enc_ctx, (nettle_cipher_func*) ctx->enc_fun, AES_BLOCK_SIZE, (uint8_t*) iv, length, out, in);
#elif USE_GCRYPT
    gcry_cipher_reset( ctx->cipher );
    gcry_cipher_setiv( ctx->cipher, iv, AES_BLOCK_SIZE );
    gcry_cipher_encrypt( ctx->cipher, out, length, in, length );
#elif USE_MBEDTLS
    size_t res_length = res_length;
    mbedtls_cipher_crypt( &ctx->enc_ctx, iv, AES_BLOCK_SIZE, in, length, out, &res_length );
#elif USE_ELL
    l_cipher_set_iv( ctx->cipher, iv, AES_BLOCK_SIZE );
    l_cipher_encrypt( ctx->cipher, in, out, length );
#elif USE_BCRYPT
    uint32_t res_length = length;
    BCryptEncrypt( ctx->hKey, (uint8_t*) in, (uint32_t) length, NULL, (uint8_t*) iv, AES_BLOCK_SIZE, out, res_length, &res_length, 0 );
#endif
}

void n2n_aes_decrypt(cipher_ctx_t ctx, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t length) {
#if USE_OPENSSL
    int res_length = -1;
    EVP_CIPHER_CTX_reset(ctx->ctx);
    EVP_DecryptInit( ctx->ctx, ctx->cipher, ctx->key, iv);
    EVP_CIPHER_CTX_set_padding(ctx->ctx, 0);
    EVP_DecryptUpdate( ctx->ctx, out, &res_length, in, length );
    EVP_DecryptFinal( ctx->ctx, out + res_length, &res_length );
#elif USE_NETTLE
    cbc_decrypt(&ctx->dec_ctx, (nettle_cipher_func*) ctx->dec_fun, AES_BLOCK_SIZE, (uint8_t*) iv, length, out, in);
#elif USE_GCRYPT
    gcry_cipher_reset( ctx->cipher );
    gcry_cipher_setiv( ctx->cipher, iv, AES_BLOCK_SIZE );
    gcry_cipher_decrypt( ctx->cipher, out, length, in, length );
#elif USE_MBEDTLS
    size_t res_length = 0;
    mbedtls_cipher_crypt( &ctx->dec_ctx, iv, AES_BLOCK_SIZE, in, length, out, &res_length );
#elif USE_ELL
    l_cipher_set_iv( ctx->cipher, iv, AES_BLOCK_SIZE );
    l_cipher_decrypt( ctx->cipher, in, out, length );
#elif USE_BCRYPT
    uint32_t res_length = length;
    BCryptDecrypt( ctx->hKey, (uint8_t*) in, (uint32_t) length, NULL, (uint8_t*) iv, AES_BLOCK_SIZE,out, res_length, &res_length, 0 );
#endif
}

#endif // N2N_HAVE_AES
