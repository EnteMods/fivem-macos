#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

struct DigestPart { const char* hex; size_t count; };
struct DigestVector {
    const char* algorithm;
    struct DigestPart parts[2];
    size_t part_count;
    const char* expected;
};
struct MacVector { const char* algorithm; const char* key; const char* input; const char* expected; };
struct CipherVector { const char* algorithm; const char* key; const char* iv; const char* plain; const char* cipher; };
#include "openssl-vectors.inc"

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode(const char* hex, unsigned char* output, size_t capacity)
{
    const size_t length = strlen(hex);
    if (length % 2 || length / 2 > capacity) return -1;
    for (size_t index = 0; index < length / 2; ++index) {
        int high = hex_value(hex[index * 2]), low = hex_value(hex[index * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        output[index] = (unsigned char)((high << 4) | low);
    }
    return (int)(length / 2);
}

static int digest_case(const struct DigestVector* vector)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char input[4096], expected[EVP_MAX_MD_SIZE], actual[EVP_MAX_MD_SIZE];
    unsigned int actual_size = 0;
    int result = 0;
    int expected_size = decode(vector->expected, expected, sizeof(expected));
    const EVP_MD* algorithm = EVP_get_digestbyname(vector->algorithm);
    if (!ctx || !algorithm || expected_size < 0 || !EVP_DigestInit_ex(ctx, algorithm, NULL)) goto done;
    for (size_t part = 0; part < vector->part_count; ++part) {
        int input_size = decode(vector->parts[part].hex, input, sizeof(input));
        if (input_size < 0) goto done;
        for (size_t count = 0; count < vector->parts[part].count; ++count)
            if (!EVP_DigestUpdate(ctx, input, (size_t)input_size)) goto done;
    }
    if (EVP_DigestFinal_ex(ctx, actual, &actual_size) && actual_size == (unsigned)expected_size &&
        !memcmp(actual, expected, actual_size)) result = 1;
done:
    EVP_MD_CTX_free(ctx);
    return result;
}

static int mac_case(const struct MacVector* vector)
{
    unsigned char key[512], input[4096], expected[EVP_MAX_MD_SIZE], actual[EVP_MAX_MD_SIZE];
    unsigned int actual_size = 0;
    int key_size = decode(vector->key, key, sizeof(key));
    int input_size = decode(vector->input, input, sizeof(input));
    int expected_size = decode(vector->expected, expected, sizeof(expected));
    const EVP_MD* algorithm = EVP_get_digestbyname(vector->algorithm);
    return key_size >= 0 && input_size >= 0 && expected_size >= 0 && algorithm &&
        HMAC(algorithm, key, key_size, input, (size_t)input_size, actual, &actual_size) &&
        actual_size == (unsigned)expected_size && !memcmp(actual, expected, actual_size);
}

static int cipher_case(const struct CipherVector* vector, int encrypt)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32], iv[16], input[4096], expected[4096], actual[4112];
    int actual_size = 0, final_size = 0, result = 0;
    int key_size = decode(vector->key, key, sizeof(key));
    int iv_size = decode(vector->iv, iv, sizeof(iv));
    int input_size = decode(encrypt ? vector->plain : vector->cipher, input, sizeof(input));
    int expected_size = decode(encrypt ? vector->cipher : vector->plain, expected, sizeof(expected));
    const EVP_CIPHER* algorithm = EVP_get_cipherbyname(vector->algorithm);
    if (!ctx || !algorithm || key_size < 0 || iv_size < 0 || input_size < 0 || expected_size < 0 ||
        key_size != EVP_CIPHER_key_length(algorithm) || iv_size != EVP_CIPHER_iv_length(algorithm) ||
        !EVP_CipherInit_ex(ctx, algorithm, NULL, key, iv_size ? iv : NULL, encrypt) ||
        !EVP_CIPHER_CTX_set_padding(ctx, 0)) goto done;
    if (EVP_CipherUpdate(ctx, actual, &actual_size, input, input_size) &&
        EVP_CipherFinal_ex(ctx, actual + actual_size, &final_size) &&
        actual_size + final_size == expected_size && !memcmp(actual, expected, (size_t)expected_size)) result = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int main(void)
{
    const size_t digest_count = sizeof(digest_vectors) / sizeof(digest_vectors[0]);
    const size_t mac_count = sizeof(mac_vectors) / sizeof(mac_vectors[0]);
    const size_t cipher_count = sizeof(cipher_vectors) / sizeof(cipher_vectors[0]);
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL))
        return 1;
    printf("OPENSSL_VERSION %s\n", OpenSSL_version(OPENSSL_VERSION));
    for (size_t index = 0; index < digest_count; ++index)
        if (!digest_case(digest_vectors + index)) {
            fprintf(stderr, "OPENSSL_KAT_FAIL digest=%zu algorithm=%s\n", index, digest_vectors[index].algorithm);
            ERR_print_errors_fp(stderr); return 1;
        }
    for (size_t index = 0; index < mac_count; ++index)
        if (!mac_case(mac_vectors + index)) {
            fprintf(stderr, "OPENSSL_KAT_FAIL hmac=%zu algorithm=%s\n", index, mac_vectors[index].algorithm);
            ERR_print_errors_fp(stderr); return 1;
        }
    for (size_t index = 0; index < cipher_count; ++index)
        for (int encrypt = 0; encrypt <= 1; ++encrypt)
            if (!cipher_case(cipher_vectors + index, encrypt)) {
                fprintf(stderr, "OPENSSL_KAT_FAIL cipher=%zu algorithm=%s encrypt=%d\n", index, cipher_vectors[index].algorithm, encrypt);
                ERR_print_errors_fp(stderr); return 1;
            }
    printf("OPENSSL_MAIN_KAT_OK digest=%zu hmac=%zu aes_encrypt=%zu aes_decrypt=%zu mt=1\n",
        digest_count, mac_count, cipher_count, cipher_count);
    return 0;
}
