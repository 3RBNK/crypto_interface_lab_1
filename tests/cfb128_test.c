#include "crypto.h"

/* NIST SP 800-38A, F.3.13: AES-128 CFB128. Test every byte prefix too. */
static BYTE key[16] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static BYTE iv[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static BYTE plain[64] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
};
static BYTE cipher[64] = {
    0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,
    0xc8,0xa6,0x45,0x37,0xa0,0xb3,0xa9,0x3f,0xcd,0xe3,0xcd,0xad,0x9f,0x1c,0xe5,0x8b,
    0x26,0x75,0x1f,0x67,0xa3,0xcb,0xb1,0x40,0xb1,0x80,0x8c,0xf1,0x87,0xa4,0xf4,0xdf,
    0xc0,0x4b,0x05,0x35,0x7c,0x5d,0x1c,0x0e,0xea,0xc4,0xc6,0x6f,0x9f,0xf7,0xf2,0xe6
};

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL at line %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static BCRYPT_KEY_HANDLE make_key(BCRYPT_ALG_HANDLE alg, BYTE* raw, DWORD size) {
    BCRYPT_KEY_HANDLE handle = NULL;
    DWORD feedback_size = AES_BLOCK_SIZE;
    CHECK(NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &handle, NULL, 0, raw, size, 0)));
    CHECK(NT_SUCCESS(BCryptSetProperty(handle, BCRYPT_MESSAGE_BLOCK_LENGTH,
        (PUCHAR)&feedback_size, sizeof(feedback_size), 0)));
    return handle;
}

int main(void) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE handle;
    BYTE out[65], saved_iv[16];
    BYTE zero_tail[37] = { 1, 2, 3 }, zero_cipher[37], zero_result[37];
    BYTE *file_key = NULL, *file_iv = NULL, *file_cipher = NULL, *expected = NULL;
    DWORD key_size, iv_size, cipher_size, expected_size;
    BYTE* result;

    CHECK(NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)));
    CHECK(NT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0)));
    handle = make_key(alg, key, sizeof(key));
    memcpy(saved_iv, iv, sizeof(iv));
    for (DWORD n = 0; n <= sizeof(plain); ++n) {
        memset(out, 0xa5, sizeof(out));
        CHECK(NT_SUCCESS(crypt_cfb128(handle, plain, n, iv, out, 0)));
        CHECK(memcmp(out, cipher, n) == 0 && out[n] == 0xa5);
        memset(out, 0xa5, sizeof(out));
        CHECK(NT_SUCCESS(crypt_cfb128(handle, cipher, n, iv, out, 1)));
        CHECK(memcmp(out, plain, n) == 0 && out[n] == 0xa5);
        CHECK(memcmp(iv, saved_iv, sizeof(iv)) == 0);
    }
    /* Legitimate trailing zero bytes must not be stripped as padding. */
    CHECK(NT_SUCCESS(crypt_cfb128(handle, zero_tail, sizeof(zero_tail), iv, zero_cipher, 0)));
    CHECK(NT_SUCCESS(crypt_cfb128(handle, zero_cipher, sizeof(zero_cipher), iv, zero_result, 1)));
    CHECK(memcmp(zero_result, zero_tail, sizeof(zero_tail)) == 0);
    /* Rounding a DWORD_MAX-sized input must fail before accessing its data. */
    CHECK(!NT_SUCCESS(crypt_cfb128(handle, plain, (DWORD)-1, iv, out, 0)));
    CHECK(!NT_SUCCESS(crypt_cfb128(handle, cipher, (DWORD)-1, iv, out, 1)));
    BCryptDestroyKey(handle);

    /* Run from the repository root. All sample files are read-only. */
    CHECK(read_file("secret_key.bin", &file_key, &key_size));
    CHECK(read_file("enc_cfb_iv.bin", &file_iv, &iv_size));
    CHECK(read_file("enc_cfb.bin", &file_cipher, &cipher_size));
    CHECK(read_file("result2.txt", &expected, &expected_size));
    CHECK(iv_size == AES_BLOCK_SIZE && cipher_size == expected_size && cipher_size == 1864);
    result = (BYTE*)malloc(cipher_size);
    CHECK(result != NULL);
    handle = make_key(alg, file_key, key_size);
    CHECK(NT_SUCCESS(crypt_cfb128(handle, file_cipher, cipher_size, file_iv, result, 1)));
    CHECK(memcmp(result, expected, cipher_size) == 0);
    CHECK(NT_SUCCESS(crypt_cfb128(handle, expected, expected_size, file_iv, result, 0)));
    CHECK(memcmp(result, file_cipher, cipher_size) == 0);
    BCryptDestroyKey(handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    free(file_key);
    free(file_iv);
    free(file_cipher);
    free(expected);
    free(result);
    puts("PASS: NIST CFB128 prefixes 0..64, trailing zeros, length overflow and enc_cfb.bin");
    return 0;
}
