#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "argon2/argon2.h"
#include "hc256/hc256.h"
#include "skein3fish/skeinApi.h"
#include "skein3fish/threefishApi.h"

#define KEY_LEN 128UL
#define HEADER_LEN 6UL
#define TWEAK_LEN 16UL
#define SALT_LEN 32UL
#define HC256_LEN 64UL
#define T3F_KEY_LEN 128UL
#define T3F_BLOCK_LEN 128UL
#define CHUNK_LEN (T3F_BLOCK_LEN * 1024)
#define SKEIN_MAC_LEN 64UL
#define ENC_KEY_LEN (HC256_LEN + T3F_KEY_LEN + TWEAK_LEN + SKEIN_MAC_LEN)

static uint8_t key[KEY_LEN];
static uint8_t header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

static void check_fatal_err(int cond, char *msg) {
    if (cond) {
        fprintf(stderr, "Error: %s\n", msg);
        exit(-1);
    }
}

static void get_key_from_file(const char *key_file, uint8_t *key) {
    FILE *f = fopen(key_file, "rb");
    check_fatal_err(f == NULL, "cannot open file.");
    check_fatal_err(fread(key, 1, KEY_LEN, f) != KEY_LEN,
                    "cannot read key from file.");
    fclose(f);
}

void *t3fc_malloc(size_t s);
void encrypt(FILE *input, FILE *output, uint8_t *key);
void encrypt_chunk(unsigned char *chunk, size_t nread, FILE *input,
                        FILE *output, hc256_ctx_t *hc256_ctx,
                        ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x);
void t3f_encrypt(unsigned char *chunk, size_t nread, FILE *output,
                 hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                 SkeinCtx_t *skein_x);

void decrypt(FILE *input, FILE *output, uint8_t *key);
void decrypt_chunk(unsigned char *chunk, size_t nread, FILE *input,
                        FILE *output, hc256_ctx_t *hc256_ctx,
                        ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x);
void t3f_decrypt(unsigned char *chunk, size_t nread, FILE *output,
                 hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                 SkeinCtx_t *skein_x, int eof);
void prepare(uint8_t *enc_key, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x);

int main(int argc, char *argv[]) {

    check_fatal_err(sodium_init() < 0, "cannot initialize libsodium.");

    if (argc == 2 && strcmp(argv[1], "-mk") == 0) {
        randombytes_buf(key, KEY_LEN);
        check_fatal_err(fwrite(key, 1, KEY_LEN, stdout) != KEY_LEN,
                        "cannot write key to file.");
    } else if (argc == 4 && strcmp(argv[1], "-e") == 0 &&
               strcmp(argv[2], "-k") == 0) {
        get_key_from_file(argv[3], key);
        encrypt(stdin, stdout, key);
    } else if (argc == 4 && strcmp(argv[1], "-d") == 0 &&
               strcmp(argv[2], "-k") == 0) {
        get_key_from_file(argv[3], key);
        decrypt(stdin, stdout, key);
    } else {
        check_fatal_err(1, "unknown options.");
    }

    return EXIT_SUCCESS;
}

void *t3fc_malloc(size_t s) {
    void *buf = malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

void prepare(uint8_t *enc_key, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x) {
    
    uint8_t hc256_kiv[HC256_LEN];
    memcpy(hc256_kiv, enc_key, HC256_LEN);
    hc256_set_kiv(hc256_ctx, hc256_kiv);

    uint8_t t3f_key[T3F_KEY_LEN];
    uint8_t t3f_tweak[TWEAK_LEN];
    memcpy(t3f_key, &enc_key[HC256_LEN], T3F_KEY_LEN);
    memcpy(t3f_tweak, &enc_key[HC256_LEN + T3F_KEY_LEN], TWEAK_LEN);
    threefishSetKey(t3f_x, Threefish1024, (uint64_t *)t3f_key,
                    (uint64_t *)t3f_tweak);

    skeinCtxPrepare(skein_x, Skein512);
    uint8_t skein_mac_key[SKEIN_MAC_LEN];
    memcpy(skein_mac_key, &enc_key[HC256_LEN + T3F_KEY_LEN + TWEAK_LEN],
           SKEIN_MAC_LEN);
    skeinMacInit(skein_x, skein_mac_key, SKEIN_MAC_LEN, Skein512);
}

void encrypt(FILE *input, FILE *output, uint8_t *key) {

    check_fatal_err(fwrite(header, 1, HEADER_LEN, output) != HEADER_LEN,
                    "cannot write header.");
    uint8_t salt[SALT_LEN];
    randombytes_buf(salt, SALT_LEN);
    check_fatal_err(fwrite(salt, 1, SALT_LEN, output) != SALT_LEN,
                    "cannot write salt.");

    uint8_t enc_key[ENC_KEY_LEN];
    // n-pass computation
    // memory usage
    // number of threads and lanes p
    uint32_t t = 8;
    uint32_t m = 1 << 18;
    uint32_t p = 1;
    check_fatal_err(argon2id_hash_raw(t, m, p, key, KEY_LEN, salt, SALT_LEN,
                                      enc_key, ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    hc256_ctx_t *hc256_ctx = t3fc_malloc(sizeof(hc256_ctx_t));
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, hc256_ctx, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t nread = 0;
    size_t buf_padded_len = 0;
    while (1) {
        nread = fread(chunk, 1, CHUNK_LEN, input);
        check_fatal_err(nread != CHUNK_LEN && ferror(input), "cannot read input.");
        if (nread == 0) {
            break;
        } else if (nread < CHUNK_LEN) {
            check_fatal_err(sodium_pad(&buf_padded_len, chunk, nread, T3F_BLOCK_LEN, CHUNK_LEN) != 0, "cannot add padding.");
        }
        size_t chunk_len = (nread/T3F_BLOCK_LEN + (nread % T3F_BLOCK_LEN != 0)) * T3F_BLOCK_LEN;
        encrypt_chunk(chunk, chunk_len, input, output, hc256_ctx, t3f_x, skein_x);
    }
    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(fwrite(hash, 1, SKEIN_MAC_LEN, stdout) != SKEIN_MAC_LEN,
                    "cannot write Skein MAC.");

    free(hc256_ctx);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void decrypt(FILE *input, FILE *output, uint8_t *key) {

    uint8_t in_header[HEADER_LEN];
    check_fatal_err(fread(in_header, 1, HEADER_LEN, input) != HEADER_LEN,
                    "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0,
                    "wrong header.");
    uint8_t salt[SALT_LEN];
    check_fatal_err(fread(salt, 1, SALT_LEN, input) != SALT_LEN,
                    "cannot read salt.");

    uint8_t enc_key[ENC_KEY_LEN];
    // n-pass computation t
    // memory usage m
    // number of threads and lanes p
    uint32_t t = 8;
    uint32_t m = 1 << 18;
    uint32_t p = 1;
    check_fatal_err(argon2id_hash_raw(t, m, p, key, KEY_LEN, salt, SALT_LEN,
                                      enc_key, ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    hc256_ctx_t *hc256_ctx = t3fc_malloc(sizeof(hc256_ctx_t));
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, hc256_ctx, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t nread = 0;
    while (1) {
        nread = fread(chunk, 1, CHUNK_LEN, input);
        check_fatal_err(nread != CHUNK_LEN && ferror(input), "cannot read input.");
        if (nread < CHUNK_LEN && nread > SKEIN_MAC_LEN) {
            decrypt_chunk(chunk, nread - SKEIN_MAC_LEN, input, output, hc256_ctx, t3f_x, skein_x);
            break;
        } else if (nread == SKEIN_MAC_LEN) {
            break;
        }
        decrypt_chunk(chunk, nread, input, output, hc256_ctx, t3f_x, skein_x);
    }

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(
        memcmp(hash, &chunk[nread - SKEIN_MAC_LEN], SKEIN_MAC_LEN) != 0,
        "wrong Skein MAC.");

    free(hc256_ctx);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void decrypt_chunk(unsigned char *chunk, size_t nread, FILE *input,
                        FILE *output, hc256_ctx_t *hc256_ctx,
                        ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x) {
    unsigned char tmp[T3F_BLOCK_LEN];
    unsigned char ctr[T3F_BLOCK_LEN];
    unsigned char tmp_out[T3F_BLOCK_LEN];

    unsigned char *dec_chunk = t3fc_malloc(nread);
    uint32_t i = 0;
    uint32_t in_len = nread;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            dec_chunk[i * T3F_BLOCK_LEN + j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        skeinUpdate(skein_x, &chunk[i * T3F_BLOCK_LEN], T3F_BLOCK_LEN);
    }

    size_t out_len = nread;
    size_t buf_unpadded_len = 0;
    if (sodium_unpad(&buf_unpadded_len, dec_chunk, nread, T3F_BLOCK_LEN) == 0) {
        out_len = buf_unpadded_len;
    }
    check_fatal_err(fwrite(dec_chunk, 1, out_len, stdout) != out_len,
                    "cannot write to stdout.");
    free(dec_chunk);
    // if (in_len > 0) {
    //     hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
    //     threefishEncryptBlockBytes(t3f_x, ctr, tmp);
    //     for (uint32_t j = 0; j < in_len; ++j) {
    //         tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
    //     }
    //     skeinUpdate(skein_x, &chunk[i * T3F_BLOCK_LEN], in_len);
    //     check_fatal_err(fwrite(tmp_out, 1, in_len, stdout) != in_len,
    //                     "cannot write to stdout.");
    // }
}

void encrypt_chunk(unsigned char *chunk, size_t nread, FILE *input,
                        FILE *output, hc256_ctx_t *hc256_ctx,
                        ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x) {
    t3f_encrypt(chunk, nread, output, hc256_ctx, t3f_x, skein_x);
}

void t3f_encrypt(unsigned char *chunk, size_t nread, FILE *output,
                 hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                 SkeinCtx_t *skein_x) {
    unsigned char tmp[T3F_BLOCK_LEN];
    unsigned char ctr[T3F_BLOCK_LEN];
    unsigned char tmp_out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    uint32_t in_len = nread;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        skeinUpdate(skein_x, tmp_out, T3F_BLOCK_LEN);
        check_fatal_err(fwrite(tmp_out, 1, T3F_BLOCK_LEN, stdout) != T3F_BLOCK_LEN,
                        "cannot write to stdout.");
    }
    // if (in_len > 0) {
    //     hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
    //     threefishEncryptBlockBytes(t3f_x, ctr, tmp);
    //     for (uint32_t j = 0; j < in_len; ++j) {
    //         tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
    //     }
    //     skeinUpdate(skein_x, tmp_out, in_len);
    //     check_fatal_err(fwrite(tmp_out, 1, in_len, stdout) != in_len,
    //                     "cannot write to stdout.");
    // }
}