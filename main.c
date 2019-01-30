#include <sodium.h>

#include "skein3fish/skeinApi.h"
#include "skein3fish/threefishApi.h"

#define STB_LIB_IMPLEMENTATION
#include "stb_lib.h"

#define MASTER_KEY_LEN 256UL
#define HEADER_LEN 6UL
#define T3F_TWEAK_LEN 16UL
#define SALT_LEN crypto_pwhash_SALTBYTES
#define X20_KEY_LEN 32UL
#define X20_HEADER_LEN 24UL
#define T3F_KEY_LEN 128UL
#define T3F_BLOCK_LEN 128UL
#define CTR_NONCE_LEN 128UL
#define NUM_BLOCKS 2048UL
#define CHUNK_LEN (T3F_BLOCK_LEN * NUM_BLOCKS)
#define SKEIN_MAC_LEN 64UL
#define ENC_KEY_LEN                                                            \
    (X20_KEY_LEN + X20_HEADER_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN +              \
     SKEIN_MAC_LEN + CTR_NONCE_LEN)

// number of passes
#define T 8U
// memory usage
#define M crypto_pwhash_MEMLIMIT_MODERATE
// number of threads and lanes
// #define P 1U

unsigned char header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

void check_fatal_err(int cond, char *msg) {
    if (cond) {
        fprintf(stderr, "Error: %s\n", msg);
        exit(-1);
    }
}

FILE *t3fc_fopen(const char *path, const char *flags) {
    FILE *f = stb__fopen(path, flags);
    check_fatal_err(f == NULL, "cannot open file.");
    return f;
}

void get_key_from_file(const char *key_file, unsigned char *key) {
    FILE *f = t3fc_fopen(key_file, "rb");
    check_fatal_err(stb_filelen(f) != MASTER_KEY_LEN,
                    "key file must have exactly 256 bytes.");
    check_fatal_err(fread(key, 1, MASTER_KEY_LEN, f) != MASTER_KEY_LEN,
                    "cannot read key from file.");
    fclose(f);
}

void *t3fc_sodium_malloc(size_t s) {
    void *buf = sodium_malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

void *t3fc_malloc(size_t s) {
    void *buf = malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

void encrypt(FILE *input, FILE *output, unsigned char *key);
void decrypt(FILE *input, FILE *output, unsigned char *key);
void prepare(unsigned char *enc_key,
             crypto_secretstream_xchacha20poly1305_state *x20_st,
             ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x, int enc);
void t3f_process_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *ctr_nonce);
unsigned char *make_enc_key(unsigned char *master_key, unsigned char *salt);

int main(int argc, char *argv[]) {

    check_fatal_err(sodium_init() < 0, "cannot initialize libsodium.");

    unsigned char *master_key = t3fc_sodium_malloc(MASTER_KEY_LEN);

    if (argc == 3 && strcmp(argv[1], "-mk") == 0) {
        randombytes_buf(master_key, MASTER_KEY_LEN);
        FILE *master_key_file = t3fc_fopen(argv[2], "wb");
        check_fatal_err(fwrite(master_key, 1, MASTER_KEY_LEN,
                               master_key_file) != MASTER_KEY_LEN,
                        "cannot write master key to file.");

    } else if (argc == 8 &&
               (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
               strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
               strcmp(argv[6], "-o") == 0) {

        get_key_from_file(argv[3], master_key);
        if (stb_fexists(argv[7])) {
            char yn;
            do {
                printf("File exists. Do you want to overwrite? (y/n) ");
                scanf("%s", &yn);
            } while (yn != 'n' && yn != 'N' && yn != 'y' && yn != 'Y');
            if (yn == 'n' || yn == 'N') {
                printf("Please choose a different output file.\n");
                return EXIT_SUCCESS;
            }
        }
        FILE *input = t3fc_fopen(argv[5], "rb");
        FILE *output = t3fc_fopen(argv[7], "wb");
        if (strcmp(argv[1], "-e") == 0) {
            encrypt(input, output, master_key);
        } else if (strcmp(argv[1], "-d") == 0) {
            decrypt(input, output, master_key);
        }
        fclose(input);
        fclose(output);

    } else {
        check_fatal_err(1, "unknown options.");
    }

    sodium_free(master_key);
    return EXIT_SUCCESS;
}

void prepare(unsigned char *enc_key,
             crypto_secretstream_xchacha20poly1305_state *x20_st,
             ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x, int enc) {
    if (enc == 1) {
        crypto_secretstream_xchacha20poly1305_init_push(
            x20_st, &enc_key[X20_KEY_LEN], enc_key);
    } else {
        check_fatal_err(crypto_secretstream_xchacha20poly1305_init_pull(
                            x20_st, &enc_key[X20_KEY_LEN], enc_key) != 0,
                        "cannot initialize to decrypt.");
    }
    threefishSetKey(
        t3f_x, Threefish1024,
        (uint64_t *)&enc_key[X20_KEY_LEN + X20_HEADER_LEN],
        (uint64_t *)&enc_key[X20_KEY_LEN + X20_HEADER_LEN + T3F_KEY_LEN]);
    skeinCtxPrepare(skein_x, Skein512);
    skeinMacInit(
        skein_x,
        &enc_key[X20_KEY_LEN + X20_HEADER_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN],
        SKEIN_MAC_LEN, Skein512);
}

unsigned char *make_enc_key(unsigned char *master_key, unsigned char *salt) {
    unsigned char *enc_key = t3fc_sodium_malloc(ENC_KEY_LEN);
    check_fatal_err(crypto_pwhash(enc_key, ENC_KEY_LEN, master_key,
                                  MASTER_KEY_LEN, salt, T, M,
                                  crypto_pwhash_ALG_ARGON2ID13) != 0,
                    "Argon2 failed.");
    return enc_key;
}

void encrypt(FILE *input, FILE *output, unsigned char *master_key) {

    assert(SALT_LEN == 32U);

    check_fatal_err(fwrite(header, 1, HEADER_LEN, output) != HEADER_LEN,
                    "cannot write header.");
    unsigned char salt[SALT_LEN];
    randombytes_buf(salt, SALT_LEN);
    check_fatal_err(fwrite(salt, 1, SALT_LEN, output) != SALT_LEN,
                    "cannot write salt.");

    unsigned char *enc_key = make_enc_key(master_key, salt);

    crypto_secretstream_xchacha20poly1305_state x20_st;
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, &x20_st, t3f_x, skein_x, 1);
    check_fatal_err(fwrite(&enc_key[X20_KEY_LEN], 1, X20_HEADER_LEN, output) !=
                        X20_HEADER_LEN,
                    "cannot write X20 header.");
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);
    skeinUpdate(skein_x, &enc_key[X20_KEY_LEN], X20_HEADER_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    unsigned char *x20_buf =
        t3fc_malloc(CHUNK_LEN + crypto_secretstream_xchacha20poly1305_ABYTES);
    size_t read_len = 0;
    int eof;
    unsigned char tag;
    unsigned char ctr_nonce[CTR_NONCE_LEN];
    memcpy(ctr_nonce,
           &enc_key[X20_KEY_LEN + X20_HEADER_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN +
                    SKEIN_MAC_LEN],
           CTR_NONCE_LEN);

    do {
        read_len = fread(chunk, 1, CHUNK_LEN, input);
        check_fatal_err(read_len != CHUNK_LEN && ferror(input),
                        "cannot read input.");
        eof = feof(input);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        t3f_process_chunk(t3f_x, chunk, read_len, ctr_nonce);

        size_t x20_buf_len =
            read_len + crypto_secretstream_xchacha20poly1305_ABYTES;
        crypto_secretstream_xchacha20poly1305_push(
            &x20_st, x20_buf, NULL, chunk, read_len, NULL, 0, tag);
        skeinUpdate(skein_x, x20_buf, x20_buf_len);
        check_fatal_err(fwrite(x20_buf, 1, x20_buf_len, output) != x20_buf_len,
                        "cannot write to file.");
    } while (!eof);

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(fwrite(hash, 1, SKEIN_MAC_LEN, output) != SKEIN_MAC_LEN,
                    "cannot write Skein MAC.");

    sodium_free(enc_key);
    free(x20_buf);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void decrypt(FILE *input, FILE *output, unsigned char *master_key) {

    assert(SALT_LEN == 32U);

    unsigned char in_header[HEADER_LEN];
    check_fatal_err(fread(in_header, 1, HEADER_LEN, input) != HEADER_LEN,
                    "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0,
                    "wrong header.");
    unsigned char salt[SALT_LEN];
    check_fatal_err(fread(salt, 1, SALT_LEN, input) != SALT_LEN,
                    "cannot read salt.");
    unsigned char x20_header[X20_HEADER_LEN];
    check_fatal_err(fread(x20_header, 1, X20_HEADER_LEN, input) !=
                        X20_HEADER_LEN,
                    "cannot read X20 header.");

    unsigned char *enc_key = make_enc_key(master_key, salt);

    crypto_secretstream_xchacha20poly1305_state x20_st;
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    memcpy(&enc_key[X20_KEY_LEN], x20_header, X20_HEADER_LEN);
    prepare(enc_key, &x20_st, t3f_x, skein_x, 0);
    skeinUpdate(skein_x, in_header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);
    skeinUpdate(skein_x, x20_header, X20_HEADER_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    unsigned long long chunk_len;
    size_t x20_buf_len =
        CHUNK_LEN + crypto_secretstream_xchacha20poly1305_ABYTES;
    unsigned char *x20_buf_in = t3fc_malloc(x20_buf_len);
    size_t read_len = 0;
    int eof;
    unsigned char tag;
    unsigned char ctr_nonce[CTR_NONCE_LEN];
    memcpy(ctr_nonce,
           &enc_key[X20_KEY_LEN + X20_HEADER_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN +
                    SKEIN_MAC_LEN],
           CTR_NONCE_LEN);

    do {
        read_len = fread(x20_buf_in, 1, x20_buf_len, input);
        check_fatal_err(read_len != x20_buf_len && ferror(input),
                        "cannot read input.");
        eof = feof(input);
        if (eof && read_len > SKEIN_MAC_LEN) {
            read_len -= SKEIN_MAC_LEN;
        } else if (read_len == SKEIN_MAC_LEN) {
            read_len = 0;
            break;
        }
        check_fatal_err(crypto_secretstream_xchacha20poly1305_pull(
                            &x20_st, chunk, &chunk_len, &tag, x20_buf_in,
                            read_len, NULL, 0) != 0,
                        "corrupted chunk.");
        skeinUpdate(skein_x, x20_buf_in, read_len);
        check_fatal_err(
            tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof,
            "premature end (end of file reached before the end of the "
            "stream).");

        t3f_process_chunk(t3f_x, chunk, chunk_len, ctr_nonce);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len,
                        "cannot write to file.");
    } while (!eof);

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(memcmp(hash, &x20_buf_in[read_len], SKEIN_MAC_LEN) != 0,
                    "wrong Skein MAC.");

    sodium_free(enc_key);
    free(t3f_x);
    free(x20_buf_in);
    free(chunk);
    free(skein_x);
}

void t3f_process_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *ctr_nonce) {
    uint32_t i = 0;
    size_t in_len = chunk_len;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        threefishEncryptBlockBytes(t3f_x, ctr_nonce, ctr_nonce);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                ctr_nonce[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
    }
    if (in_len > 0) {
        threefishEncryptBlockBytes(t3f_x, ctr_nonce, ctr_nonce);
        for (uint32_t j = 0; j < in_len; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                ctr_nonce[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
    }
}