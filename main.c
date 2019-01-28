#include "argon2/argon2.h"
#include "hc256/hc256.h"
#include "skein3fish/skeinApi.h"
#include "skein3fish/threefishApi.h"
#include "randombytes/randombytes.h"

#define ZPL_IMPLEMENTATION
#include "zpl.h"

#define KEY_LEN 256UL
#define HEADER_LEN 6UL
#define TWEAK_LEN 16UL
#define SALT_LEN 32UL
#define HC256_LEN 64UL
#define T3F_KEY_LEN 128UL
#define T3F_BLOCK_LEN 128UL
#define NUM_BLOCKS 1024UL
#define CHUNK_LEN (T3F_BLOCK_LEN * NUM_BLOCKS)
#define SKEIN_MAC_LEN 64UL
#define ENC_KEY_LEN (HC256_LEN + T3F_KEY_LEN + TWEAK_LEN + SKEIN_MAC_LEN)

// number of passes
#define T 8U
// memory usage
#define M (1 << 18)
// number of threads and lanes
#define P 1U

static uint8_t key[KEY_LEN];
static uint8_t header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

void check_fatal_err(int cond, char *msg) {
    if (cond) {
        fprintf(stderr, "Error: %s\n", msg);
        exit(-1);
    }
}

void get_key_from_file(const char *key_file, uint8_t *key) {
    zpl_file f = {0};
    zplFileError rc = zpl_file_open(&f, key_file);
    check_fatal_err(rc != ZPL_FILE_ERROR_NONE, "cannot open file.");
    check_fatal_err(zpl_file_size(&f) != KEY_LEN,
                    "key file must have exactly 256 bytes.");
    check_fatal_err(zpl_file_read(&f, key, KEY_LEN) != 1,
                    "cannot read key from file.");
    zpl_file_close(&f);
}

void *t3fc_malloc(size_t s) {
    void *buf = malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

void encrypt(zpl_file *input, zpl_file *output, uint8_t *key);
void encrypt_chunk(unsigned char *chunk, size_t nread, zpl_file *input,
                   zpl_file *output, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, size_t total_bytes_read);
void decrypt(zpl_file *input, zpl_file *output, uint8_t *key);
void decrypt_chunk(unsigned char *chunk, size_t nread, zpl_file *input,
                   zpl_file *output, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, size_t total_bytes_read);
void prepare(uint8_t *enc_key, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
             SkeinCtx_t *skein_x);

int main(int argc, char *argv[]) {

    if (argc == 3 && strcmp(argv[1], "-mk") == 0) {
        randombytes(key, KEY_LEN);
        zpl_file f = {0};
        zplFileError rc = zpl_file_create(&f, argv[2]);
        check_fatal_err(rc != ZPL_FILE_ERROR_NONE, "cannot create file.");
        check_fatal_err(zpl_file_write(&f, key, KEY_LEN) != 1,
                    "cannot write key to file.");
        zpl_file_close(&    f);

    } else if (argc == 8 &&
               (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
               strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
               strcmp(argv[6], "-o") == 0) {

        get_key_from_file(argv[3], key);
        if (zpl_file_exists(argv[7])) {
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
        zpl_file input = {0};
        zpl_file output = {0};
        zplFileError rc = zpl_file_open(&input, argv[5]);
        check_fatal_err(rc != ZPL_FILE_ERROR_NONE, "cannot open file.");
        rc = zpl_file_create(&output, argv[7]);
        check_fatal_err(rc != ZPL_FILE_ERROR_NONE, "cannot create file.");
        if (strcmp(argv[1], "-e") == 0) {
            encrypt(&input, &output, key);
        } else if (strcmp(argv[1], "-d") == 0) {
            decrypt(&input, &output, key);
        }
        zpl_file_close(&input);
        zpl_file_close(&output);

    } else {
        check_fatal_err(1, "unknown options.");
    }

    return EXIT_SUCCESS;
}

void prepare(uint8_t *enc_key, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
             SkeinCtx_t *skein_x) {

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

void encrypt(zpl_file *input, zpl_file *output, uint8_t *key) {

    isize bytes_written = HEADER_LEN;
    b32 rc = zpl_file_write_at_check(output, header, HEADER_LEN, 0, &bytes_written);
    check_fatal_err(rc != 1 || bytes_written != HEADER_LEN, "cannot write header.");
    uint8_t salt[SALT_LEN];
    randombytes(salt, SALT_LEN);
    rc = zpl_file_write_at_check(output, salt, SALT_LEN, HEADER_LEN, &bytes_written);
    check_fatal_err(rc != 1 || bytes_written != SALT_LEN, "cannot write salt.");

    uint8_t enc_key[ENC_KEY_LEN];
    check_fatal_err(argon2id_hash_raw(T, M, P, key, KEY_LEN, salt, SALT_LEN,
                                      enc_key, ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    hc256_ctx_t *hc256_ctx = t3fc_malloc(sizeof(hc256_ctx_t));
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, hc256_ctx, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t bytes_read = 0;
    size_t total_bytes_read = 0;
    while (1) {
        rc = zpl_file_read_at_check(input, chunk, CHUNK_LEN, total_bytes_read, &bytes_read);
        check_fatal_err(rc != 1, "cannot read input.");
        encrypt_chunk(chunk, bytes_read, input, output, hc256_ctx, t3f_x, skein_x, total_bytes_read);
        total_bytes_read += bytes_read;
        if (bytes_read < CHUNK_LEN) {
            break;
        }
    }

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    rc = zpl_file_write_at_check(output, hash, SKEIN_MAC_LEN, HEADER_LEN + SALT_LEN + total_bytes_read, &bytes_written);
    check_fatal_err(rc != 1 || bytes_written != SKEIN_MAC_LEN, "cannot write Skein MAC.");

    free(hc256_ctx);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void decrypt(zpl_file *input, zpl_file *output, uint8_t *key) {

    uint8_t in_header[HEADER_LEN];
    isize bytes_read = 0;
    b32 rc = zpl_file_read_at_check(input, in_header, HEADER_LEN, 0, &bytes_read);
    check_fatal_err(rc != 1 || bytes_read != HEADER_LEN, "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0,
                    "wrong header.");
    uint8_t salt[SALT_LEN];
    rc = zpl_file_read_at_check(input, salt, SALT_LEN, HEADER_LEN, &bytes_read);
    check_fatal_err(rc != 1 || bytes_read != SALT_LEN, "cannot read salt.");

    uint8_t enc_key[ENC_KEY_LEN];
    check_fatal_err(argon2id_hash_raw(T, M, P, key, KEY_LEN, salt, SALT_LEN,
                                      enc_key, ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    hc256_ctx_t *hc256_ctx = t3fc_malloc(sizeof(hc256_ctx_t));
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, hc256_ctx, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    size_t infile_len =
        zpl_file_size(input) - (HEADER_LEN + SALT_LEN + SKEIN_MAC_LEN);
    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t chunk_len = CHUNK_LEN;
    size_t num_read = infile_len / CHUNK_LEN + (infile_len % CHUNK_LEN != 0);
    size_t total_bytes_read = HEADER_LEN + SALT_LEN;
    for (size_t i = 0; i < num_read; ++i) {
        if (i == num_read - 1) {
            chunk_len = infile_len - i * CHUNK_LEN;
        }
        rc = zpl_file_read_at_check(input, chunk, chunk_len, total_bytes_read, &bytes_read);
        check_fatal_err(rc != 1, "cannot read input.");
        decrypt_chunk(chunk, bytes_read, input, output, hc256_ctx, t3f_x,
                      skein_x, total_bytes_read - (HEADER_LEN + SALT_LEN));
        total_bytes_read += bytes_read;
    }

    rc = zpl_file_read_at_check(input, chunk, SKEIN_MAC_LEN, total_bytes_read, &bytes_read);
    check_fatal_err(rc != 1 || bytes_read != SKEIN_MAC_LEN, "cannot read input.");

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(memcmp(hash, chunk, SKEIN_MAC_LEN) != 0,
                    "wrong Skein MAC.");

    free(hc256_ctx);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void decrypt_chunk(unsigned char *chunk, size_t nread, zpl_file *input,
                   zpl_file *output, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, size_t total_bytes_read) {
    unsigned char tmp[T3F_BLOCK_LEN];
    unsigned char ctr[T3F_BLOCK_LEN];
    unsigned char tmp_out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    size_t in_len = nread;
    isize bytes_written = 0;
    isize offset = total_bytes_read;
    b32 rc = 0;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        rc = zpl_file_write_at_check(output, tmp_out, T3F_BLOCK_LEN, offset, &bytes_written);
        check_fatal_err(rc != 1 || bytes_written != T3F_BLOCK_LEN, "cannot write to file.");
        offset += T3F_BLOCK_LEN;
    }
    if (in_len > 0) {
        hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < in_len; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        rc = zpl_file_write_at_check(output, tmp_out, in_len, offset, &bytes_written);
        check_fatal_err(rc != 1 || bytes_written != in_len, "cannot write to file.");
    }
    skeinUpdate(skein_x, chunk, nread);
}

void encrypt_chunk(unsigned char *chunk, size_t nread, zpl_file *input,
                   zpl_file *output, hc256_ctx_t *hc256_ctx, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, size_t total_bytes_read) {
    unsigned char tmp[T3F_BLOCK_LEN];
    unsigned char ctr[T3F_BLOCK_LEN];
    unsigned char tmp_out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    isize bytes_written = 0;
    isize offset = HEADER_LEN + SALT_LEN + total_bytes_read;
    size_t in_len = nread;
    b32 rc = 0;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        skeinUpdate(skein_x, tmp_out, T3F_BLOCK_LEN);
        rc = zpl_file_write_at_check(output, tmp_out, T3F_BLOCK_LEN, offset, &bytes_written);
        check_fatal_err(rc != 1 || bytes_written != T3F_BLOCK_LEN, "cannot write to file.");
        offset += T3F_BLOCK_LEN;
    }
    if (in_len > 0) {
        hc256_gen_bytes(hc256_ctx, ctr, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr, tmp);
        for (uint32_t j = 0; j < in_len; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        skeinUpdate(skein_x, tmp_out, in_len);
        rc = zpl_file_write_at_check(output, tmp_out, in_len, offset, &bytes_written);
        check_fatal_err(rc != 1 || bytes_written != in_len, "cannot write to file.");
    }
}