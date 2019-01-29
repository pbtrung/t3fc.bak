#include "argon2/argon2.h"
#include "hc256/hc256_opt32.h"
#include "randombytes/randombytes.h"
#include "skein3fish/skeinApi.h"
#include "skein3fish/threefishApi.h"

#define STB_LIB_IMPLEMENTATION
#include "stb_lib.h"

#define MASTER_KEY_LEN 256UL
#define HEADER_LEN 6UL
#define T3F_TWEAK_LEN 16UL
#define SALT_LEN 32UL
#define HC256_KEY_LEN 32UL
#define HC256_IV_LEN 32UL
#define HC256_KIV_LEN (HC256_KEY_LEN + HC256_IV_LEN)
#define T3F_KEY_LEN 128UL
#define T3F_BLOCK_LEN 128UL
#define CTR_NONCE_LEN 128UL
#define NUM_BLOCKS 2048UL
#define CHUNK_LEN (T3F_BLOCK_LEN * NUM_BLOCKS)
#define SKEIN_MAC_LEN 64UL
#define ENC_KEY_LEN (HC256_KIV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN + SKEIN_MAC_LEN + CTR_NONCE_LEN)

// number of passes
#define T 8U
// memory usage
#define M (1 << 18)
// number of threads and lanes
#define P 1U

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

void *t3fc_malloc(size_t s) {
    void *buf = malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

void encrypt(FILE *input, FILE *output, unsigned char *key);
void encrypt_chunk(unsigned char *chunk, size_t chunk_len, FILE *input,
                   FILE *output, HC256_State *hc256_st, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, unsigned char *ctr_nonce);
void decrypt(FILE *input, FILE *output, unsigned char *key);
void decrypt_chunk(unsigned char *chunk, size_t chunk_len, FILE *input,
                   FILE *output, HC256_State *hc256_st, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, unsigned char *ctr_nonce);
void prepare(unsigned char *enc_key, HC256_State *hc256_st,
             ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x);

int main(int argc, char *argv[]) {

    unsigned char master_key[MASTER_KEY_LEN];

    if (argc == 3 && strcmp(argv[1], "-mk") == 0) {
        randombytes(master_key, MASTER_KEY_LEN);
        FILE *master_key_file = t3fc_fopen(argv[2], "wb");
        check_fatal_err(fwrite(master_key, 1, MASTER_KEY_LEN, master_key_file) != MASTER_KEY_LEN,
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

    return EXIT_SUCCESS;
}

void prepare(unsigned char *enc_key, HC256_State *hc256_st,
             ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x) {

    Initialization(hc256_st, enc_key, &enc_key[HC256_KEY_LEN]);

    unsigned char t3f_key[T3F_KEY_LEN];
    unsigned char t3f_tweak[T3F_TWEAK_LEN];
    memcpy(t3f_key, &enc_key[HC256_KIV_LEN], T3F_KEY_LEN);
    memcpy(t3f_tweak, &enc_key[HC256_KIV_LEN + T3F_KEY_LEN], T3F_TWEAK_LEN);
    threefishSetKey(t3f_x, Threefish1024, (uint64_t *)t3f_key,
                    (uint64_t *)t3f_tweak);

    skeinCtxPrepare(skein_x, Skein512);
    unsigned char skein_mac_key[SKEIN_MAC_LEN];
    memcpy(skein_mac_key, &enc_key[HC256_KIV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN],
           SKEIN_MAC_LEN);
    skeinMacInit(skein_x, skein_mac_key, SKEIN_MAC_LEN, Skein512);
}

void encrypt(FILE *input, FILE *output, unsigned char *master_key) {

    check_fatal_err(fwrite(header, 1, HEADER_LEN, output) != HEADER_LEN,
                    "cannot write header.");
    unsigned char salt[SALT_LEN];
    randombytes(salt, SALT_LEN);
    check_fatal_err(fwrite(salt, 1, SALT_LEN, output) != SALT_LEN,
                    "cannot write salt.");

    unsigned char *enc_key = t3fc_malloc(ENC_KEY_LEN);
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt, SALT_LEN,
                                      enc_key, ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    HC256_State hc256_st = {0};
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, &hc256_st, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char ctr_nonce[CTR_NONCE_LEN];
    memcpy(ctr_nonce, &enc_key[HC256_KIV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN + SKEIN_MAC_LEN], CTR_NONCE_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t read_len = 0;
    while (1) {
        read_len = fread(chunk, 1, CHUNK_LEN, input);
        check_fatal_err(read_len != CHUNK_LEN && ferror(input),
                        "cannot read input.");
        encrypt_chunk(chunk, read_len, input, output, &hc256_st, t3f_x,
                      skein_x, ctr_nonce);
        if (read_len < CHUNK_LEN) {
            break;
        }
    }

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(fwrite(hash, 1, SKEIN_MAC_LEN, output) != SKEIN_MAC_LEN,
                    "cannot write Skein MAC.");

    free(enc_key);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void encrypt_chunk(unsigned char *chunk, size_t chunk_len, FILE *input,
                   FILE *output, HC256_State *hc256_st, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, unsigned char *ctr_nonce) {

    unsigned char tmp[T3F_BLOCK_LEN];
    unsigned char tmp_out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    size_t in_len = chunk_len;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        EncryptMessage(hc256_st, ctr_nonce, ctr_nonce, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr_nonce, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        skeinUpdate(skein_x, tmp_out, T3F_BLOCK_LEN);
        check_fatal_err(fwrite(tmp_out, 1, T3F_BLOCK_LEN, output) !=
                            T3F_BLOCK_LEN,
                        "cannot write to file.");
    }
    if (in_len > 0) {
        EncryptMessage(hc256_st, ctr_nonce, ctr_nonce, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr_nonce, tmp);
        for (uint32_t j = 0; j < in_len; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        skeinUpdate(skein_x, tmp_out, in_len);
        check_fatal_err(fwrite(tmp_out, 1, in_len, output) != in_len,
                        "cannot write to file.");
    }
}

void decrypt(FILE *input, FILE *output, unsigned char *master_key) {

    unsigned char in_header[HEADER_LEN];
    check_fatal_err(fread(in_header, 1, HEADER_LEN, input) != HEADER_LEN,
                    "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0,
                    "wrong header.");
    unsigned char salt[SALT_LEN];
    check_fatal_err(fread(salt, 1, SALT_LEN, input) != SALT_LEN,
                    "cannot read salt.");

    unsigned char *enc_key = t3fc_malloc(ENC_KEY_LEN);
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt, SALT_LEN,
                                      enc_key, ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    HC256_State hc256_st = {0};
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, &hc256_st, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char ctr_nonce[CTR_NONCE_LEN];
    memcpy(ctr_nonce, &enc_key[HC256_KIV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN + SKEIN_MAC_LEN], CTR_NONCE_LEN);

    size_t infile_len =
        stb_filelen(input) - (HEADER_LEN + SALT_LEN + SKEIN_MAC_LEN);
    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t read_len = 0;
    size_t chunk_len = CHUNK_LEN;
    size_t num_read = infile_len / CHUNK_LEN + (infile_len % CHUNK_LEN != 0);
    for (size_t i = 0; i < num_read; ++i) {
        if (i == num_read - 1) {
            chunk_len = infile_len - i * CHUNK_LEN;
        }
        read_len = fread(chunk, 1, chunk_len, input);
        check_fatal_err(read_len != chunk_len && ferror(input),
                        "cannot read input.");
        decrypt_chunk(chunk, read_len, input, output, &hc256_st, t3f_x,
                      skein_x, ctr_nonce);
    }

    read_len = fread(chunk, 1, SKEIN_MAC_LEN, input);
    check_fatal_err(read_len != SKEIN_MAC_LEN && ferror(input),
                    "cannot read input.");
    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(memcmp(hash, chunk, SKEIN_MAC_LEN) != 0,
                    "wrong Skein MAC.");

    free(enc_key);
    free(t3f_x);
    free(chunk);
    free(skein_x);
}

void decrypt_chunk(unsigned char *chunk, size_t chunk_len, FILE *input,
                   FILE *output, HC256_State *hc256_st, ThreefishKey_t *t3f_x,
                   SkeinCtx_t *skein_x, unsigned char *ctr_nonce) {

    unsigned char tmp[T3F_BLOCK_LEN];
    unsigned char tmp_out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    size_t in_len = chunk_len;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
        EncryptMessage(hc256_st, ctr_nonce, ctr_nonce, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr_nonce, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        check_fatal_err(fwrite(tmp_out, 1, T3F_BLOCK_LEN, output) !=
                            T3F_BLOCK_LEN,
                        "cannot write to file.");
    }
    if (in_len > 0) {
        EncryptMessage(hc256_st, ctr_nonce, ctr_nonce, T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, ctr_nonce, tmp);
        for (uint32_t j = 0; j < in_len; ++j) {
            tmp_out[j] = tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        check_fatal_err(fwrite(tmp_out, 1, in_len, output) != in_len,
                        "cannot write to file.");
    }
    skeinUpdate(skein_x, chunk, chunk_len);
}