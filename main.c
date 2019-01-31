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
#define T3F_KEY_LEN 128UL
#define T3F_BLOCK_LEN 128UL
#define T3F_IV_LEN 128UL
#define NUM_BLOCKS 2048UL
#define CHUNK_LEN (T3F_BLOCK_LEN * NUM_BLOCKS)
#define SKEIN_MAC_LEN 64UL
#define ENC_KEY_LEN                                                            \
    (HC256_KEY_LEN + HC256_IV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN +              \
     SKEIN_MAC_LEN + T3F_IV_LEN)

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
void t3f_encrypt_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *t3f_iv);
void decrypt(FILE *input, FILE *output, unsigned char *key);
void t3f_decrypt_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *t3f_iv);
void prepare(unsigned char *enc_key, HC256_State *hc256_st,
             ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x);
void t3f_process_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *t3f_iv);
unsigned char *make_enc_key(unsigned char *master_key, unsigned char *salt);

int main(int argc, char *argv[]) {

    unsigned char *master_key = t3fc_malloc(MASTER_KEY_LEN);

    if (argc == 3 && strcmp(argv[1], "-mk") == 0) {
        randombytes(master_key, MASTER_KEY_LEN);
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

    free(master_key);
    return EXIT_SUCCESS;
}

void prepare(unsigned char *enc_key, HC256_State *hc256_st,
             ThreefishKey_t *t3f_x, SkeinCtx_t *skein_x) {

    hc256_init(hc256_st, enc_key, &enc_key[HC256_KEY_LEN]);
    threefishSetKey(
        t3f_x, Threefish1024,
        (uint64_t *)&enc_key[HC256_KEY_LEN + HC256_IV_LEN],
        (uint64_t *)&enc_key[HC256_KEY_LEN + HC256_IV_LEN + T3F_KEY_LEN]);
    skeinCtxPrepare(skein_x, Skein512);
    skeinMacInit(
        skein_x,
        &enc_key[HC256_KEY_LEN + HC256_IV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN],
        SKEIN_MAC_LEN, Skein512);
}

unsigned char *make_enc_key(unsigned char *master_key, unsigned char *salt) {
    unsigned char *enc_key = t3fc_malloc(ENC_KEY_LEN);
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt,
                                      SALT_LEN, enc_key,
                                      ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");
    return enc_key;
}

void encrypt(FILE *input, FILE *output, unsigned char *master_key) {

    check_fatal_err(fwrite(header, 1, HEADER_LEN, output) != HEADER_LEN,
                    "cannot write header.");
    unsigned char salt[SALT_LEN];
    randombytes(salt, SALT_LEN);
    check_fatal_err(fwrite(salt, 1, SALT_LEN, output) != SALT_LEN,
                    "cannot write salt.");

    unsigned char *enc_key = make_enc_key(master_key, salt);

    HC256_State hc256_st;
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, &hc256_st, t3f_x, skein_x);
    skeinUpdate(skein_x, header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    size_t chunk_len = 0;
    unsigned char t3f_iv[T3F_IV_LEN];
    memcpy(t3f_iv,
           &enc_key[HC256_KEY_LEN + HC256_IV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN +
                    SKEIN_MAC_LEN],
           T3F_IV_LEN);

    do {
        chunk_len = fread(chunk, 1, CHUNK_LEN, input);
        check_fatal_err(chunk_len != CHUNK_LEN && ferror(input),
                        "cannot read input.");
        t3f_encrypt_chunk(t3f_x, chunk, chunk_len, t3f_iv);
        hc256_process_chunk(&hc256_st, chunk, chunk, chunk_len);
        skeinUpdate(skein_x, chunk, chunk_len);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len,
                        "cannot write to file.");
    } while(!feof(input));

    unsigned char hash[SKEIN_MAC_LEN];
    skeinFinal(skein_x, hash);
    check_fatal_err(fwrite(hash, 1, SKEIN_MAC_LEN, output) != SKEIN_MAC_LEN,
                    "cannot write Skein MAC.");

    free(enc_key);
    free(t3f_x);
    free(chunk);
    free(skein_x);
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

    unsigned char *enc_key = make_enc_key(master_key, salt);

    HC256_State hc256_st;
    ThreefishKey_t *t3f_x = t3fc_malloc(sizeof(ThreefishKey_t));
    SkeinCtx_t *skein_x = t3fc_malloc(sizeof(SkeinCtx_t));
    prepare(enc_key, &hc256_st, t3f_x, skein_x);
    skeinUpdate(skein_x, in_header, HEADER_LEN);
    skeinUpdate(skein_x, salt, SALT_LEN);

    unsigned char *chunk = t3fc_malloc(CHUNK_LEN);
    unsigned char t3f_iv[T3F_IV_LEN];
    memcpy(t3f_iv,
           &enc_key[HC256_KEY_LEN + HC256_IV_LEN + T3F_KEY_LEN + T3F_TWEAK_LEN +
                    SKEIN_MAC_LEN],
           T3F_IV_LEN);
    size_t infile_len =
        stb_filelen(input) - (HEADER_LEN + SALT_LEN + SKEIN_MAC_LEN);
    size_t chunk_len = CHUNK_LEN;
    size_t num_read = infile_len / CHUNK_LEN + (infile_len % CHUNK_LEN != 0);
    for (size_t i = 0; i < num_read; ++i) {
        if (i == num_read - 1) {
            chunk_len = infile_len - i * CHUNK_LEN;
        }
        chunk_len = fread(chunk, 1, chunk_len, input);
        check_fatal_err(chunk_len != CHUNK_LEN && ferror(input),
                        "cannot read input.");
        skeinUpdate(skein_x, chunk, chunk_len);
        hc256_process_chunk(&hc256_st, chunk, chunk, chunk_len);
        t3f_decrypt_chunk(t3f_x, chunk, chunk_len, t3f_iv);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len,
                        "cannot write to file.");
    }

    chunk_len = fread(chunk, 1, SKEIN_MAC_LEN, input);
    check_fatal_err(chunk_len != SKEIN_MAC_LEN && ferror(input),
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

void t3f_encrypt_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *t3f_iv) {
    uint32_t i = 0;
    unsigned char tmp[T3F_BLOCK_LEN];
    
    for (; chunk_len >= T3F_BLOCK_LEN; ++i, chunk_len -= T3F_BLOCK_LEN) {
        threefishEncryptBlockBytes(t3f_x, t3f_iv, tmp);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        memcpy(t3f_iv, &chunk[i * T3F_BLOCK_LEN], T3F_BLOCK_LEN);
    }
    if (chunk_len > 0) {
        threefishEncryptBlockBytes(t3f_x, t3f_iv, tmp);
        for (uint32_t j = 0; j < chunk_len; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                tmp[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
    }
}

void t3f_decrypt_chunk(ThreefishKey_t *t3f_x, unsigned char *chunk,
                       size_t chunk_len, unsigned char *t3f_iv) {
    uint32_t i = 0;
    unsigned char tmp[T3F_BLOCK_LEN];

    for (; chunk_len >= T3F_BLOCK_LEN; ++i, chunk_len -= T3F_BLOCK_LEN) {
        memcpy(tmp, &chunk[i * T3F_BLOCK_LEN], T3F_BLOCK_LEN);
        threefishEncryptBlockBytes(t3f_x, t3f_iv, t3f_iv);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                t3f_iv[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        memcpy(t3f_iv, tmp, T3F_BLOCK_LEN);
    }
    if (chunk_len > 0) {
        threefishEncryptBlockBytes(t3f_x, t3f_iv, t3f_iv);
        for (uint32_t j = 0; j < chunk_len; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                t3f_iv[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
    }
}