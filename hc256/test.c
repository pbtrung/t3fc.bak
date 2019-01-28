#include <stdio.h>
#include <stdlib.h>

#include "hc256.h"
#include "hc256_opt32.h"

#define HC256_LEN 64UL
#define TEST_LEN 32UL
#define HC256_KEY_LEN 32UL

static void check_fatal_err(int cond, char *msg) {
    if (cond) {
        fprintf(stderr, "Error: %s\n", msg);
        exit(-1);
    }
}

void *t3fc_malloc(size_t s) {
    void *buf = malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

int main(int argc, char *argv[]) {
    hc256_ctx_t *hc256_ctx = t3fc_malloc(sizeof(hc256_ctx_t));
    uint8_t hc256_kiv[HC256_LEN];
    uint8_t buf[TEST_LEN];

    memset(hc256_kiv, 0, HC256_LEN);
    hc256_set_kiv(hc256_ctx, hc256_kiv);
    uint8_t test_vector_1[TEST_LEN] = {
        0x5b, 0x07, 0x89, 0x85, 0xd8, 0xf6, 0xf3, 0x0d,
        0x42, 0xc5, 0xc0, 0x2f, 0xa6, 0xb6, 0x79, 0x51,
        0x53, 0xf0, 0x65, 0x34, 0x80, 0x1f, 0x89, 0xf2,
        0x4e, 0x74, 0x24, 0x8b, 0x72, 0x0b, 0x48, 0x18
    };
    hc256_gen_bytes(hc256_ctx, buf, TEST_LEN);
    check_fatal_err(memcmp(buf, test_vector_1, TEST_LEN) != 0, "does not match test vector 1.");

    memset(hc256_kiv, 0, HC256_LEN);
    hc256_kiv[HC256_KEY_LEN] = 0x01;
    hc256_set_kiv(hc256_ctx, hc256_kiv);
    uint8_t test_vector_2[TEST_LEN] = {
        0xaf, 0xe2, 0xa2, 0xbf, 0x4f, 0x17, 0xce, 0xe9,
        0xfe, 0xc2, 0x05, 0x8b, 0xd1, 0xb1, 0x8b, 0xb1,
        0x5f, 0xc0, 0x42, 0xee, 0x71, 0x2b, 0x31, 0x01,
        0xdd, 0x50, 0x1f, 0xc6, 0x0b, 0x08, 0x2a, 0x50
    };
    hc256_gen_bytes(hc256_ctx, buf, TEST_LEN);
    check_fatal_err(memcmp(buf, test_vector_2, TEST_LEN) != 0, "does not match test vector 2.");

    memset(hc256_kiv, 0, HC256_LEN);
    hc256_kiv[0] = 0x55;
    hc256_set_kiv(hc256_ctx, hc256_kiv);
    uint8_t test_vector_3[TEST_LEN] = {
        0x1c, 0x40, 0x4a, 0xfe, 0x4f, 0xe2, 0x5f, 0xed,
        0x95, 0x8f, 0x9a, 0xd1, 0xae, 0x36, 0xc0, 0x6f,
        0x88, 0xa6, 0x5a, 0x3c, 0xc0, 0xab, 0xe2, 0x23,
        0xae, 0xb3, 0x90, 0x2f, 0x42, 0x0e, 0xd3, 0xa8
    };
    hc256_gen_bytes(hc256_ctx, buf, TEST_LEN);
    check_fatal_err(memcmp(buf, test_vector_3, TEST_LEN) != 0, "does not match test vector 3.");

    free(hc256_ctx);

    memset(hc256_kiv, 0, HC256_LEN);
    memset(buf, 0, TEST_LEN);
    HC256(hc256_kiv, &hc256_kiv[HC256_KEY_LEN], buf, buf, TEST_LEN);
    check_fatal_err(memcmp(buf, test_vector_1, TEST_LEN) != 0, "does not match test vector 1.");

    memset(hc256_kiv, 0, HC256_LEN);
    hc256_kiv[HC256_KEY_LEN] = 0x01;
    memset(buf, 0, TEST_LEN);
    HC256(hc256_kiv, &hc256_kiv[HC256_KEY_LEN], buf, buf, TEST_LEN);
    check_fatal_err(memcmp(buf, test_vector_2, TEST_LEN) != 0, "does not match test vector 2.");

    memset(hc256_kiv, 0, HC256_LEN);
    hc256_kiv[0] = 0x55;
    memset(buf, 0, TEST_LEN);
    HC256(hc256_kiv, &hc256_kiv[HC256_KEY_LEN], buf, buf, TEST_LEN);
    check_fatal_err(memcmp(buf, test_vector_3, TEST_LEN) != 0, "does not match test vector 3.");

    return EXIT_SUCCESS;
}