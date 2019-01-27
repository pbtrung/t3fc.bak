#include "hc256.h"

// key stream generation function
uint32_t hc256_generate(hc256_ctx_t *c) {
    uint32_t r, i, i3, i10, i12, i1023;
    uint32_t *x0, *x1;
    uint32_t w0, w1, t;

    t = c->ctr;

    c->ctr = (c->ctr + 1) & 0x7ff;

    x0 = c->P;
    x1 = c->Q;

    if (t > 0x3ff) {
        x0 = c->Q;
        x1 = c->P;
    }

    i = t & 0x3ff;
    i3 = (i - 3) & 0x3ff;
    i10 = (i - 10) & 0x3ff;
    i1023 = (i - 1023) & 0x3ff;

    x0[i] += x0[i10] + (HC256_ROTR32(x0[i3], 10) ^ HC256_ROTL32(x0[i1023], 9)) +
             x1[(x0[i3] ^ x0[i1023]) & 0x3ff];

    i12 = (i - 12) & 0x3ff;

    w0 = x0[i];
    w1 = x0[i12];

    for (r = 0, t = 0; t < 4; t++) {
        r += x1[w1 & 255];
        w1 >>= 8;
        x1 += 1024 / 4;
    }
    r ^= w0;

    return r;
}

// both key and iv must be 32 bytes each / 256-bits!
void hc256_set_kiv(hc256_ctx_t *c, void *kiv) {
    uint32_t W[4096], i;

    // 1. set counter
    c->ctr = 0;

    // 2. copy 512-bit key and iv to local workspace
    memcpy(W, kiv, 64);

    // 3. expand buffer using SHA-256 macros
    for (i = 16; i < 4096; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16] + i;
    }

    // 5. set the P and Q tables
    memcpy(&c->T[0], &W[512], 2048 * 4);

    // 6. run cipher 4096 iterations before generating output
    for (i = 0; i < 4096; i++) {
        hc256_generate(c);
    }
}

void hc256_gen_bytes(hc256_ctx_t *c, unsigned char *buf, uint32_t buf_len) {
    uint32_t i, j, w;

    for (i = 0; i < buf_len;) {
        w = hc256_generate(c);
        for (j = 0; j < 4 && i < buf_len; j++) {
            buf[i++] = (w & 255);
            w >>= 8;
        }
    }
}
