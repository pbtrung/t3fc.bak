#ifndef __HC256_H__
#define __HC256_H__

#include <stdint.h>
#include <string.h>

#define HC256_U8V(v) ((uint8_t)(v)&0xFFU)
#define HC256_U16V(v) ((uint16_t)(v)&0xFFFFU)
#define HC256_U32V(v) ((uint32_t)(v)&0xFFFFFFFFUL)
#define HC256_U64V(v) ((uint64_t)(v)&0xFFFFFFFFFFFFFFFFULL)

#define HC256_ROTL8(v, n) (HC256_U8V((v) << (n)) | ((v) >> (8 - (n))))

#define HC256_ROTL16(v, n) (HC256_U16V((v) << (n)) | ((v) >> (16 - (n))))

#define HC256_ROTL32(v, n) (HC256_U32V((v) << (n)) | ((v) >> (32 - (n))))

#define HC256_ROTL64(v, n) (HC256_U64V((v) << (n)) | ((v) >> (64 - (n))))

#define HC256_ROTR8(v, n) HC256_ROTL8(v, 8 - (n))
#define HC256_ROTR16(v, n) HC256_ROTL16(v, 16 - (n))
#define HC256_ROTR32(v, n) HC256_ROTL32(v, 32 - (n))
#define HC256_ROTR64(v, n) HC256_ROTL64(v, 64 - (n))

#define SIG0(x) (HC256_ROTR32((x), 7) ^ HC256_ROTR32((x), 18) ^ ((x) >> 3))
#define SIG1(x) (HC256_ROTR32((x), 17) ^ HC256_ROTR32((x), 19) ^ ((x) >> 10))

typedef struct hc_ctx_t {
    uint32_t ctr;
    union {
        uint32_t T[2048];
        struct {
            uint32_t P[1024];
            uint32_t Q[1024];
        };
    };
} hc256_ctx_t;

void hc256_set_kiv(hc256_ctx_t *, void *);
void hc256_gen_bytes(hc256_ctx_t *, unsigned char *, uint32_t);

#endif //__HC256_H__
