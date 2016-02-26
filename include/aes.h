#ifndef AES_H_
#define AES_H_

#include <stdint.h>

#define FOR_MIX 1
#define INV_MIX 2

#define rotl(i, n) ((i << n) | (i >> (32 - n)))
#define rot_byte(i) rotl(i, 8)
#define sub_byte(i) ((s[i >> 24] << 24) |\
                    (s[(i >> 16) & 255] << 16) |\
                    (s[(i >> 8) & 255] << 8) |\
                    (s[i & 255] & 255))

#define NB	4
#define NK	8
#define NR	(NK + 6)

#define AES_BSIZE (NB * 4)
#define AES_KSIZE (NK * 4)

typedef struct {
	uint32_t expkey[NB * (NR + 1)];
	uint8_t state[NB * 4];
} aes_ctx_t;

void aes_enc(aes_ctx_t *ctx);
void aes_dec(aes_ctx_t *ctx);

void aes_update(aes_ctx_t *ctx, const uint8_t *data, const uint8_t *key);
void aes_init(aes_ctx_t *ctx, const uint8_t *data, const uint8_t *key);
void aes_tostr(aes_ctx_t ctx, uint8_t *out);

#endif
