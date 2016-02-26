#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"

int main(void) {
	uint8_t key[32] = {
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};

	uint8_t inblock[AES_BSIZE] = {
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};

	uint8_t outblock[AES_BSIZE] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	size_t i;
	aes_ctx_t ctx;

	aes_init(&ctx, inblock, key);
	aes_enc(&ctx);
	aes_tostr(ctx, outblock);

	for(i = 0; i < 16; i++)
		printf("%02x", outblock[i]);
	printf("\n");

	aes_dec(&ctx);
	aes_tostr(ctx, outblock);

	for(i = 0; i < 16; i++)
		printf("%02x", outblock[i]);
	printf("\n");

	return EXIT_SUCCESS;

}
