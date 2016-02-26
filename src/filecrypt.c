#include <stdio.h>
#include <unistd.h>

#include "aes.h"
#include "etc.h"

int file_enc(const char *infile, const char *outfile, const uint8_t *key) {
	FILE *in, *out;
	int ret = 0;
	uint8_t iv[AES_BSIZE], data[AES_BSIZE], ct[AES_BSIZE];
	size_t fsize;
	aes_ctx_t ctx;

	if((in = fopen(infile, "rb")) == NULL) return 0;
	if((out = fopen(outfile, "wb")) == NULL) goto closein;

	fsize = fp_size(in);
	if(fwrite(&fsize, sizeof(size_t), 1, out) == 0) goto closeout;

	getrand(iv, AES_BSIZE, NULL);

	if(fwrite(iv, AES_BSIZE, 1, out) == 0) goto closeout;

	aes_init(&ctx, NULL, key);
	while(!feof(in)) {
		memset(data, 0, AES_BSIZE);
		if(fread(data, 1, AES_BSIZE, in) > 0) {
			xorblock(data, iv, AES_BSIZE);
			aes_update(&ctx, data, NULL);
			aes_enc(&ctx);
			aes_tostr(ctx, ct);
			memcpy(iv, ct, AES_BSIZE);

			fwrite(ct, AES_BSIZE, 1, out);
		}
	}
	ret = 1;

closeout:
	fclose(out);
closein:
	fclose(in);
	return ret;
}

int file_dec(const char *infile, const char *outfile, const uint8_t *key) {
	FILE *in, *out;
	uint8_t iv[AES_BSIZE], data[AES_BSIZE], pt[AES_BSIZE];
	int ret = 0;
	size_t fsize = 0;
	aes_ctx_t ctx;

	if((in = fopen(infile, "rb")) == NULL) return 0;
	if((out = fopen(outfile, "wb")) == NULL) goto closein;

	if(fread(&fsize, sizeof(size_t), 1, in) == 0) goto closeout;
	if(fread(iv, AES_BSIZE, 1, in) == 0) goto closeout;

	aes_init(&ctx, NULL, key);

	while(fread(data, 1, AES_BSIZE, in) != 0) {
		aes_update(&ctx, data, NULL);
		aes_dec(&ctx);
		aes_tostr(ctx, pt);
		xorblock(pt, iv, AES_BSIZE);
		memcpy(iv, data, AES_BSIZE);
		
		fwrite(pt, AES_BSIZE, 1, out);
	}
	ret = 1;

closeout:
	fclose(out);
closein:
	fclose(in);

	if(fsize)
		truncate(outfile, fsize);

	return ret;
}
