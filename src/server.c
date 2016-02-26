#include <stdint.h>
#include <stdio.h>

#include <tommath.h>

#include "etc.h"
#include "rsa.h"
#include "rsa_io.h"

static int mp_getrand(mp_int *i, const size_t bits) {
	const size_t bytes = bits / 8;
	FILE *fp;
	uint8_t *buf;
	int ret;

	if(i == 0)
		return MP_VAL;

	if(bytes == 0)
		return MP_VAL;

	if((fp = fopen("/dev/urandom", "rb")) == NULL)
		return MP_MEM;

	if((buf = malloc(bytes)) == NULL) {
		fclose(fp);
		return MP_MEM;
	}

	fread(buf, 1, bytes, fp);
	fclose(fp);

	ret = mp_read_unsigned_bin(i, buf, bytes);
	free(buf);

	return ret;
}

int main(void) {
	rsa_keypair_t *pair;
	mp_int p, c;

	int status;


	if((pair = rsa_keypair_gen(KEYSIZE, &status)) == NULL)
		return EXIT_FAILURE;

	rsa_keypair_print(pair);

	mp_init_multi(&p, &c, NULL);
	mp_getrand(&p, KEYSIZE / 2);
	printint(&p, "pt");

	rsa_enc(&p, pair, &c);
	printint(&c, "ct");
	mp_set_int(&p, 0);

	rsa_dec(&c, pair, &p);
	printint(&p, "pt");
	
	rsa_keypair_free(pair);
	mp_clear_multi(&p, &c, NULL);

	return EXIT_SUCCESS;
}
