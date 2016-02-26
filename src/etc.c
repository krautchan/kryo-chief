#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <tommath.h>

#define RADIX 16

size_t fp_size(FILE *fp) {
	size_t startpos, out;
	if(fp == NULL)
		return 0;

	startpos = ftell(fp);
	fseek(fp, 0, SEEK_END);
	out = ftell(fp);
	fseek(fp, startpos, SEEK_SET);

	return out;
}

char *alloc_copy(const char *str) {
	char *out;
	size_t size;

	if(str == NULL)
		return NULL;
	
	size = strlen(str) + 1;

	if((out = malloc(size)) == NULL)
		return NULL;

	memcpy(out, str, size);

	return out;
}

void xorblock(uint8_t *dat1, uint8_t *dat2, size_t len) {
	size_t i;

	for(i = 0; i < len; i++)
		dat1[i] ^= dat2[i];
}

int getrand(uint8_t *dst, int len, void *dat) {
	FILE *fp;
	size_t bytes_read;

	if((fp = fopen("/dev/urandom", "rb")) == NULL)
		return 0;

	bytes_read = fread(dst, 1, len, fp);

	fclose(fp);
	return bytes_read;
}

void printint(mp_int *i, const char *id) {
	int size;
	char *str;

	if(mp_radix_size(i, RADIX, &size) == MP_OKAY) {
		if((str = malloc(size)) == NULL) {
			fprintf(stderr, "printint(): malloc() failed.\n");
			return;
		}
		mp_toradix(i, str, RADIX);

		if(id)
			printf("%s = ", id);
		printf("%s\n", str);
		free(str);
	} else {
		fprintf(stderr, "printint(): mp_radix_size() failed.\n");
	}
}

#define BUFSIZE 16

char *line_in(FILE *fp) {
	size_t len = BUFSIZE;
	char buf[BUFSIZE];
	char *end = NULL;
	char *ret = calloc(BUFSIZE, 1);

	while(fgets(buf, BUFSIZE, fp)) {
		if(len - strlen(ret) < BUFSIZE)
			ret = realloc(ret, len *= 2);

		strcat(ret, buf);

		if((end = strrchr(ret, '\n')) != NULL)
			break;
	}
	if(end)
		*end = '\0';

	return ret;
}
