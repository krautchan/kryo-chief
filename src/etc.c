/* 
 * HTR -- The Heisetrolljan
 * 
 * Copyright (C) 2016  Martin Wolters
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to 
 * the Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA
 * 
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tommath.h>

#define RADIX 16

union endtest_t {
	uint32_t i;
	uint8_t j[4];
};

void printaddr(const uint8_t *peer) {
	int i;

	for(i = 0; i < 3; i++)
		printf("%d.", peer[i]);
	printf("%d: ", peer[3]);
}

void inttoarr(const uint32_t in, uint8_t *out) {
	union endtest_t test;
	test.i = 1;

	if(test.j[0] == test.i) {
		out[3] = (in >> 24) & 0xff;
		out[2] = (in >> 16) & 0xff;
		out[1] = (in >> 8) & 0xff;
		out[0] = in & 0xff;
	} else {
		out[0] = (in >> 24) & 0xff;
		out[1] = (in >> 16) & 0xff;
		out[2] = (in >> 8) & 0xff;
		out[3] = in & 0xff;
	}	
}

uint32_t arrtoint(const uint8_t *in) {
	union endtest_t test;
	test.i = 1;
	
	if(test.j[0] == test.i) {
		return (in[3] << 24) | (in[2] << 16) | (in[1] << 8) | in[0];
	} else {
		return (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
	}
}

size_t bitstobytes(const size_t n_bits) {
	size_t out = n_bits / 8;
	return out + ((n_bits % 8) ? 1 : 0);
}

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
		if((str = malloc(size)) == NULL)
			return;
		mp_toradix(i, str, RADIX);

		if(id)
			printf("%s = ", id);
		printf("%s\n", str);
		free(str);
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
