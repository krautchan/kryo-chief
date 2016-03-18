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
#include <stdlib.h>

/*
 * lookup3 hash function by Bob Jenkins, abridged version.
 *
 * All special cases were removed. Only works on x86 and x64
 * machines. Maybe more, but no guarantees!
 */

#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

#define mix_jenkins(a, b, c) \
	do { \
		a -= c; a ^= rot(c, 4); c += b; \
		b -= a; b ^= rot(a, 6); a += c; \
		c -= b; c ^= rot(b, 8); b += a; \
		a -= c; a ^= rot(c,16); c += b; \
		b -= a; b ^= rot(a,19); a += c; \
		c -= b; c ^= rot(b, 4); b += a; \
	} while(0);

#define final_jenkins(a, b, c) \
	do { \
		c ^= b; c -= rot(b, 14); \
		a ^= c; a -= rot(c, 11); \
		b ^= a; b -= rot(a, 25); \
		c ^= b; c -= rot(b, 16); \
		a ^= c; a -= rot(c,  4); \
		b ^= a; b -= rot(a, 14); \
		c ^= b; c -= rot(b, 24); \
	} while(0);

size_t hfunc_jenkins(const uint8_t *key, const size_t klen) {
	uint32_t a, b, c;
	uint32_t length = klen;
	uint32_t *k;
	size_t out;

	a = b = c = 0xdeadbeef + klen;

	k = (uint32_t*)key;

	while(length > 12) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix_jenkins(a, b, c);
		length -= 12;
		k += 3;
	}

	switch(length) {
		case 12: c += k[2];				b += k[1]; a += k[0];	break;
		case 11: c += k[2] & 0xffffff;	b += k[1]; a += k[0];	break;
		case 10: c += k[2] & 0xffff;	b += k[1]; a += k[0];	break;
		case  9: c += k[2] & 0xff;		b += k[1]; a += k[0];	break;
		case  8: b += k[1];				a += k[0];				break;
		case  7: b += k[1] & 0xffffff;	a += k[0];				break;
		case  6: b += k[1] & 0xffff;	a += k[0];				break;
		case  5: b += k[1] & 0xff;		a += k[0];				break;
		case  4: a += k[0];										break;
		case  3: a += k[0] & 0xffffff;							break;
		case  2: a += k[0] & 0xffff;							break;
		case  1: a += k[0] & 0xff;								break;
		case  0: goto ret;
	}

	final_jenkins(a, b, c);

ret:
	out = b;
	out <<= 32;
	out += c;

	return out;
}

/*
 * Peter K. Pearson's algorithm from June 1990
 * Communications of the ACM 33 (6): 677
 *
 * Adapted from http://en.wikipedia.org/wiki/Pearson_hashing
 * using Pearson's original table from page 679 of the paper.
 */

size_t hfunc_pearson(const uint8_t *key, const size_t klen) {
	size_t i, j;
	size_t out = 0;
	uint8_t h;

	const uint8_t T[] = {
		  1,  87,  49,  12, 176, 178, 102, 166, 121, 193,   6,  84, 249, 230,  44, 163,
		 14, 197, 213, 181, 161,  85, 218,  80,  64, 239,  24, 226, 236, 142,  38, 200,
		110, 177, 104, 103, 141, 253, 255,  50,  77, 101,  81,  18,  45,  96,  31, 222,
		 25, 107, 190,  70,  86, 237, 240,  34,  72, 242,  20, 214, 244, 227, 149, 235,
		 97, 234,  57,  22,  60, 250,  82, 175, 208,   5, 127, 199, 111,  62, 135, 248,
		174, 169, 211,  58,  66, 154, 106, 195, 245, 171,  17, 187, 182, 179,   0, 243,
		132,  56, 148,  75, 128, 133, 158, 100, 130, 126,  91,  13, 153, 246, 216, 219,
		119,  68, 223,  78,  83,  88, 201,  99, 122,  11,  92,  32, 136, 114,  52,  10,
		138,  30,  48, 183, 156,  35,  61,  26, 143,  74, 251,  94, 129, 162,  63, 152,
		170,   7, 115, 167, 241, 206,   3, 150,  55,  59, 151, 220,  90,  53,  23, 131,
		125, 173,  15, 238,  79,  95,  89,  16, 105, 137, 225, 224, 217, 160,  37, 123,
		118,  73,   2, 157,  46, 116,   9, 145, 134, 228, 207, 212, 202, 215,  69, 229,
		 27, 188,  67, 124, 168, 252,  42,   4,  29, 108,  21, 247,  19, 205,  39, 203,
		233,  40, 186, 147, 198, 192, 155,  33, 164, 191,  98, 204, 165, 180, 117,  76,
		140,  36, 210, 172,  41,  54, 159,   8, 185, 232, 113, 196, 231,  47, 146, 120,
		 51,  65,  28, 144, 254, 221,  93, 189, 194, 139, 112,  43,  71, 109, 184, 209
	};

	for(j = 0; j < sizeof(size_t); j++) {
		h = T[(key[0] + j) & 0xff];
		for(i = 1; i < klen; i++)
			h = T[h ^ key[i]];
		out <<= 8;
		out |= h;
	}

	return out;
}

/*
 * Simple hash function from Stackoverflow user "Enno":
 * http://stackoverflow.com/posts/5075554/revisions
 */

size_t hfunc_stackov(const uint8_t *key, const size_t klen) {
	size_t out = 0, i;

	for(i = 0; i < klen; i++)
		out = out * 37 + key[i];

	return out;
}
