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
