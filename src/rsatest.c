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
#include "config.h"
#include "oaep.h"
#include "rsa.h"
#include "rsa_io.h"

int main(int argc, char **argv) {
	int i, status;
	size_t minsize, keysize;
	rsa_keypair_t *pair;

	minsize = oaep_minsize(AES_KSIZE);
	for(i = 1; i < argc; i++) {
		keysize = atoi(argv[i]);
		if(keysize < minsize) {
			printf("Adjusting %lu to %lu bits. ", keysize, minsize);
			keysize = minsize;
		}

		printf("Generating %lu-bit key... ", keysize);
		fflush(stdout);
		if((pair = rsa_keypair_gen(keysize, &status)) == NULL) {
			printf("FAILED!\n");
			fflush(stdout);
			continue;
		} 
		
		printf("Testing... ");
		fflush(stdout);
		if(rsa_keypair_test(pair) == 0)
			printf("FAILED!\n");
		else
			printf("OK!\n");

		fflush(stdout);
		rsa_keypair_free(pair);
	}

	return EXIT_SUCCESS;
}
