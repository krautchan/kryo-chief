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

#include "config.h"

int main(void) {
	FILE *fp;
	uint32_t len, i;
	int c;

	if((fp = fopen(CONFIG_DATADIR "release_tokens", "rb")) == NULL) {
		fprintf(stderr, "ERROR: fopen() failed!\n");
		return EXIT_FAILURE;
	}

	while(!feof(fp)) {
		fread(&len, sizeof(uint32_t), 1, fp);

		for(i = 0; i < len; i++) {
			c = fgetc(fp);
			if(c != EOF)
				putchar(c);
		}
		putchar('\n');
	}

	fclose(fp);
	return EXIT_SUCCESS;
}
