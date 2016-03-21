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

#include <stdio.h>
#include <stdlib.h>

#include <tommath.h>

#define RADIX 16

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
