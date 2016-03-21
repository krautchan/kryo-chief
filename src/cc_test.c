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
#include <stdio.h>
#include <string.h>

#include "ccard.h"

int main(int argc, char **argv) {
	int i, chk, len;
	char realcheck;

	for(i = 1; i < argc; i++) {
		len = strlen(argv[i]);
		chk = cc_check((uint8_t*)argv[i], strlen(argv[i]), &realcheck);
		printf("%s: ", argv[i]);

		switch(chk) {
			case CC_KNOWN:	printf("Seen before, but ");
			case CC_OK: 	printf("OK\n"); 				break;
			case CC_UNSURE:	printf("Maybe OK\n");			break;
			case CC_BLIST: 	printf("Fail: Blacklist\n"); 	break;
			case CC_WLIST:	printf("Fail: Whitelist\n");	break;
			case CC_LENGTH:	printf("Fail: Length\n");		break;
			case CC_CKSUM:	argv[i][len - 1] = realcheck;
							printf(" -> %s\n", argv[i]);
		}
		cc_freelists();
	}

	return EXIT_SUCCESS;
}
