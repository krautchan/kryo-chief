#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ccard.h"

int main(int argc, char **argv) {
	int i, chk;

	for(i = 1; i < argc; i++) {
		chk = cc_check((uint8_t*)argv[i], strlen(argv[i]));
		printf("%s: ", argv[i]);

		switch(chk) {
			case CC_OK: 	printf("OK\n"); 				break;
			case CC_UNSURE:	printf("Maybe OK\n");			break;
			case CC_BLIST: 	printf("Fail: Blacklist\n"); 	break;
			case CC_WLIST:	printf("Fail: Whitelist\n");	break;
			case CC_LENGTH:	printf("Fail: Length\n");		break;
			case CC_CKSUM:	printf("Fail: Checksum\n");		break;
		}
		cc_freelists();
	}

	return EXIT_SUCCESS;
}
