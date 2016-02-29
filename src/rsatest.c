#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "rsa.h"
#include "rsa_io.h"

int main(int argc, char **argv) {
	int i, status;
	size_t keysize;
	rsa_keypair_t *pair;

	for(i = 1; i < argc; i++) {
		keysize = atoi(argv[i]);
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
