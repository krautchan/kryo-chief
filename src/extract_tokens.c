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
