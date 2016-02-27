#include <pthread.h>
#include <stdlib.h>

#include "config.h"
#include "sv_keydb.h"

int main(void) {
	keydb_init(CONFIG_KEYDIR, CONFIG_PREGEN_KEYS, CONFIG_REGEN_KEYS);
	keydb_spawngen();

	pthread_exit(NULL);
	return EXIT_SUCCESS;
}
