#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "sv_keydb.h"
#include "sv_net.h"

#include "etc.h"

int main(void) {
	int listen_socket;

	keydb_init(CONFIG_DATADIR "keystore", CONFIG_PREGEN_KEYS, CONFIG_REGEN_KEYS);

	if((listen_socket = sv_listen(CONFIG_SV_PORT)) == INVALID_SOCKET) {
		printf("listen() failed!\n");
		goto end;
	}
	printf("Listening on port %d\n", CONFIG_SV_PORT);

	keydb_spawngen();
	sv_accept(listen_socket);

end:
//	keydb_free();
	pthread_exit(NULL);
	return EXIT_SUCCESS;

}
