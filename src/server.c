#include <pthread.h>
#include <stdlib.h>

#include "config.h"
#include "sv_keydb.h"
#include "sv_net.h"

int main(void) {
	int listen_socket;

	keydb_init(CONFIG_KEYDIR, CONFIG_PREGEN_KEYS, CONFIG_REGEN_KEYS);
	keydb_spawngen();

	if((listen_socket = sv_listen(CONFIG_SV_PORT)) == INVALID_SOCKET) goto end;
	sv_accept(listen_socket);

end:
//	keydb_free();
	pthread_exit(NULL);
	return EXIT_SUCCESS;

}
