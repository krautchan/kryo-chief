#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>

#include "config.h"
#include "sv_keydb.h"
#include "sv_net.h"

#include "etc.h"

extern int genthread_shutdown;

int main(void) {
	int listen_socket;

	signal(SIGPIPE, SIG_IGN);

	keydb_init(CONFIG_DATADIR "keystore", CONFIG_PREGEN_KEYS, CONFIG_REGEN_KEYS);
	if(keydb_spawngen() == 0) goto end;

	printf("Opening listening socket on port %d\n", CONFIG_SV_PORT);

	if((listen_socket = sv_listen(CONFIG_SV_PORT)) == INVALID_SOCKET) {
		printf("listen() failed!\n");
		goto end;
	}

	while(genthread_shutdown < 2);

end:
	return EXIT_SUCCESS;

}
