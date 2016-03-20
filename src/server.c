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

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "sv_keydb.h"
#include "sv_net.h"
#include "etc.h"

extern int genthread_shutdown;

int main(void) {
	signal(SIGPIPE, SIG_IGN);

	keydb_init(CONFIG_DATADIR "keystore", CONFIG_PREGEN_KEYS, CONFIG_REGEN_KEYS);
	if(keydb_spawngen() == 0) goto end;

	printf("Opening listening socket on port %d\n", CONFIG_SV_PORT);

	if(sv_listen(CONFIG_SV_PORT) == 0) {
		printf("listen() failed!\n");
		genthread_shutdown = 1;
		goto end;
	}

	while(genthread_shutdown < 2);

end:
	return EXIT_SUCCESS;

}
