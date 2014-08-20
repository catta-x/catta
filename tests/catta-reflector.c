/***
  This file is part of catta.

  catta is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  catta is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with catta; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <catta/simple-watch.h>
#include <catta/core.h>

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char*argv[]) {
    CattaServer *server;
    CattaServerConfig config;
    int error;
    CattaSimplePoll *simple_poll;

    simple_poll = catta_simple_poll_new();

    catta_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;
    config.use_ipv6 = 0;
    config.enable_reflector = 1;

    server = catta_server_new(catta_simple_poll_get(simple_poll), &config, NULL, NULL, &error);
    catta_server_config_free(&config);

    for (;;)
        if (catta_simple_poll_iterate(simple_poll, -1) != 0)
            break;

    catta_server_free(server);
    catta_simple_poll_free(simple_poll);

    return 0;
}
