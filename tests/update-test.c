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

#include <assert.h>
#include <stdlib.h>

#include <catta/error.h>
#include <catta/watch.h>
#include <catta/simple-watch.h>
#include <catta/malloc.h>
#include <catta/alternative.h>
#include <catta/timeval.h>

#include <catta/core.h>
#include <catta/log.h>
#include <catta/publish.h>
#include <catta/lookup.h>

static CattaSEntryGroup *group = NULL;

static void server_callback(CattaServer *s, CattaServerState state, CATTA_GCC_UNUSED void* userdata) {

    catta_log_debug("server state: %i", state);

    if (state == CATTA_SERVER_RUNNING) {
        int ret;

        group = catta_s_entry_group_new(s, NULL, NULL);
        assert(group);

        ret = catta_server_add_service(s, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, "foo", "_http._tcp", NULL, NULL, 80, "test1", NULL);
        assert(ret == CATTA_OK);

        catta_s_entry_group_commit(group);
    }
}

static void modify_txt_callback(CATTA_GCC_UNUSED CattaTimeout *e, void *userdata) {
    int ret;
    CattaServer *s = userdata;

    catta_log_debug("modifying");

    ret = catta_server_update_service_txt(s, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, "foo", "_http._tcp", NULL, "test2", NULL);
    assert(ret == CATTA_OK);
}

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    CattaSimplePoll *simple_poll;
    const CattaPoll *poll_api;
    CattaServer *server;
    struct timeval tv;
    CattaServerConfig config;

    simple_poll = catta_simple_poll_new();
    assert(simple_poll);

    poll_api = catta_simple_poll_get(simple_poll);
    assert(poll_api);

    catta_server_config_init(&config);
    config.publish_domain = config.publish_workstation = config.use_ipv6 = config.publish_hinfo = 0;
    server = catta_server_new(poll_api, &config, server_callback, NULL, NULL);
    assert(server);
    catta_server_config_free(&config);

    poll_api->timeout_new(poll_api, catta_elapse_time(&tv, 1000*10, 0), modify_txt_callback, server);

    catta_simple_poll_loop(simple_poll);
    return 0;
}
