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
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <catta/alternative.h>
#include <catta/malloc.h>
#include <catta/simple-watch.h>
#include <catta/timeval.h>

#include <catta/core.h>
#include <catta/log.h>
#include <catta/lookup.h>
#include <catta/publish.h>

static char *name = NULL;
static CattaSEntryGroup *group = NULL;
static int try = 0;
static CattaServer *catta = NULL;
static const CattaPoll *poll_api;

static void dump_line(const char *text, CATTA_GCC_UNUSED void* userdata) {
    printf("%s\n", text);
}

static void dump_timeout_callback(CattaTimeout *timeout, CATTA_GCC_UNUSED void* userdata) {
    struct timeval tv;

    catta_server_dump(catta, dump_line, NULL);

    catta_elapse_time(&tv, 5000, 0);
    poll_api->timeout_update(timeout, &tv);
}

static void entry_group_callback(CattaServer *s, CattaSEntryGroup *g, CattaEntryGroupState state, void* userdata);

static void create_service(const char *t) {
    char *n;

    assert(t || name);

    n = t ? catta_strdup(t) : catta_alternative_service_name(name);
    catta_free(name);
    name = n;

    if (group)
        catta_s_entry_group_reset(group);
    else
        group = catta_s_entry_group_new(catta, entry_group_callback, NULL);

    catta_server_add_service(catta, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, name, "_http._tcp", NULL, NULL, 80, "foo", NULL);
    catta_s_entry_group_commit(group);

    try++;
}

static void rename_timeout_callback(CattaTimeout *timeout, CATTA_GCC_UNUSED void *userdata) {
    struct timeval tv;

    if (access("flag", F_OK) == 0) {
        create_service("New - Bonjour Service Name");
        return;
    }

    catta_elapse_time(&tv, 5000, 0);
    poll_api->timeout_update(timeout, &tv);
}

static void entry_group_callback(CATTA_GCC_UNUSED CattaServer *s, CATTA_GCC_UNUSED CattaSEntryGroup *g, CattaEntryGroupState state, CATTA_GCC_UNUSED void* userdata) {
    if (state == CATTA_ENTRY_GROUP_COLLISION)
        create_service(NULL);
    else if (state == CATTA_ENTRY_GROUP_ESTABLISHED) {
        catta_log_debug("ESTABLISHED !!!!");
        try = 0;
    }
}

static void server_callback(CattaServer *s, CattaServerState state, CATTA_GCC_UNUSED void* userdata) {
    catta_log_debug("server state: %i", state);

    if (state == CATTA_SERVER_RUNNING) {
        catta_server_dump(catta, dump_line, NULL);
    } else if (state == CATTA_SERVER_COLLISION) {
        char *n;

        n = catta_alternative_host_name(catta_server_get_host_name(s));
        catta_log_warn("Host name conflict, retrying with <%s>", n);
        catta_server_set_host_name(s, n);
        catta_free(n);

    }
}

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    int error;
    CattaSimplePoll *simple_poll;
    struct timeval tv;
    struct CattaServerConfig config;

    simple_poll = catta_simple_poll_new();
    poll_api = catta_simple_poll_get(simple_poll);

    catta_server_config_init(&config);
    config.publish_workstation = 0;
    config.use_ipv6 = 0;
    config.publish_domain = 0;
    config.publish_hinfo = 0;
    catta = catta_server_new(poll_api, &config, server_callback, NULL, &error);
    catta_server_config_free(&config);

    catta_elapse_time(&tv, 5000, 0);
    poll_api->timeout_new(poll_api, &tv, dump_timeout_callback, catta);

    catta_elapse_time(&tv, 5000, 0);
    poll_api->timeout_new(poll_api, &tv, rename_timeout_callback, catta);

    /* Evil, but the conformace test requires that*/
    create_service("gurke");


    catta_simple_poll_loop(simple_poll);

    if (group)
        catta_s_entry_group_free(group);
    catta_server_free(catta);

    catta_simple_poll_free(simple_poll);

    return 0;
}
