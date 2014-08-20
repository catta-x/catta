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
#include <assert.h>

#include <catta/malloc.h>
#include <catta/simple-watch.h>
#include <catta/alternative.h>
#include <catta/timeval.h>

#include <catta/core.h>
#include <catta/log.h>
#include <catta/publish.h>
#include <catta/lookup.h>

#define DOMAIN NULL
#define SERVICE_TYPE "_http._tcp"

static CattaSServiceBrowser *service_browser1 = NULL, *service_browser2 = NULL;
static const CattaPoll * poll_api = NULL;
static CattaServer *server = NULL;
static CattaSimplePoll *simple_poll;

static const char *browser_event_to_string(CattaBrowserEvent event) {
    switch (event) {
        case CATTA_BROWSER_NEW : return "NEW";
        case CATTA_BROWSER_REMOVE : return "REMOVE";
        case CATTA_BROWSER_CACHE_EXHAUSTED : return "CACHE_EXHAUSTED";
        case CATTA_BROWSER_ALL_FOR_NOW : return "ALL_FOR_NOW";
        case CATTA_BROWSER_FAILURE : return "FAILURE";
    }

    abort();
}

static void sb_callback(
    CattaSServiceBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *name,
    const char *service_type,
    const char *domain,
    CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {
    catta_log_debug("SB%i: (%i.%s) <%s> as <%s> in <%s> [%s] cached=%i", b == service_browser1 ? 1 : 2, iface, catta_proto_to_string(protocol), name, service_type, domain, browser_event_to_string(event), !!(flags & CATTA_LOOKUP_RESULT_CACHED));
}

static void create_second_service_browser(CattaTimeout *timeout, CATTA_GCC_UNUSED void* userdata) {

    service_browser2 = catta_s_service_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, SERVICE_TYPE, DOMAIN, 0, sb_callback, NULL);
    assert(service_browser2);

    poll_api->timeout_free(timeout);
}

static void quit(CATTA_GCC_UNUSED CattaTimeout *timeout, CATTA_GCC_UNUSED void *userdata) {
    catta_simple_poll_quit(simple_poll);
}

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    struct timeval tv;
    CattaServerConfig config;

    simple_poll = catta_simple_poll_new();
    assert(simple_poll);

    poll_api = catta_simple_poll_get(simple_poll);
    assert(poll_api);

    catta_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;

    catta_address_parse("192.168.50.1", CATTA_PROTO_UNSPEC, &config.wide_area_servers[0]);
    config.n_wide_area_servers = 1;
    config.enable_wide_area = 1;

    server = catta_server_new(poll_api, &config, NULL, NULL, NULL);
    assert(server);
    catta_server_config_free(&config);

    service_browser1 = catta_s_service_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, SERVICE_TYPE, DOMAIN, 0, sb_callback, NULL);
    assert(service_browser1);

    poll_api->timeout_new(poll_api, catta_elapse_time(&tv, 10000, 0), create_second_service_browser, NULL);

    poll_api->timeout_new(poll_api, catta_elapse_time(&tv, 60000, 0), quit, NULL);


    for (;;)
        if (catta_simple_poll_iterate(simple_poll, -1) != 0)
            break;

    catta_server_free(server);
    catta_simple_poll_free(simple_poll);

    return 0;
}
