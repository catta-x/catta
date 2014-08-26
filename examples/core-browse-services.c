/* PLEASE NOTE *
 * This file demonstrates how to use Catta's core API, this is
 * the embeddable mDNS stack for embedded applications.
 *
 * End user applications should *not* use this API and should use
 * the D-Bus or C APIs, please see
 * client-browse-services.c and glib-integration.c
 *
 * I repeat, you probably do *not* want to use this example.
 */

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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include <catta/core.h>
#include <catta/lookup.h>
#include <catta/simple-watch.h>
#include <catta/malloc.h>
#include <catta/error.h>

static CattaSimplePoll *simple_poll = NULL;
static CattaServer *server = NULL;

static void resolve_callback(
    CattaSServiceResolver *r,
    CATTA_GCC_UNUSED CattaIfIndex iface,
    CATTA_GCC_UNUSED CattaProtocol protocol,
    CattaResolverEvent event,
    const char *name,
    const char *type,
    const char *domain,
    const char *host_name,
    const CattaAddress *address,
    uint16_t port,
    CattaStringList *txt,
    CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {

    assert(r);

    /* Called whenever a service has been resolved successfully or timed out */

    switch (event) {
        case CATTA_RESOLVER_FAILURE:
            fprintf(stderr, "(Resolver) Failed to resolve service '%s' of type '%s' in domain '%s': %s\n", name, type, domain, catta_strerror(catta_server_errno(server)));
            break;

        case CATTA_RESOLVER_FOUND: {
            char a[CATTA_ADDRESS_STR_MAX], *t;

            fprintf(stderr, "(Resolver) Service '%s' of type '%s' in domain '%s':\n", name, type, domain);

            catta_address_snprint(a, sizeof(a), address);
            t = catta_string_list_to_string(txt);
            fprintf(stderr,
                    "\t%s:%u (%s)\n"
                    "\tTXT=%s\n"
                    "\tcookie is %u\n"
                    "\tis_local: %i\n"
                    "\twide_area: %i\n"
                    "\tmulticast: %i\n"
                    "\tcached: %i\n",
                    host_name, port, a,
                    t,
                    catta_string_list_get_service_cookie(txt),
                    !!(flags & CATTA_LOOKUP_RESULT_LOCAL),
                    !!(flags & CATTA_LOOKUP_RESULT_WIDE_AREA),
                    !!(flags & CATTA_LOOKUP_RESULT_MULTICAST),
                    !!(flags & CATTA_LOOKUP_RESULT_CACHED));
            catta_free(t);
        }
    }

    catta_s_service_resolver_free(r);
}

static void browse_callback(
    CattaSServiceBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *name,
    const char *type,
    const char *domain,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    void* userdata) {

    CattaServer *s = userdata;
    assert(b);

    /* Called whenever a new services becomes available on the LAN or is removed from the LAN */

    switch (event) {

        case CATTA_BROWSER_FAILURE:

            fprintf(stderr, "(Browser) %s\n", catta_strerror(catta_server_errno(server)));
            catta_simple_poll_quit(simple_poll);
            return;

        case CATTA_BROWSER_NEW:
            fprintf(stderr, "(Browser) NEW: service '%s' of type '%s' in domain '%s'\n", name, type, domain);

            /* We ignore the returned resolver object. In the callback
               function we free it. If the server is terminated before
               the callback function is called the server will free
               the resolver for us. */

            if (!(catta_s_service_resolver_new(s, iface, protocol, name, type, domain, CATTA_PROTO_UNSPEC, 0, resolve_callback, s)))
                fprintf(stderr, "Failed to resolve service '%s': %s\n", name, catta_strerror(catta_server_errno(s)));

            break;

        case CATTA_BROWSER_REMOVE:
            fprintf(stderr, "(Browser) REMOVE: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
            break;

        case CATTA_BROWSER_ALL_FOR_NOW:
        case CATTA_BROWSER_CACHE_EXHAUSTED:
            fprintf(stderr, "(Browser) %s\n", event == CATTA_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
            break;
    }
}

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char*argv[]) {
    CattaServerConfig config;
    CattaSServiceBrowser *sb = NULL;
    int error;
    int ret = 1;

    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    if (!(simple_poll = catta_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }

    /* Do not publish any local records */
    catta_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;

    /* Set a unicast DNS server for wide area DNS-SD */
    catta_address_parse("192.168.50.1", CATTA_PROTO_UNSPEC, &config.wide_area_servers[0]);
    config.n_wide_area_servers = 1;
    config.enable_wide_area = 1;

    /* Allocate a new server */
    server = catta_server_new(catta_simple_poll_get(simple_poll), &config, NULL, NULL, &error);

    /* Free the configuration data */
    catta_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    if (!server) {
        fprintf(stderr, "Failed to create server: %s\n", catta_strerror(error));
        goto fail;
    }

    /* Create the service browser */
    if (!(sb = catta_s_service_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, "_ipp._tcp", NULL, 0, browse_callback, server))) {
        fprintf(stderr, "Failed to create service browser: %s\n", catta_strerror(catta_server_errno(server)));
        goto fail;
    }

    /* Run the main loop */
    catta_simple_poll_loop(simple_poll);

    ret = 0;

fail:

    /* Cleanup things */
    if (sb)
        catta_s_service_browser_free(sb);

    if (server)
        catta_server_free(server);

    if (simple_poll)
        catta_simple_poll_free(simple_poll);

    return ret;
}
