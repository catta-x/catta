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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>

#include <catta/core.h>
#include <catta/publish.h>
#include <catta/simple-watch.h>
#include <catta/malloc.h>
#include <catta/alternative.h>
#include <catta/error.h>

static CattaSEntryGroup *group = NULL;
static CattaSimplePoll *simple_poll = NULL;
static char *name = NULL;

static void create_services(CattaServer *s);

static void entry_group_callback(CattaServer *s, CattaSEntryGroup *g, CattaEntryGroupState state, CATTA_GCC_UNUSED void *userdata) {
    assert(s);
    assert(g == group);

    /* Called whenever the entry group state changes */

    switch (state) {

        case CATTA_ENTRY_GROUP_ESTABLISHED:

            /* The entry group has been established successfully */
            fprintf(stderr, "Service '%s' successfully established.\n", name);
            break;

        case CATTA_ENTRY_GROUP_COLLISION: {
            char *n;

            /* A service name collision happened. Let's pick a new name */
            n = catta_alternative_service_name(name);
            catta_free(name);
            name = n;

            fprintf(stderr, "Service name collision, renaming service to '%s'\n", name);

            /* And recreate the services */
            create_services(s);
            break;
        }

        case CATTA_ENTRY_GROUP_FAILURE :

            fprintf(stderr, "Entry group failure: %s\n", catta_strerror(catta_server_errno(s)));

            /* Some kind of failure happened while we were registering our services */
            catta_simple_poll_quit(simple_poll);
            break;

        case CATTA_ENTRY_GROUP_UNCOMMITED:
        case CATTA_ENTRY_GROUP_REGISTERING:
            ;
    }
}

static void create_services(CattaServer *s) {
    char r[128];
    int ret;
    assert(s);

    /* If this is the first time we're called, let's create a new entry group */
    if (!group)
        if (!(group = catta_s_entry_group_new(s, entry_group_callback, NULL))) {
            fprintf(stderr, "catta_entry_group_new() failed: %s\n", catta_strerror(catta_server_errno(s)));
            goto fail;
        }

    fprintf(stderr, "Adding service '%s'\n", name);

    /* Create some random TXT data */
    snprintf(r, sizeof(r), "random=%i", rand());

    /* Add the service for IPP */
    if ((ret = catta_server_add_service(s, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, name, "_ipp._tcp", NULL, NULL, 651, "test=blah", r, NULL)) < 0) {
        fprintf(stderr, "Failed to add _ipp._tcp service: %s\n", catta_strerror(ret));
        goto fail;
    }

    /* Add the same service for BSD LPR */
    if ((ret = catta_server_add_service(s, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, name, "_printer._tcp", NULL, NULL, 515, NULL)) < 0) {
        fprintf(stderr, "Failed to add _printer._tcp service: %s\n", catta_strerror(ret));
        goto fail;
    }

    /* Add an additional (hypothetic) subtype */
    if ((ret = catta_server_add_service_subtype(s, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, name, "_printer._tcp", NULL, "_magic._sub._printer._tcp") < 0)) {
        fprintf(stderr, "Failed to add subtype _magic._sub._printer._tcp: %s\n", catta_strerror(ret));
        goto fail;
    }

    /* Tell the server to register the service */
    if ((ret = catta_s_entry_group_commit(group)) < 0) {
        fprintf(stderr, "Failed to commit entry_group: %s\n", catta_strerror(ret));
        goto fail;
    }

    return;

fail:
    catta_simple_poll_quit(simple_poll);
}

static void server_callback(CattaServer *s, CattaServerState state, CATTA_GCC_UNUSED void * userdata) {
    assert(s);

    /* Called whenever the server state changes */

    switch (state) {

        case CATTA_SERVER_RUNNING:
            /* The serve has startup successfully and registered its host
             * name on the network, so it's time to create our services */

            if (!group)
                create_services(s);

            break;

        case CATTA_SERVER_COLLISION: {
            char *n;
            int r;

            /* A host name collision happened. Let's pick a new name for the server */
            n = catta_alternative_host_name(catta_server_get_host_name(s));
            fprintf(stderr, "Host name collision, retrying with '%s'\n", n);
            r = catta_server_set_host_name(s, n);
            catta_free(n);

            if (r < 0) {
                fprintf(stderr, "Failed to set new host name: %s\n", catta_strerror(r));

                catta_simple_poll_quit(simple_poll);
                return;
            }

        }

            /* Fall through */

        case CATTA_SERVER_REGISTERING:

	    /* Let's drop our registered services. When the server is back
             * in CATTA_SERVER_RUNNING state we will register them
             * again with the new host name. */
            if (group)
                catta_s_entry_group_reset(group);

            break;

        case CATTA_SERVER_FAILURE:

            /* Terminate on failure */

            fprintf(stderr, "Server failure: %s\n", catta_strerror(catta_server_errno(s)));
            catta_simple_poll_quit(simple_poll);
            break;

        case CATTA_SERVER_INVALID:
            ;
    }
}

static void signal_exit(int signum) {
    int errnosave = errno;
    catta_simple_poll_quit(simple_poll);
    errno = errnosave;

    (void)signum; // ignore
}

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char*argv[]) {
    CattaServerConfig config;
    CattaServer *server = NULL;
    int error;
    int ret = 1;

    /* Initialize the pseudo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    if (!(simple_poll = catta_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }

    name = catta_strdup("MegaPrinter");

    /* Let's set the host name for this server. */
    catta_server_config_init(&config);
    config.host_name = catta_strdup("gurkiman");
    config.publish_workstation = 0;
    config.publish_no_reverse = 1;

    /* Allocate a new server */
    server = catta_server_new(catta_simple_poll_get(simple_poll), &config, server_callback, NULL, &error);

    /* Free the configuration data */
    catta_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    if (!server) {
        fprintf(stderr, "Failed to create server: %s\n", catta_strerror(error));
        goto fail;
    }

    /* exit cleanly on signals */
    signal(SIGINT, signal_exit);
    signal(SIGTERM, signal_exit);

    /* Run the main loop */
    catta_simple_poll_loop(simple_poll);

    ret = 0;

fail:

    /* Cleanup things */

    if (server)
        catta_server_free(server);

    if (simple_poll)
        catta_simple_poll_free(simple_poll);

    catta_free(name);

    return ret;
}
