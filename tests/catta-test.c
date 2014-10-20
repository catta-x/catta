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
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <catta/malloc.h>
#include <catta/simple-watch.h>
#include <catta/alternative.h>
#include <catta/timeval.h>

#include <catta/core.h>
#include <catta/log.h>
#include <catta/publish.h>
#include <catta/lookup.h>
#include "../src/dns-srv-rr.h"

static CattaSEntryGroup *group = NULL;
static CattaServer *server = NULL;
static char *service_name = NULL;

static const CattaPoll *poll_api;

static void quit_timeout_callback(CATTA_GCC_UNUSED CattaTimeout *timeout, void* userdata) {
    CattaSimplePoll *simple_poll = userdata;

    catta_simple_poll_quit(simple_poll);
}

static void dump_line(const char *text, CATTA_GCC_UNUSED void* userdata) {
    printf("%s\n", text);
}

static void dump_timeout_callback(CattaTimeout *timeout, void* userdata) {
    struct timeval tv;

    CattaServer *catta = userdata;
    catta_server_dump(catta, dump_line, NULL);

    catta_elapse_time(&tv, 5000, 0);
    poll_api->timeout_update(timeout, &tv);
}

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

static const char *resolver_event_to_string(CattaResolverEvent event) {
    switch (event) {
        case CATTA_RESOLVER_FOUND: return "FOUND";
        case CATTA_RESOLVER_FAILURE: return "FAILURE";
    }
    abort();
}

static void record_browser_callback(
    CattaSRecordBrowser *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    CattaRecord *record,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {
    char *t;

    assert(r);

    if (record) {
        catta_log_debug("RB: record [%s] on %i.%i is %s", t = catta_record_to_string(record), iface, protocol, browser_event_to_string(event));
        catta_free(t);
    } else
        catta_log_debug("RB: [%s]", browser_event_to_string(event));

}

static void remove_entries(void);
static void create_entries(int new_name);

static void entry_group_callback(CATTA_GCC_UNUSED CattaServer *s, CATTA_GCC_UNUSED CattaSEntryGroup *g, CattaEntryGroupState state, CATTA_GCC_UNUSED void* userdata) {
    catta_log_debug("entry group state: %i", state);

    if (state == CATTA_ENTRY_GROUP_COLLISION) {
        remove_entries();
        create_entries(1);
        catta_log_debug("Service name conflict, retrying with <%s>", service_name);
    } else if (state == CATTA_ENTRY_GROUP_ESTABLISHED) {
        catta_log_debug("Service established under name <%s>", service_name);
    }
}

static void server_callback(CattaServer *s, CattaServerState state, CATTA_GCC_UNUSED void* userdata) {

    server = s;
    catta_log_debug("server state: %i", state);

    if (state == CATTA_SERVER_RUNNING) {
        catta_log_debug("Server startup complete. Host name is <%s>. Service cookie is %u", catta_server_get_host_name_fqdn(s), catta_server_get_local_service_cookie(s));
        create_entries(0);
    } else if (state == CATTA_SERVER_COLLISION) {
        char *n;
        remove_entries();

        n = catta_alternative_host_name(catta_server_get_host_name(s));

        catta_log_debug("Host name conflict, retrying with <%s>", n);
        catta_server_set_host_name(s, n);
        catta_free(n);
    }
}

static void remove_entries(void) {
    if (group)
        catta_s_entry_group_reset(group);
}

static void create_entries(int new_name) {
    CattaAddress a;
    CattaRecord *r;

    remove_entries();

    if (!group)
        group = catta_s_entry_group_new(server, entry_group_callback, NULL);

    assert(catta_s_entry_group_is_empty(group));

    if (!service_name)
        service_name = catta_strdup("Test Service");
    else if (new_name) {
        char *n = catta_alternative_service_name(service_name);
        catta_free(service_name);
        service_name = n;
    }

    if (catta_server_add_service(server, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, service_name, "_http._tcp", NULL, NULL, 80, "foo", NULL) < 0) {
        catta_log_error("Failed to add HTTP service");
        goto fail;
    }

    if (catta_server_add_service(server, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, service_name, "_ftp._tcp", NULL, NULL, 21, "foo", NULL) < 0) {
        catta_log_error("Failed to add FTP service");
        goto fail;
    }

    if (catta_server_add_service(server, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0,service_name, "_webdav._tcp", NULL, NULL, 80, "foo", NULL) < 0) {
        catta_log_error("Failed to add WEBDAV service");
        goto fail;
    }

    if (catta_server_add_dns_server_address(server, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, NULL, CATTA_DNS_SERVER_RESOLVE, catta_address_parse("192.168.50.1", CATTA_PROTO_UNSPEC, &a), 53) < 0) {
        catta_log_error("Failed to add new DNS Server address");
        goto fail;
    }

    r = catta_record_new_full("cname.local", CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_CNAME, CATTA_DEFAULT_TTL);
    r->data.cname.name = catta_strdup("cocaine.local");

    if (catta_server_add(server, group, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, 0, r) < 0) {
        catta_record_unref(r);
        catta_log_error("Failed to add CNAME record");
        goto fail;
    }
    catta_record_unref(r);

    catta_s_entry_group_commit(group);
    return;

fail:
    if (group)
        catta_s_entry_group_free(group);

    group = NULL;
}

static void hnr_callback(
    CATTA_GCC_UNUSED CattaSHostNameResolver *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaResolverEvent event,
    const char *hostname,
    const CattaAddress *a,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {
    char t[CATTA_ADDRESS_STR_MAX];

    if (a)
        catta_address_snprint(t, sizeof(t), a);

    catta_log_debug("HNR: (%i.%i) <%s> -> %s [%s]", iface, protocol, hostname, a ? t : "n/a", resolver_event_to_string(event));
}

static void ar_callback(
    CATTA_GCC_UNUSED CattaSAddressResolver *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaResolverEvent event,
    const CattaAddress *a,
    const char *hostname,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {
    char t[CATTA_ADDRESS_STR_MAX];

    catta_address_snprint(t, sizeof(t), a);

    catta_log_debug("AR: (%i.%i) %s -> <%s> [%s]", iface, protocol, t, hostname ? hostname : "n/a", resolver_event_to_string(event));
}

static void db_callback(
    CATTA_GCC_UNUSED CattaSDomainBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *domain,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {

    catta_log_debug("DB: (%i.%i) <%s> [%s]", iface, protocol, domain ? domain : "NULL", browser_event_to_string(event));
}

static void stb_callback(
    CATTA_GCC_UNUSED CattaSServiceTypeBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *service_type,
    const char *domain,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {

    catta_log_debug("STB: (%i.%i) %s in <%s> [%s]", iface, protocol, service_type ? service_type : "NULL", domain ? domain : "NULL", browser_event_to_string(event));
}

static void sb_callback(
    CATTA_GCC_UNUSED CattaSServiceBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *name,
    const char *service_type,
    const char *domain,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {
    catta_log_debug("SB: (%i.%i) <%s> as %s in <%s> [%s]", iface, protocol, name ? name : "NULL", service_type ? service_type : "NULL", domain ? domain : "NULL", browser_event_to_string(event));
}

static void sr_callback(
    CATTA_GCC_UNUSED CattaSServiceResolver *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaResolverEvent event,
    const char *name,
    const char*service_type,
    const char*domain_name,
    const char*hostname,
    const CattaAddress *a,
    uint16_t port,
    CattaStringList *txt,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {

    if (event != CATTA_RESOLVER_FOUND)
        catta_log_debug("SR: (%i.%i) <%s> as %s in <%s> [%s]", iface, protocol, name, service_type, domain_name, resolver_event_to_string(event));
    else {
        char t[CATTA_ADDRESS_STR_MAX], *s;

        catta_address_snprint(t, sizeof(t), a);

        s = catta_string_list_to_string(txt);
        catta_log_debug("SR: (%i.%i) <%s> as %s in <%s>: %s/%s:%i (%s) [%s]", iface, protocol, name, service_type, domain_name, hostname, t, port, s, resolver_event_to_string(event));
        catta_free(s);
    }
}

static void dsb_callback(
    CATTA_GCC_UNUSED CattaSDNSServerBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char*hostname,
    const CattaAddress *a,
    uint16_t port,
    CATTA_GCC_UNUSED CattaLookupResultFlags flags,
    CATTA_GCC_UNUSED void* userdata) {

    char t[CATTA_ADDRESS_STR_MAX] = "n/a";

    if (a)
        catta_address_snprint(t, sizeof(t), a);

    catta_log_debug("DSB: (%i.%i): %s/%s:%i [%s]", iface, protocol, hostname ? hostname : "NULL", t, port, browser_event_to_string(event));
}

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {
    CattaSRecordBrowser *r;
    CattaSHostNameResolver *hnr;
    CattaSAddressResolver *ar;
    CattaKey *k;
    CattaServerConfig config;
    CattaAddress a;
    CattaSDomainBrowser *db;
    CattaSServiceTypeBrowser *stb;
    CattaSServiceBrowser *sb;
    CattaSServiceResolver *sr;
    CattaSDNSServerBrowser *dsb;
    CattaSimplePoll *simple_poll;
    int error;
    struct timeval tv;

    simple_poll = catta_simple_poll_new();
    poll_api = catta_simple_poll_get(simple_poll);

    catta_server_config_init(&config);

    catta_address_parse("192.168.50.1", CATTA_PROTO_UNSPEC, &config.wide_area_servers[0]);
    config.n_wide_area_servers = 1;
    config.enable_wide_area = 1;

    server = catta_server_new(poll_api, &config, server_callback, NULL, &error);
    catta_server_config_free(&config);

    k = catta_key_new("_http._tcp.0pointer.de", CATTA_DNS_CLASS_IN, CATTA_DNS_TYPE_PTR);
    r = catta_s_record_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, k, 0, record_browser_callback, NULL);
    catta_key_unref(k);

    hnr = catta_s_host_name_resolver_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, "cname.local", CATTA_PROTO_UNSPEC, 0, hnr_callback, NULL);

    ar = catta_s_address_resolver_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, catta_address_parse("192.168.50.1", CATTA_PROTO_INET, &a), 0, ar_callback, NULL);

    db = catta_s_domain_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, NULL, CATTA_DOMAIN_BROWSER_BROWSE, 0, db_callback, NULL);

    stb = catta_s_service_type_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, NULL, 0, stb_callback, NULL);

    sb = catta_s_service_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, "_http._tcp", NULL, 0, sb_callback, NULL);

    sr = catta_s_service_resolver_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, "Ecstasy HTTP", "_http._tcp", "local", CATTA_PROTO_UNSPEC, 0, sr_callback, NULL);

    dsb = catta_s_dns_server_browser_new(server, CATTA_IF_UNSPEC, CATTA_PROTO_UNSPEC, "local", CATTA_DNS_SERVER_RESOLVE, CATTA_PROTO_UNSPEC, 0, dsb_callback, NULL);

    catta_elapse_time(&tv, 1000*5, 0);
    poll_api->timeout_new(poll_api, &tv, dump_timeout_callback, server);

    catta_elapse_time(&tv, 1000*60, 0);
    poll_api->timeout_new(poll_api, &tv, quit_timeout_callback, simple_poll);

    catta_simple_poll_loop(simple_poll);

    catta_s_record_browser_free(r);
    catta_s_host_name_resolver_free(hnr);
    catta_s_address_resolver_free(ar);
    catta_s_domain_browser_free(db);
    catta_s_service_type_browser_free(stb);
    catta_s_service_browser_free(sb);
    catta_s_service_resolver_free(sr);
    catta_s_dns_server_browser_free(dsb);

    if (group)
        catta_s_entry_group_free(group);

    if (server)
        catta_server_free(server);

    if (simple_poll)
        catta_simple_poll_free(simple_poll);

    catta_free(service_name);

    return 0;
}
