#ifndef foointernalhfoo
#define foointernalhfoo

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

/** A locally registered DNS resource record */
typedef struct CattaEntry CattaEntry;

#include <catta/llist.h>
#include <catta/watch.h>
#include <catta/timeval.h>
#include <catta/core.h>

#include "iface.h"
#include "prioq.h"
#include "timeeventq.h"
#include "announce.h"
#include "browse.h"
#include "dns.h"
#include "rrlist.h"
#include "hashmap.h"
#include "wide-area.h"
#include "multicast-lookup.h"
#include "dns-srv-rr.h"

#define CATTA_LEGACY_UNICAST_REFLECT_SLOTS_MAX 100

#define CATTA_FLAGS_VALID(flags, max) (!((flags) & ~(max)))

#define CATTA_RR_HOLDOFF_MSEC 1000
#define CATTA_RR_HOLDOFF_MSEC_RATE_LIMIT 20000
#define CATTA_RR_RATE_LIMIT_COUNT 15

#ifndef _WIN32
#define closesocket close
#define winsock_init()
#define winsock_exit()
#endif

typedef struct CattaLegacyUnicastReflectSlot CattaLegacyUnicastReflectSlot;

struct CattaLegacyUnicastReflectSlot {
    CattaServer *server;

    uint16_t id, original_id;
    CattaAddress address;
    uint16_t port;
    int iface;
    struct timeval elapse_time;
    CattaTimeEvent *time_event;
};

struct CattaEntry {
    CattaServer *server;
    CattaSEntryGroup *group;

    int dead;

    CattaPublishFlags flags;
    CattaRecord *record;
    CattaIfIndex iface;
    CattaProtocol protocol;

    CATTA_LLIST_FIELDS(CattaEntry, entries);
    CATTA_LLIST_FIELDS(CattaEntry, by_key);
    CATTA_LLIST_FIELDS(CattaEntry, by_group);

    CATTA_LLIST_HEAD(CattaAnnouncer, announcers);
};

struct CattaSEntryGroup {
    CattaServer *server;
    int dead;

    CattaEntryGroupState state;
    void* userdata;
    CattaSEntryGroupCallback callback;

    unsigned n_probing;

    unsigned n_register_try;
    struct timeval register_time;
    CattaTimeEvent *register_time_event;

    struct timeval established_at;

    CATTA_LLIST_FIELDS(CattaSEntryGroup, groups);
    CATTA_LLIST_HEAD(CattaEntry, entries);
};

struct CattaServer {
    const CattaPoll *poll_api;

    CattaInterfaceMonitor *monitor;
    CattaServerConfig config;

    CATTA_LLIST_HEAD(CattaEntry, entries);
    CattaHashmap *entries_by_key;

    CATTA_LLIST_HEAD(CattaSEntryGroup, groups);

    CATTA_LLIST_HEAD(CattaSRecordBrowser, record_browsers);
    CattaHashmap *record_browser_hashmap;
    CATTA_LLIST_HEAD(CattaSHostNameResolver, host_name_resolvers);
    CATTA_LLIST_HEAD(CattaSAddressResolver, address_resolvers);
    CATTA_LLIST_HEAD(CattaSDomainBrowser, domain_browsers);
    CATTA_LLIST_HEAD(CattaSServiceTypeBrowser, service_type_browsers);
    CATTA_LLIST_HEAD(CattaSServiceBrowser, service_browsers);
    CATTA_LLIST_HEAD(CattaSServiceResolver, service_resolvers);
    CATTA_LLIST_HEAD(CattaSDNSServerBrowser, dns_server_browsers);

    int need_entry_cleanup, need_group_cleanup, need_browser_cleanup;

    /* Used for scheduling RR cleanup */
    CattaTimeEvent *cleanup_time_event;

    CattaTimeEventQueue *time_event_queue;

    char *host_name, *host_name_fqdn, *domain_name;

    int fd_ipv4, fd_ipv6,
        /* The following two sockets two are used for reflection only */
        fd_legacy_unicast_ipv4, fd_legacy_unicast_ipv6;

    CattaWatch *watch_ipv4, *watch_ipv6,
        *watch_legacy_unicast_ipv4, *watch_legacy_unicast_ipv6;

    CattaServerState state;
    CattaServerCallback callback;
    void* userdata;

    CattaSEntryGroup *hinfo_entry_group;
    CattaSEntryGroup *browse_domain_entry_group;
    unsigned n_host_rr_pending;

    /* Used for assembling responses */
    CattaRecordList *record_list;

    /* Used for reflection of legacy unicast packets */
    CattaLegacyUnicastReflectSlot **legacy_unicast_reflect_slots;
    uint16_t legacy_unicast_reflect_id;

    /* The last error code */
    int error;

    /* The local service cookie */
    uint32_t local_service_cookie;

    CattaMulticastLookupEngine *multicast_lookup_engine;
    CattaWideAreaLookupEngine *wide_area_lookup_engine;
};

void catta_entry_free(CattaServer*s, CattaEntry *e);
void catta_entry_group_free(CattaServer *s, CattaSEntryGroup *g);

void catta_cleanup_dead_entries(CattaServer *s);

void catta_server_prepare_response(CattaServer *s, CattaInterface *i, CattaEntry *e, int unicast_response, int auxiliary);
void catta_server_prepare_matching_responses(CattaServer *s, CattaInterface *i, CattaKey *k, int unicast_response);
void catta_server_generate_response(CattaServer *s, CattaInterface *i, CattaDnsPacket *p, const CattaAddress *a, uint16_t port, int legacy_unicast, int is_probe);

void catta_s_entry_group_change_state(CattaSEntryGroup *g, CattaEntryGroupState state);

int catta_entry_is_commited(CattaEntry *e);

void catta_server_enumerate_aux_records(CattaServer *s, CattaInterface *i, CattaRecord *r, void (*callback)(CattaServer *s, CattaRecord *r, int flush_cache, void* userdata), void* userdata);

void catta_host_rr_entry_group_callback(CattaServer *s, CattaSEntryGroup *g, CattaEntryGroupState state, void *userdata);

void catta_server_decrease_host_rr_pending(CattaServer *s);

int catta_server_set_errno(CattaServer *s, int error);

int catta_server_is_service_local(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, const char *name);
int catta_server_is_record_local(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, CattaRecord *record);

int catta_server_add_ptr(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    uint32_t ttl,
    const char *name,
    const char *dest);

#define CATTA_CHECK_VALIDITY(server, expression, error) { \
        if (!(expression)) \
            return catta_server_set_errno((server), (error)); \
}

#define CATTA_CHECK_VALIDITY_RETURN_NULL(server, expression, error) { \
        if (!(expression)) { \
            catta_server_set_errno((server), (error)); \
            return NULL; \
        } \
}

#define CATTA_CHECK_VALIDITY_SET_RET_GOTO_FAIL(server, expression, error) {\
    if (!(expression)) { \
        ret = catta_server_set_errno((server), (error)); \
        goto fail; \
    } \
}

#define CATTA_ASSERT_TRUE(expression) { \
    int __tmp = !!(expression); \
    assert(__tmp); \
}

#define CATTA_ASSERT_SUCCESS(expression) { \
    int __tmp = (expression); \
    assert(__tmp == 0); \
}

#endif
