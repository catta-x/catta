#ifndef fooifacehfoo
#define fooifacehfoo

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

typedef struct CattaInterfaceMonitor CattaInterfaceMonitor;
typedef struct CattaInterfaceAddress CattaInterfaceAddress;
typedef struct CattaInterface CattaInterface;
typedef struct CattaHwInterface CattaHwInterface;

#include <catta/llist.h>
#include <catta/address.h>

#include "internal.h"
#include "cache.h"
#include "response-sched.h"
#include "query-sched.h"
#include "probe-sched.h"
#include "dns.h"
#include "announce.h"
#include "browse.h"
#include "querier.h"

#ifdef HAVE_NETLINK
#include "iface-linux.h"
#elif defined(HAVE_PF_ROUTE)
#include "iface-pfroute.h"
#elif defined(_WIN32)
#include "iface-windows.h"
#else
typedef struct CattaInterfaceMonitorOSDep CattaInterfaceMonitorOSDep;
struct CattaInterfaceMonitorOSDep {

    unsigned query_addr_seq, query_link_seq;

    enum {
        LIST_IFACE,
        LIST_ADDR,
        LIST_DONE
    } list;
};
#endif

#define CATTA_MAC_ADDRESS_MAX 32

struct CattaInterfaceMonitor {
    CattaServer *server;
    CattaHashmap *hashmap;

    CATTA_LLIST_HEAD(CattaInterface, interfaces);
    CATTA_LLIST_HEAD(CattaHwInterface, hw_interfaces);

    int list_complete;
    CattaInterfaceMonitorOSDep osdep;
};

struct CattaHwInterface {
    CattaInterfaceMonitor *monitor;

    CATTA_LLIST_FIELDS(CattaHwInterface, hardware);

    char *name;
    CattaIfIndex index;
    int flags_ok;

    unsigned mtu;

    uint8_t mac_address[CATTA_MAC_ADDRESS_MAX];
    size_t mac_address_size;

    CattaSEntryGroup *entry_group;

    /* Packet rate limiting */
    struct timeval ratelimit_begin;
    unsigned ratelimit_counter;

    CATTA_LLIST_HEAD(CattaInterface, interfaces);
};

struct CattaInterface {
    CattaInterfaceMonitor *monitor;
    CattaHwInterface *hardware;

    CATTA_LLIST_FIELDS(CattaInterface, iface);
    CATTA_LLIST_FIELDS(CattaInterface, by_hardware);

    CattaProtocol protocol;
    int announcing;
    CattaAddress local_mcast_address;
    int mcast_joined;

    CattaCache *cache;

    CattaQueryScheduler *query_scheduler;
    CattaResponseScheduler * response_scheduler;
    CattaProbeScheduler *probe_scheduler;

    CATTA_LLIST_HEAD(CattaInterfaceAddress, addresses);
    CATTA_LLIST_HEAD(CattaAnnouncer, announcers);

    CattaHashmap *queriers_by_key;
    CATTA_LLIST_HEAD(CattaQuerier, queriers);
};

struct CattaInterfaceAddress {
    CattaInterfaceMonitor *monitor;
    CattaInterface *iface;

    CATTA_LLIST_FIELDS(CattaInterfaceAddress, address);

    CattaAddress address;
    unsigned prefix_len;

    int global_scope;
    int deprecated;

    CattaSEntryGroup *entry_group;
};

CattaInterfaceMonitor *catta_interface_monitor_new(CattaServer *server);
void catta_interface_monitor_free(CattaInterfaceMonitor *m);

int catta_interface_monitor_init_osdep(CattaInterfaceMonitor *m);
void catta_interface_monitor_free_osdep(CattaInterfaceMonitor *m);
void catta_interface_monitor_sync(CattaInterfaceMonitor *m);

typedef void (*CattaInterfaceMonitorWalkCallback)(CattaInterfaceMonitor *m, CattaInterface *i, void* userdata);
void catta_interface_monitor_walk(CattaInterfaceMonitor *m, CattaIfIndex idx, CattaProtocol protocol, CattaInterfaceMonitorWalkCallback callback, void* userdata);
int catta_dump_caches(CattaInterfaceMonitor *m, CattaDumpCallback callback, void* userdata);

void catta_interface_monitor_update_rrs(CattaInterfaceMonitor *m, int remove_rrs);
int catta_address_is_local(CattaInterfaceMonitor *m, const CattaAddress *a);
void catta_interface_monitor_check_relevant(CattaInterfaceMonitor *m);

/* CattaHwInterface */

CattaHwInterface *catta_hw_interface_new(CattaInterfaceMonitor *m, CattaIfIndex idx);
void catta_hw_interface_free(CattaHwInterface *hw, int send_goodbye);

void catta_hw_interface_update_rrs(CattaHwInterface *hw, int remove_rrs);
void catta_hw_interface_check_relevant(CattaHwInterface *hw);

CattaHwInterface* catta_interface_monitor_get_hw_interface(CattaInterfaceMonitor *m, int idx);

/* CattaInterface */

CattaInterface* catta_interface_new(CattaInterfaceMonitor *m, CattaHwInterface *hw, CattaProtocol protocol);
void catta_interface_free(CattaInterface *i, int send_goodbye);

void catta_interface_update_rrs(CattaInterface *i, int remove_rrs);
void catta_interface_check_relevant(CattaInterface *i);
int catta_interface_is_relevant(CattaInterface *i);

void catta_interface_send_packet(CattaInterface *i, CattaDnsPacket *p);
void catta_interface_send_packet_unicast(CattaInterface *i, CattaDnsPacket *p, const CattaAddress *a, uint16_t port);

int catta_interface_post_query(CattaInterface *i, CattaKey *k, int immediately, unsigned *ret_id);
int catta_interface_withraw_query(CattaInterface *i, unsigned id);
int catta_interface_post_response(CattaInterface *i, CattaRecord *record, int flush_cache, const CattaAddress *querier, int immediately);
int catta_interface_post_probe(CattaInterface *i, CattaRecord *p, int immediately);

int catta_interface_match(CattaInterface *i, CattaIfIndex idx, CattaProtocol protocol);
int catta_interface_address_on_link(CattaInterface *i, const CattaAddress *a);
int catta_interface_has_address(CattaInterfaceMonitor *m, CattaIfIndex iface, const CattaAddress *a);

CattaInterface* catta_interface_monitor_get_interface(CattaInterfaceMonitor *m, CattaIfIndex idx, CattaProtocol protocol);

/* CattaInterfaceAddress */

CattaInterfaceAddress *catta_interface_address_new(CattaInterfaceMonitor *m, CattaInterface *i, const CattaAddress *addr, unsigned prefix_len);
void catta_interface_address_free(CattaInterfaceAddress *a);

void catta_interface_address_update_rrs(CattaInterfaceAddress *a, int remove_rrs);
int catta_interface_address_is_relevant(CattaInterfaceAddress *a);

CattaInterfaceAddress* catta_interface_monitor_get_address(CattaInterfaceMonitor *m, CattaInterface *i, const CattaAddress *raddr);

CattaIfIndex catta_find_interface_for_address(CattaInterfaceMonitor *m, const CattaAddress *a);

#endif
