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

#include "iface.h"
#include "iface-windows.h"

#include <stdlib.h> // wcstombs
#include <catta/malloc.h>
#include <catta/log.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <assert.h>
#include "compat/windows/wincompat.h"
#include "hashmap.h"
#include "util.h"   // catta_format_mac_address
#include "fdutil.h" // catta_set_nonblock


typedef enum {
    INTERFACE_CHANGE_EVENT,
    ADDRESS_CHANGE_EVENT
} ChangeEventType;

struct ChangeEvent {
    CATTA_LLIST_FIELDS(ChangeEvent, event);
    ChangeEventType type;
    MIB_NOTIFICATION_TYPE notification_type;
    union {
        MIB_IPINTERFACE_ROW iface;
        MIB_UNICASTIPADDRESS_ROW addr;
    } data;
};


// helper: determine the global_scope flag for an address
static void set_global_scope_flag(CattaInterfaceAddress *ifaddr, const CattaAddress *addr)
{
    if(addr->proto == CATTA_PROTO_INET6) {
        const struct in6_addr *ia = (struct in6_addr *)addr->data.ipv6.address;
        ifaddr->global_scope = !(IN6_IS_ADDR_LINKLOCAL(ia) || IN6_IS_ADDR_MULTICAST(ia));
    } else {
        ifaddr->global_scope = 1;
    }
}

// integrate the information from an IP_ADAPTER_UNICAST_ADDRESS structure for
// given CattaHwInterface into the CattaInterfaceMonitor
static void ip_adapter_unicast_address(CattaInterfaceMonitor *m,
                                       CattaHwInterface *hw,
                                       IP_ADAPTER_UNICAST_ADDRESS *a)
{
    CattaInterface *iface;
    CattaAddress addr;
    CattaInterfaceAddress *ifaddr;
    struct sockaddr *sa = a->Address.lpSockaddr;

    // skip transient addresses; to quote MSDN: "The IP address is a cluster
    // address and should not be used by most applications."
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366066(v=vs.85).aspx
    if(a->Flags & IP_ADAPTER_ADDRESS_TRANSIENT)
        return;

    // fill addr struct for address lookup
    switch(sa->sa_family) {
    case AF_INET:
        memcpy(addr.data.data, &((struct sockaddr_in *)sa)->sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(addr.data.data, &((struct sockaddr_in6 *)sa)->sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        catta_log_debug("unexpected address family on interface %d: %u", hw->index, sa->sa_family);
        return;
    }
    addr.proto = catta_af_to_proto(sa->sa_family);

    // get protocol-specific CattaInterface object
    if(!(iface = catta_interface_monitor_get_interface(m, hw->index, addr.proto))) {
        catta_log_error("CattaInterface (index %d, proto %d) not found", hw->index, addr.proto);
        return;
    }

    // find or allocate a CattaInterfaceAddress struct for this address
    if(!(ifaddr = catta_interface_monitor_get_address(m, iface, &addr))) {
        if(!(ifaddr = catta_interface_address_new(m, iface, &addr, a->OnLinkPrefixLength))) {
            catta_log_error("out of memory in ip_adapter_unicast_address");
            return;
        }
    }

    set_global_scope_flag(ifaddr, &addr);
}

// integrate the information from an IP_ADAPTER_ADDRESSES structure
// as returned by GetAdaptersAddresses into the CattaInterfaceMonitor
static void ip_adapter(CattaInterfaceMonitor *m, IP_ADAPTER_ADDRESSES *p)
{
    IP_ADAPTER_UNICAST_ADDRESS *a;
    CattaIfIndex idx;
    CattaHwInterface *hw;
    size_t n;

    // we want an index specific to the hardware interface, but Windows
    // has one for IPv4 and one for IPv6. it seems like these are always the
    // same unless one of the protocols is not available. let's have a bunch of
    // checks...
    if(!p->IfIndex && !p->Ipv6IfIndex) {
        return; // no usable protocols
    } else if(!p->IfIndex) {
        idx = p->Ipv6IfIndex;   // IPv6 but no IPv4 (huh!)
    } else if(!p->Ipv6IfIndex) {
        idx = p->IfIndex;       // IPv4 but no IPv6
    } else if(p->IfIndex == p->Ipv6IfIndex) {
        idx = p->IfIndex;       // same index for both protocols
    } else {
        // both indexes valid but not equal
        catta_log_error("unsupported interface: %ls (IfIndex and Ipv6IfIndex differ: %u/%u)",
            p->FriendlyName, (unsigned int)p->IfIndex, (unsigned int)p->Ipv6IfIndex);
        return;
    }

    // find the CattaHwInterface by index or allocate a new one
    if((hw = catta_interface_monitor_get_hw_interface(m, idx)) == NULL) {
        if((hw = catta_hw_interface_new(m, idx)) == NULL) {
            catta_log_error("catta_hw_interface_new failed in ip_adapter_address");
            return;
        }
    }

    // fill the CattaHwInterface struct with data
    // notice: this code is essentially duplicated in update_hw_interface()
    hw->flags_ok =
        (p->OperStatus == IfOperStatusUp) &&
        !(p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) &&
        !(p->Flags & IP_ADAPTER_NO_MULTICAST) &&
        (m->server->config.allow_point_to_point || !(p->IfType == IF_TYPE_PPP));
            // XXX what about IF_TYPE_TUNNEL?

    n = wcstombs(NULL, p->FriendlyName, 0) + 1;
    catta_free(hw->name);
    hw->name = catta_new(char, n);
    wcstombs(hw->name, p->FriendlyName, n);

    hw->mtu = p->Mtu;

    hw->mac_address_size = p->PhysicalAddressLength;
    if(hw->mac_address_size > CATTA_MAC_ADDRESS_MAX)
        hw->mac_address_size = CATTA_MAC_ADDRESS_MAX;
    memcpy(hw->mac_address, p->PhysicalAddress, hw->mac_address_size);

    // process addresses
    // XXX remove addresses that are no longer in the list
    for(a=p->FirstUnicastAddress; a; a=a->Next)
        ip_adapter_unicast_address(m, hw, a);
}


// place the event into the queue to be handled (by the main thread)
// and wake the event handler if necessary
static void queue_event(CattaInterfaceMonitor *m, ChangeEvent *ev)
{
    char c = 'X';

    if(!ev)
        return;

    if(!pthread_mutex_lock(&m->osdep.mutex)) {
        // queue the event
        CATTA_LLIST_APPEND(ChangeEvent, event, m->osdep.events, ev);

        // wake the handler
        writepipe(m->osdep.pipefd[1], &c, sizeof(c));

        pthread_mutex_unlock(&m->osdep.mutex);
    } else {
        catta_log_debug(__FILE__": queue_event: could not lock mutex");
        catta_free(ev);
    }
}

// copy the given data row into an appropriate change event struct
static ChangeEvent *new_event(ChangeEventType type, MIB_NOTIFICATION_TYPE ntype, void *row, size_t n)
{
    ChangeEvent *ev;

    if(!row)
        return NULL;

    if(!(ev = catta_new(ChangeEvent, 1)))
        return NULL;

    ev->type = type;
    ev->notification_type = ntype;
    memcpy(&ev->data, row, n);

    return ev;
}

static void WINAPI icn_callback(void *m, MIB_IPINTERFACE_ROW *row, MIB_NOTIFICATION_TYPE type)
{
    queue_event(m, new_event(INTERFACE_CHANGE_EVENT, type, row, sizeof(*row)));
}

static void WINAPI acn_callback(void *m, MIB_UNICASTIPADDRESS_ROW *row, MIB_NOTIFICATION_TYPE type)
{
    queue_event(m, new_event(ADDRESS_CHANGE_EVENT, type, row, sizeof(*row)));
}

static void update_hw_interface(CattaHwInterface *hw)
{
    MIB_IF_ROW2 row;
    DWORD r;
    size_t n;
    int multicast;  // synthetic flag

    row.InterfaceLuid.Value = 0;
    row.InterfaceIndex = hw->index;
    if((r = GetIfEntry2(&row)) != NO_ERROR) {
        catta_log_error("GetIfEntry2 failed for iface %d (error %u)", hw->index, (unsigned int)r);
        return;
    }

    // fill the CattaHwInterface struct with data
    // notice: this code is essentially duplicated from ip_adapter()
    // notice: not sure where to find the IP_ADAPTER_NO_MULTICAST flag from an
    //         MIB_IF_ROW2 struct, so try to deduce it otherwise
    //         cf. http://msdn.microsoft.com/en-us/windows/desktop/ff568739(v=vs.100).aspx
    multicast = row.AccessType == NET_IF_ACCESS_BROADCAST ||
                row.AccessType == NET_IF_ACCESS_POINT_TO_POINT;
    hw->flags_ok =
        (row.OperStatus == IfOperStatusUp) &&
        !(row.Type == IF_TYPE_SOFTWARE_LOOPBACK) &&
        multicast &&
        (hw->monitor->server->config.allow_point_to_point || !(row.Type == IF_TYPE_PPP));
            // XXX what about IF_TYPE_TUNNEL?

    n = wcstombs(NULL, row.Alias, 0) + 1;
    catta_free(hw->name);
    hw->name = catta_new(char, n);
    wcstombs(hw->name, row.Alias, n);

    hw->mtu = row.Mtu;

    hw->mac_address_size = row.PhysicalAddressLength;
    if(hw->mac_address_size > CATTA_MAC_ADDRESS_MAX)
        hw->mac_address_size = CATTA_MAC_ADDRESS_MAX;
    memcpy(hw->mac_address, row.PhysicalAddress, hw->mac_address_size);

    catta_hw_interface_check_relevant(hw);
    catta_hw_interface_update_rrs(hw, 0);
}

static void handle_iface_event(CattaInterfaceMonitor *m, MIB_IPINTERFACE_ROW *row, MIB_NOTIFICATION_TYPE type)
{
    CattaIfIndex idx = row->InterfaceIndex;
    CattaProtocol proto = catta_af_to_proto(row->Family);
    const char *protostr = catta_proto_to_string(proto);
    CattaInterface *iface;
    CattaHwInterface *hw;

    // see if we know this interface
    iface = catta_interface_monitor_get_interface(m, idx, proto);
    hw = iface ? iface->hardware : catta_interface_monitor_get_hw_interface(m, idx);

    // print debug messages for some unexpected cases
    if(type==MibParameterNotification && !iface)
        catta_log_debug("ParameterNotification received for unknown interface %d (%s)", idx, protostr);
    if(type==MibDeleteInstance && !iface)
        catta_log_debug("DeleteInstance received for unknown interface %d (%s)", idx, protostr);
    if(type==MibAddInstance && iface)
        catta_log_debug("AddInstance received for existing interface %d (%s)", idx, protostr);
    if(iface && !hw)
        catta_log_debug("missing CattaHwInterface for interface %d (%s)", idx, protostr);

    switch(type) {
    case MibParameterNotification:
    case MibAddInstance:
        // create the physical interface if it is missing
        if(!hw) {
            if((hw = catta_hw_interface_new(m, idx)) == NULL) {
                catta_log_error("catta_hw_interface_new failed in handle_iface_event");
                return;
            }
        }

        // create the protocol-specific interface if it is missing
        if(!iface) {
            if((iface = catta_interface_new(m, hw, proto)) == NULL) {
                catta_log_error("catta_interface_new failed in handle_iface_event");
                return;
            }
        }

        assert(iface != NULL);
        assert(hw != NULL);
        assert(iface->hardware == hw);

        update_hw_interface(hw);
        break;
    case MibDeleteInstance:
        if(iface)
            catta_interface_free(iface, 0);

        // free the hardware interface when there are no more protocol-specific interfaces
        if(hw && !hw->interfaces)
            catta_hw_interface_free(hw, 0);
        break;
    default:
        catta_log_debug("unexpected type (%d) of interface change notification received", type);
    }
}

static void handle_addr_event(CattaInterfaceMonitor *m, MIB_UNICASTIPADDRESS_ROW *row, MIB_NOTIFICATION_TYPE type)
{
    CattaIfIndex idx = row->InterfaceIndex;
    CattaInterfaceAddress *ifaddr;
    CattaInterface *iface;
    CattaAddress addr;
    const char *protostr;

    // fill addr struct for address lookup
    switch(row->Address.si_family) {
    case AF_INET:
        memcpy(addr.data.data, &row->Address.Ipv4.sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(addr.data.data, &row->Address.Ipv6.sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        catta_log_debug("unexpected address family on interface %d: %u", idx, row->Address.si_family);
        return;
    }
    addr.proto = catta_af_to_proto(row->Address.si_family);
    protostr = catta_proto_to_string(addr.proto);

    // see if we know this address/interface
    iface = catta_interface_monitor_get_interface(m, idx, addr.proto);
    ifaddr = iface ? catta_interface_monitor_get_address(m, iface, &addr) : NULL;

    // print debug messages for some unexpected cases
    if(type==MibParameterNotification && !ifaddr)
        catta_log_debug("ParameterNotification received for unknown address on interface %d (%s)", idx, protostr);
    if(type==MibDeleteInstance && !ifaddr)
        catta_log_debug("DeleteInstance received for unknown address on interface %d (%s)", idx, protostr);
    if(type==MibAddInstance && ifaddr)
        catta_log_debug("AddInstance received for existing address on interface %d (%s)", idx, protostr);
    if(ifaddr && !iface)
        catta_log_debug("missing CattaInterface for address on interface %d (%s)", idx, protostr);

    switch(type) {
    case MibParameterNotification:
    case MibAddInstance:
        // fetch the full event data
        if(GetUnicastIpAddressEntry(row) != NO_ERROR) {
            catta_log_error("GetUnicastIpAddressEntry failed in handle_addr_event");
            return;
        }

        // skip addresses that are not suitable as source addresses
        if(row->SkipAsSource)
            return;

        // create the interface if it is missing
        if(!iface) {
            CattaHwInterface *hw;

            if((hw = catta_interface_monitor_get_hw_interface(m, idx)) == NULL) {
                catta_log_error("interface %d not found in handle_addr_event", idx);
                return;
            }

            if((iface = catta_interface_new(m, hw, addr.proto)) == NULL) {
                catta_log_error("catta_interface_new failed in handle_addr_event");
                return;
            }
        }
        assert(iface != NULL);

        // create the interface-associated address if it is missing
        if(!ifaddr) {
            unsigned prefixlen = row->OnLinkPrefixLength;

            if((ifaddr = catta_interface_address_new(m, iface, &addr, prefixlen)) == NULL) {
                catta_log_error("catta_interface_address_new failed in handle_addr_event");
                return;
            }
        }
        assert(ifaddr != NULL);

        set_global_scope_flag(ifaddr, &addr);
        break;
    case MibDeleteInstance:
        if(ifaddr)
            catta_interface_address_free(ifaddr);
        break;
    default:
        catta_log_debug("unexpected type (%d) of address change notification received", type);
    }

    if(iface) {
        catta_interface_check_relevant(iface);
        catta_interface_update_rrs(iface, 0);
    }
}

static void handle_events(CattaInterfaceMonitor *m)
{
    char buf[16];
    ChangeEvent *ev;

    if(!pthread_mutex_lock(&m->osdep.mutex)) {
        // clear the pipe
        while(readpipe(m->osdep.pipefd[0], buf, sizeof(buf)) == sizeof(buf)) {}

        while((ev = m->osdep.events) != NULL) {
            CATTA_LLIST_REMOVE(ChangeEvent, event, m->osdep.events, ev);

            // dispatch to the appropriate handler
            switch(ev->type) {
            case INTERFACE_CHANGE_EVENT:
                handle_iface_event(m, &ev->data.iface, ev->notification_type);
                break;
            case ADDRESS_CHANGE_EVENT:
                handle_addr_event(m, &ev->data.addr, ev->notification_type);
                break;
            default:
                catta_log_debug("unhandled change event type in handle_events");
            }

            catta_free(ev);
        }

        pthread_mutex_unlock(&m->osdep.mutex);
    }
}

static void pipe_callback(CattaWatch *w, int fd, CattaWatchEvent event, void *m)
{
    // silence "unused parameter" warnings
    (void)w;
    (void)fd;
    (void)event;

    handle_events(m);
}


int catta_interface_monitor_init_osdep(CattaInterfaceMonitor *m)
{
    DWORD r;

    pthread_mutex_init(&m->osdep.mutex, NULL);

    CATTA_LLIST_HEAD_INIT(ChangeEvent, m->osdep.events);

    if(pipe(m->osdep.pipefd) < 0) {
        catta_log_error("pipe() in catta_interface_monitor_init_osdep failed");
        return -1;
    }
    if(catta_set_nonblock(m->osdep.pipefd[0]) < 0 ||
       catta_set_nonblock(m->osdep.pipefd[1]) < 0)
    {
        catta_log_error(__FILE__": catta_set_nonblock failed: %s", errnostrsocket());
        goto fail;
    }

    m->osdep.icnhandle = NULL;
    m->osdep.acnhandle = NULL;

    // register handler for change events
    m->osdep.watch = m->server->poll_api->watch_new(m->server->poll_api,
                                                    m->osdep.pipefd[0],
                                                    CATTA_WATCH_IN,
                                                    pipe_callback,
                                                    m);
    if(!m->osdep.watch) {
        catta_log_error(__FILE__": Failed to create watch.");
        goto fail;
    }

    // request async notification on interface changes
    r = NotifyIpInterfaceChange(AF_UNSPEC,
                                // icn_callback needs to be WINAPI but
                                // MingW up to 3.1.0 erroneously defines
                                // PIPINTERFACE_CHANGE_CALLBACK without it
                                (PIPINTERFACE_CHANGE_CALLBACK)icn_callback,
                                m, FALSE, &m->osdep.icnhandle);
    if(r != NO_ERROR)
        catta_log_error("NotifyIpInterfaceChange failed: %u", (unsigned int)r);

    // request async notification on address changes
    r = NotifyUnicastIpAddressChange(AF_UNSPEC, acn_callback, m, FALSE,
                                     &m->osdep.acnhandle);
    if(r != NO_ERROR)
        catta_log_error("NotifyUnicastIpAddressChange failed: %u", (unsigned int)r);

    return 0;

fail:
    closesocket(m->osdep.pipefd[0]);
    closesocket(m->osdep.pipefd[1]);
    return -1;
}

void catta_interface_monitor_free_osdep(CattaInterfaceMonitor *m)
{
    ChangeEvent *ev;

    // unregister callbacks
    if(m->osdep.icnhandle) CancelMibChangeNotify2(m->osdep.icnhandle);
    if(m->osdep.acnhandle) CancelMibChangeNotify2(m->osdep.acnhandle);

    // unregister event handler
    m->server->poll_api->watch_free(m->osdep.watch);

    // close pipe
    closepipe(m->osdep.pipefd[0]);
    closepipe(m->osdep.pipefd[1]);

    // make sure no stray events can come in during destruction
    pthread_mutex_lock(&m->osdep.mutex);

    // free all events that are still in the queue
    while((ev = m->osdep.events) != NULL) {
        CATTA_LLIST_REMOVE(ChangeEvent, event, m->osdep.events, ev);
        catta_free(ev);
    }

    pthread_mutex_unlock(&m->osdep.mutex);
    pthread_mutex_destroy(&m->osdep.mutex);
}

void catta_interface_monitor_sync(CattaInterfaceMonitor *m)
{
    IP_ADAPTER_ADDRESSES *buf = NULL;
    IP_ADAPTER_ADDRESSES *p;
    ULONG bufsize = 15000;
    ULONG r;

    // allocate a buffer and call GetAdaptersAddresses
    // retry with the correct size if the buffer was too small
    do {
        catta_free(buf);    // no-op on first iteration
        if((buf = catta_malloc(bufsize)) == NULL) {
            catta_log_error("malloc failed in catta_interface_monitor_sync");
            return;
        }

        r = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, buf, &bufsize);
    } while(r == ERROR_BUFFER_OVERFLOW);

    if(r != NO_ERROR) {
        catta_log_error("GetAdaptersAddresses failed: %u", (unsigned int)r);
        return;
    }

    // XXX remove interfaces for adapters that are no longer in the list

    // create 'CattaInterface's for every adapter
    for(p=buf; p; p=p->Next)
        ip_adapter(m, p);

    catta_free(buf);

    m->list_complete = 1;
    catta_interface_monitor_check_relevant(m);
    catta_interface_monitor_update_rrs(m, 0);
    catta_log_info("Network interface enumeration completed.");
}
