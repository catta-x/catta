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

#include "iface-windows.h"
#include "iface.h"

#include <stdlib.h> // wcstombs
#include <catta/malloc.h>
#include <catta/log.h>
#include <iphlpapi.h>
#include "hashmap.h"
#include "util.h"   // catta_format_mac_address


// for the luid-to-idx hashmap
static unsigned luid_hash(const void *data)
{
    return ((NET_LUID *)data)->Info.NetLuidIndex;
}
static int luid_equal(const void *a, const void *b)
{
    return (((NET_LUID *)a)->Value == ((NET_LUID *)b)->Value);
}

static CattaIfIndex find_ifindex(CattaInterfaceMonitor *m, NET_LUID luid)
{
    CattaIfIndex *pi = NULL;
    NET_LUID *key = NULL;

    if((pi = catta_hashmap_lookup(m->osdep.idxmap, &luid)) == NULL) {
        // allocate memory for the hashmap key and value
        key = catta_malloc(sizeof(luid));
        pi = catta_malloc(sizeof(CattaIfIndex));
        if(!key || !pi)
            goto fail;

        *key = luid;
            
        // find an index for this luid
        *pi = m->osdep.nidx;
        if(*pi < 0)  // overflow
            goto fail;

        // register the index
        if(catta_hashmap_replace(m->osdep.idxmap, key, pi) < 0)
            goto fail;
        m->osdep.nidx++;
    }

    return *pi;

fail:
    catta_free(key);
    catta_free(pi);
    return -1;
}

// integrate the information from an IP_ADAPTER_ADDRESSES structure
// as returned by GetAdaptersAddresses into the CattaInterfaceMonitor
static void ip_adapter_address(CattaInterfaceMonitor *m, IP_ADAPTER_ADDRESSES *p)
{
    CattaIfIndex idx;
    CattaHwInterface *hw;
    size_t n;

    // look up the interface index by LUID
    if((idx = find_ifindex(m, p->Luid)) < 0) {
        catta_log_error("could not allocate index ip_adapter_address");
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
    hw->flags_ok =
        (p->OperStatus & IfOperStatusUp) &&
        !(p->IfType & IF_TYPE_SOFTWARE_LOOPBACK) &&
        !(p->Flags & IP_ADAPTER_NO_MULTICAST) &&
        (m->server->config.allow_point_to_point || !(p->IfType & IF_TYPE_PPP));
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

    // XXX process addresses

    // XXX debugging, remove
   { 
     char mac[256]; 
     catta_log_debug("======\n name: %s\n index:%d\n mtu:%d\n mac:%s\n flags_ok:%d\n======",  
 		    hw->name, hw->index,  
 		    hw->mtu,  
 		    catta_format_mac_address(mac, sizeof(mac), hw->mac_address, hw->mac_address_size), 
 		    hw->flags_ok); 
   } 
}


int catta_interface_monitor_init_osdep(CattaInterfaceMonitor *m)
{
    m->osdep.nidx = 0;
    m->osdep.idxmap = catta_hashmap_new(luid_hash, luid_equal, catta_free, catta_free);
    if(m->osdep.idxmap == NULL) {
        catta_log_error("out of memory in catta_interface_monitor_init_osdep");
        return -1;
    }

    // XXX register callbacks to get notified of interface/address changes

    return 0;
}

void catta_interface_monitor_free_osdep(CattaInterfaceMonitor *m)
{
    catta_hashmap_free(m->osdep.idxmap);
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
        ip_adapter_address(m, p);

    catta_free(buf);

    m->list_complete = 1;
    catta_interface_monitor_check_relevant(m);
    catta_interface_monitor_update_rrs(m, 0);
    catta_log_info("Network interface enumeration completed.");
}
