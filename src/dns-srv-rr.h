#ifndef foodnssrvhfoo
#define foodnssrvhfoo

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

/** \file catta/dns-srv-rr.h Functions for announcing and browsing for unicast DNS servers via mDNS */

/** A domain service browser object. Use this to browse for
 * conventional unicast DNS servers which may be used to resolve
 * conventional domain names */
typedef struct CattaSDNSServerBrowser CattaSDNSServerBrowser;

#include <catta/cdecl.h>
#include <catta/defs.h>
#include <catta/core.h>
#include <catta/publish.h>

CATTA_C_DECL_BEGIN

/** The type of DNS server */
typedef enum {
    CATTA_DNS_SERVER_RESOLVE,         /**< Unicast DNS servers for normal resolves (_domain._udp)*/
    CATTA_DNS_SERVER_UPDATE,           /**< Unicast DNS servers for updates (_dns-update._udp)*/
    CATTA_DNS_SERVER_MAX
} CattaDNSServerType;

/** Publish the specified unicast DNS server address via mDNS. You may
 * browse for records create this way wit
 * catta_s_dns_server_browser_new(). */
int catta_server_add_dns_server_address(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *domain,
    CattaDNSServerType type,
    const CattaAddress *address,
    uint16_t port /** should be 53 */);

/** Callback prototype for CattaSDNSServerBrowser events */
typedef void (*CattaSDNSServerBrowserCallback)(
    CattaSDNSServerBrowser *b,
    CattaIfIndex interface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *host_name,       /**< Host name of the DNS server, probably useless */
    const CattaAddress *a,        /**< Address of the DNS server */
    uint16_t port,                 /**< Port number of the DNS servers, probably 53 */
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create a new CattaSDNSServerBrowser object */
CattaSDNSServerBrowser *catta_s_dns_server_browser_new(
    CattaServer *server,
    CattaIfIndex interface,
    CattaProtocol protocol,
    const char *domain,
    CattaDNSServerType type,
    CattaProtocol aprotocol,  /**< Address protocol for the DNS server */
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSDNSServerBrowserCallback callback,
    void* userdata);

/** Free an CattaSDNSServerBrowser object */
void catta_s_dns_server_browser_free(CattaSDNSServerBrowser *b);

CATTA_C_DECL_END

#endif
