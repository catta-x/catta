#ifndef foolookuphfoo
#define foolookuphfoo

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

/** \file catta/lookup.h Functions for browsing/resolving services and other RRs */

/** \example core-browse-services.c Example how to browse for DNS-SD
 * services using an embedded mDNS stack. */

/** A browsing object for arbitrary RRs */
typedef struct CattaSRecordBrowser CattaSRecordBrowser;

/** A host name to IP adddress resolver object */
typedef struct CattaSHostNameResolver CattaSHostNameResolver;

/** An IP address to host name resolver object ("reverse lookup") */
typedef struct CattaSAddressResolver CattaSAddressResolver;

/** A local domain browsing object. May be used to enumerate domains used on the local LAN */
typedef struct CattaSDomainBrowser CattaSDomainBrowser;

/** A DNS-SD service type browsing object. May be used to enumerate the service types of all available services on the local LAN */
typedef struct CattaSServiceTypeBrowser CattaSServiceTypeBrowser;

/** A DNS-SD service browser. Use this to enumerate available services of a certain kind on the local LAN. Use CattaSServiceResolver to get specific service data like address and port for a service. */
typedef struct CattaSServiceBrowser CattaSServiceBrowser;

/** A DNS-SD service resolver.  Use this to retrieve addres, port and TXT data for a DNS-SD service */
typedef struct CattaSServiceResolver CattaSServiceResolver;

#include <catta/cdecl.h>
#include <catta/defs.h>
#include <catta/core.h>

CATTA_C_DECL_BEGIN

/** Callback prototype for CattaSRecordBrowser events */
typedef void (*CattaSRecordBrowserCallback)(
    CattaSRecordBrowser *b,          /**< The CattaSRecordBrowser object that is emitting this callback */
    CattaIfIndex iface,          /**< Logical OS network interface number the record was found on */
    CattaProtocol protocol,          /**< Protocol number the record was found. */
    CattaBrowserEvent event,         /**< Browsing event, either CATTA_BROWSER_NEW or CATTA_BROWSER_REMOVE */
    CattaRecord *record,             /**< The record that was found */
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata                   /**< Arbitrary user data passed to catta_s_record_browser_new() */ );

/** Create a new browsing object for arbitrary RRs */
CattaSRecordBrowser *catta_s_record_browser_new(
    CattaServer *server,                    /**< The server object to which attach this query */
    CattaIfIndex iface,                 /**< Logical OS interface number where to look for the records, or CATTA_IF_UNSPEC to look on interfaces */
    CattaProtocol protocol,                 /**< Protocol number to use when looking for the record, or CATTA_PROTO_UNSPEC to look on all protocols */
    CattaKey *key,                          /**< The search key */
    CattaLookupFlags flags,                 /**< Lookup flags. Must have set either CATTA_LOOKUP_FORCE_WIDE_AREA or CATTA_LOOKUP_FORCE_MULTICAST, since domain based detection is not available here. */
    CattaSRecordBrowserCallback callback,   /**< The callback to call on browsing events */
    void* userdata                          /**< Arbitrary use suppliable data which is passed to the callback */);

/** Free an CattaSRecordBrowser object */
void catta_s_record_browser_free(CattaSRecordBrowser *b);

/** Callback prototype for CattaSHostNameResolver events */
typedef void (*CattaSHostNameResolverCallback)(
    CattaSHostNameResolver *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaResolverEvent event, /**< Resolving event */
    const char *host_name,   /**< Host name which should be resolved. May differ in case from the query */
    const CattaAddress *a,    /**< The address, or NULL if the host name couldn't be resolved. */
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create an CattaSHostNameResolver object for resolving a host name to an adddress. See CattaSRecordBrowser for more info on the paramters. */
CattaSHostNameResolver *catta_s_host_name_resolver_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *host_name,                  /**< The host name to look for */
    CattaProtocol aprotocol,                /**< The address family of the desired address or CATTA_PROTO_UNSPEC if doesn't matter. */
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSHostNameResolverCallback calback,
    void* userdata);

/** Free a CattaSHostNameResolver object */
void catta_s_host_name_resolver_free(CattaSHostNameResolver *r);

/** Callback prototype for CattaSAddressResolver events */
typedef void (*CattaSAddressResolverCallback)(
    CattaSAddressResolver *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaResolverEvent event,
    const CattaAddress *a,
    const char *host_name,   /**< A host name for the specified address, if one was found, i.e. event == CATTA_RESOLVER_FOUND */
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create an CattaSAddressResolver object. See CattaSRecordBrowser for more info on the paramters. */
CattaSAddressResolver *catta_s_address_resolver_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const CattaAddress *address,
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSAddressResolverCallback calback,
    void* userdata);

/** Free an CattaSAddressResolver object */
void catta_s_address_resolver_free(CattaSAddressResolver *r);

/** Callback prototype for CattaSDomainBrowser events */
typedef void (*CattaSDomainBrowserCallback)(
    CattaSDomainBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *domain,
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create a new CattaSDomainBrowser object */
CattaSDomainBrowser *catta_s_domain_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *domain,
    CattaDomainBrowserType type,
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSDomainBrowserCallback callback,
    void* userdata);

/** Free an CattaSDomainBrowser object */
void catta_s_domain_browser_free(CattaSDomainBrowser *b);

/** Callback prototype for CattaSServiceTypeBrowser events */
typedef void (*CattaSServiceTypeBrowserCallback)(
    CattaSServiceTypeBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *type,
    const char *domain,
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create a new CattaSServiceTypeBrowser object. */
CattaSServiceTypeBrowser *catta_s_service_type_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *domain,
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSServiceTypeBrowserCallback callback,
    void* userdata);

/** Free an CattaSServiceTypeBrowser object */
void catta_s_service_type_browser_free(CattaSServiceTypeBrowser *b);

/** Callback prototype for CattaSServiceBrowser events */
typedef void (*CattaSServiceBrowserCallback)(
    CattaSServiceBrowser *b,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaBrowserEvent event,
    const char *name     /**< Service name, e.g. "Lennart's Files" */,
    const char *type     /**< DNS-SD type, e.g. "_http._tcp" */,
    const char *domain   /**< Domain of this service, e.g. "local" */,
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create a new CattaSServiceBrowser object. */
CattaSServiceBrowser *catta_s_service_browser_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *service_type /** DNS-SD service type, e.g. "_http._tcp" */,
    const char *domain,
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSServiceBrowserCallback callback,
    void* userdata);

/** Free an CattaSServiceBrowser object */
void catta_s_service_browser_free(CattaSServiceBrowser *b);

/** Callback prototype for CattaSServiceResolver events */
typedef void (*CattaSServiceResolverCallback)(
    CattaSServiceResolver *r,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaResolverEvent event,  /**< Is CATTA_RESOLVER_FOUND when the service was resolved successfully, and everytime it changes. Is CATTA_RESOLVER_TIMOUT when the service failed to resolve or disappeared. */
    const char *name,       /**< Service name */
    const char *type,       /**< Service Type */
    const char *domain,
    const char *host_name,  /**< Host name of the service */
    const CattaAddress *a,   /**< The resolved host name */
    uint16_t port,            /**< Service name */
    CattaStringList *txt,    /**< TXT record data */
    CattaLookupResultFlags flags,  /**< Lookup flags */
    void* userdata);

/** Create a new CattaSServiceResolver object. The specified callback function will be called with the resolved service data. */
CattaSServiceResolver *catta_s_service_resolver_new(
    CattaServer *server,
    CattaIfIndex iface,
    CattaProtocol protocol,
    const char *name,
    const char *type,
    const char *domain,
    CattaProtocol aprotocol,    /**< Address family of the desired service address. Use CATTA_PROTO_UNSPEC if you don't care */
    CattaLookupFlags flags,                 /**< Lookup flags. */
    CattaSServiceResolverCallback calback,
    void* userdata);

/** Free an CattaSServiceResolver object */
void catta_s_service_resolver_free(CattaSServiceResolver *r);

CATTA_C_DECL_END

#endif
