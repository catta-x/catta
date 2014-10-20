#ifndef foopublishhfoo
#define foopublishhfoo

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

/** \file core/publish.h Functions for publising local services and RRs */

/** \example core-publish-service.c Example how to register a DNS-SD
 * service using an embedded mDNS stack. It behaves like a network
 * printer registering both an IPP and a BSD LPR service. */

/** A group of locally registered DNS RRs */
typedef struct CattaSEntryGroup CattaSEntryGroup;

#include <catta/cdecl.h>
#include <catta/core.h>

CATTA_C_DECL_BEGIN

/** Prototype for callback functions which are called whenever the state of an CattaSEntryGroup object changes */
typedef void (*CattaSEntryGroupCallback) (CattaServer *s, CattaSEntryGroup *g, CattaEntryGroupState state, void* userdata);

/** Iterate through all local entries of the server. (when g is NULL)
 * or of a specified entry group. At the first call state should point
 * to a NULL initialized void pointer, That pointer is used to track
 * the current iteration. It is not safe to call any other
 * catta_server_xxx() function during the iteration. If the last entry
 * has been read, NULL is returned. */
const CattaRecord *catta_server_iterate(CattaServer *s, CattaSEntryGroup *g, void **state);

/** Create a new entry group. The specified callback function is
 * called whenever the state of the group changes. Use entry group
 * objects to keep track of you RRs. Add new RRs to a group using
 * catta_server_add_xxx(). Make sure to call catta_s_entry_group_commit()
 * to start the registration process for your RRs */
CattaSEntryGroup *catta_s_entry_group_new(CattaServer *s, CattaSEntryGroupCallback callback, void* userdata);

/** Free an entry group. All RRs assigned to the group are removed from the server */
void catta_s_entry_group_free(CattaSEntryGroup *g);

/** Commit an entry group. This starts the probing and registration process for all RRs in the group */
int catta_s_entry_group_commit(CattaSEntryGroup *g);

/** Remove all entries from the entry group and reset the state to CATTA_ENTRY_GROUP_UNCOMMITED. */
void catta_s_entry_group_reset(CattaSEntryGroup *g);

/** Return 1 if the entry group is empty, i.e. has no records attached. */
int catta_s_entry_group_is_empty(CattaSEntryGroup *g);

/** Return the current state of the specified entry group */
CattaEntryGroupState catta_s_entry_group_get_state(CattaSEntryGroup *g);

/** Change the opaque user data pointer attached to an entry group object */
void catta_s_entry_group_set_data(CattaSEntryGroup *g, void* userdata);

/** Return the opaque user data pointer currently set for the entry group object */
void* catta_s_entry_group_get_data(CattaSEntryGroup *g);

/** Add a new resource record to the server. Returns 0 on success, negative otherwise. */
int catta_server_add(
    CattaServer *s,           /**< The server object to add this record to */
    CattaSEntryGroup *g,       /**< An entry group object if this new record shall be attached to one, or NULL. If you plan to remove the record sometime later you a required to pass an entry group object here. */
    CattaIfIndex iface,   /**< A numeric index of a network interface to attach this record to, or CATTA_IF_UNSPEC to attach this record to all interfaces */
    CattaProtocol protocol,   /**< A protocol family to attach this record to. One of the CATTA_PROTO_xxx constants. Use CATTA_PROTO_UNSPEC to make this record available on all protocols (wich means on both IPv4 and IPv6). */
    CattaPublishFlags flags,    /**< Special flags for this record */
    CattaRecord *r            /**< The record to add. This function increases the reference counter of this object. */);

/** Add an IP address mapping to the server. This will add both the
 * host-name-to-address and the reverse mapping to the server. See
 * catta_server_add() for more information. If adding one of the RRs
 * fails, the function returns with an error, but it is not defined if
 * the other RR is deleted from the server or not. Therefore, you have
 * to free the CattaSEntryGroup and create a new one before
 * proceeding. */
int catta_server_add_address(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    CattaAddress *a);

/** Add an DNS-SD service to the Server. This will add all required
 * RRs to the server. See catta_server_add() for more information.  If
 * adding one of the RRs fails, the function returns with an error,
 * but it is not defined if the other RR is deleted from the server or
 * not. Therefore, you have to free the CattaSEntryGroup and create a
 * new one before proceeding. */
int catta_server_add_service(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,         /**< Service name, e.g. "Lennart's Files" */
    const char *type,         /**< DNS-SD type, e.g. "_http._tcp" */
    const char *domain,
    const char *host,         /**< Host name where this servcie resides, or NULL if on the local host */
    uint16_t port,              /**< Port number of the service */
    ...  /**< Text records, terminated by NULL */) CATTA_GCC_SENTINEL;

/** Mostly identical to catta_server_add_service(), but takes an CattaStringList object for the TXT records.  The CattaStringList object is copied. */
int catta_server_add_service_strlst(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    const char *host,
    uint16_t port,
    CattaStringList *strlst);

/** Add a subtype for an already existing service */
int catta_server_add_service_subtype(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,         /**< Specify the name of main service you already added here */
    const char *type,         /**< Specify the main type of the service you already added here */
    const char *domain,       /**< Specify the main type of the service you already added here */
    const char *subtype       /**< The new subtype for the specified service */ );

/** Update the TXT record for a service with the data from the specified string list */
int catta_server_update_service_txt_strlst(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    CattaStringList *strlst);

/** Update the TXT record for a service with the NULL termonate list of strings */
int catta_server_update_service_txt(
    CattaServer *s,
    CattaSEntryGroup *g,
    CattaIfIndex iface,
    CattaProtocol protocol,
    CattaPublishFlags flags,
    const char *name,
    const char *type,
    const char *domain,
    ...) CATTA_GCC_SENTINEL;

/** Check if there is a service locally defined and return the entry group it is attached to. Returns NULL if the service isn't local*/
int catta_server_get_group_of_service(CattaServer *s, CattaIfIndex iface, CattaProtocol protocol, const char *name, const char *type, const char *domain, CattaSEntryGroup** ret_group);

CATTA_C_DECL_END

#endif
