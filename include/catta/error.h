#ifndef fooerrorhfoo
#define fooerrorhfoo

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

/** \file error.h Error codes and auxiliary functions */

#include <catta/cdecl.h>

CATTA_C_DECL_BEGIN

/** Error codes used by catta */
enum {
    CATTA_OK = 0,                            /**< OK */
    CATTA_ERR_FAILURE = -1,                  /**< Generic error code */
    CATTA_ERR_BAD_STATE = -2,                /**< Object was in a bad state */
    CATTA_ERR_INVALID_HOST_NAME = -3,        /**< Invalid host name */
    CATTA_ERR_INVALID_DOMAIN_NAME = -4,      /**< Invalid domain name */
    CATTA_ERR_NO_NETWORK = -5,               /**< No suitable network protocol available */
    CATTA_ERR_INVALID_TTL = -6,              /**< Invalid DNS TTL */
    CATTA_ERR_IS_PATTERN = -7,               /**< RR key is pattern */
    CATTA_ERR_COLLISION = -8,                /**< Name collision */
    CATTA_ERR_INVALID_RECORD = -9,           /**< Invalid RR */

    CATTA_ERR_INVALID_SERVICE_NAME = -10,    /**< Invalid service name */
    CATTA_ERR_INVALID_SERVICE_TYPE = -11,    /**< Invalid service type */
    CATTA_ERR_INVALID_PORT = -12,            /**< Invalid port number */
    CATTA_ERR_INVALID_KEY = -13,             /**< Invalid key */
    CATTA_ERR_INVALID_ADDRESS = -14,         /**< Invalid address */
    CATTA_ERR_TIMEOUT = -15,                 /**< Timeout reached */
    CATTA_ERR_TOO_MANY_CLIENTS = -16,        /**< Too many clients */
    CATTA_ERR_TOO_MANY_OBJECTS = -17,        /**< Too many objects */
    CATTA_ERR_TOO_MANY_ENTRIES = -18,        /**< Too many entries */
    CATTA_ERR_OS = -19,                      /**< OS error */

    CATTA_ERR_ACCESS_DENIED = -20,           /**< Access denied */
    CATTA_ERR_INVALID_OPERATION = -21,       /**< Invalid operation */
    CATTA_ERR_DBUS_ERROR = -22,              /**< An unexpected D-Bus error occurred */
    CATTA_ERR_DISCONNECTED = -23,            /**< Daemon connection failed */
    CATTA_ERR_NO_MEMORY = -24,               /**< Memory exhausted */
    CATTA_ERR_INVALID_OBJECT = -25,          /**< The object passed to this function was invalid */
    CATTA_ERR_NO_DAEMON = -26,               /**< Daemon not running */
    CATTA_ERR_INVALID_INTERFACE = -27,       /**< Invalid interface */
    CATTA_ERR_INVALID_PROTOCOL = -28,        /**< Invalid protocol */
    CATTA_ERR_INVALID_FLAGS = -29,           /**< Invalid flags */

    CATTA_ERR_NOT_FOUND = -30,               /**< Not found */
    CATTA_ERR_INVALID_CONFIG = -31,          /**< Configuration error */
    CATTA_ERR_VERSION_MISMATCH = -32,        /**< Verson mismatch */
    CATTA_ERR_INVALID_SERVICE_SUBTYPE = -33, /**< Invalid service subtype */
    CATTA_ERR_INVALID_PACKET = -34,          /**< Invalid packet */
    CATTA_ERR_INVALID_DNS_ERROR = -35,       /**< Invlaid DNS return code */
    CATTA_ERR_DNS_FORMERR = -36,             /**< DNS Error: Form error */
    CATTA_ERR_DNS_SERVFAIL = -37,            /**< DNS Error: Server Failure */
    CATTA_ERR_DNS_NXDOMAIN = -38,            /**< DNS Error: No such domain */
    CATTA_ERR_DNS_NOTIMP = -39,              /**< DNS Error: Not implemented */

    CATTA_ERR_DNS_REFUSED = -40,             /**< DNS Error: Operation refused */
    CATTA_ERR_DNS_YXDOMAIN = -41,
    CATTA_ERR_DNS_YXRRSET = -42,
    CATTA_ERR_DNS_NXRRSET = -43,
    CATTA_ERR_DNS_NOTAUTH = -44,             /**< DNS Error: Not authorized */
    CATTA_ERR_DNS_NOTZONE = -45,
    CATTA_ERR_INVALID_RDATA = -46,           /**< Invalid RDATA */
    CATTA_ERR_INVALID_DNS_CLASS = -47,       /**< Invalid DNS class */
    CATTA_ERR_INVALID_DNS_TYPE = -48,        /**< Invalid DNS type */
    CATTA_ERR_NOT_SUPPORTED = -49,           /**< Not supported */

    CATTA_ERR_NOT_PERMITTED = -50,           /**< Operation not permitted */
    CATTA_ERR_INVALID_ARGUMENT = -51,        /**< Invalid argument */
    CATTA_ERR_IS_EMPTY = -52,                /**< Is empty */
    CATTA_ERR_NO_CHANGE = -53,               /**< The requested operation is invalid because it is redundant */

    /****
     ****    IF YOU ADD A NEW ERROR CODE HERE, PLEASE DON'T FORGET TO ADD
     ****    IT TO THE STRING ARRAY IN catta_strerror() IN error.c AND
     ****    TO THE ARRAY IN dbus.c AND FINALLY TO dbus.h!
     ****
     ****    Also remember to update the MAX value below.
     ****/

    CATTA_ERR_MAX = -54
};

/** Return a human readable error string for the specified error code */
const char *catta_strerror(int error);

CATTA_C_DECL_END

#endif
