#ifndef foologhfoo
#define foologhfoo

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

#include <stdarg.h>

#include <catta/cdecl.h>
#include <catta/gccmacro.h>

/** \file log.h Extensible logging subsystem */

CATTA_C_DECL_BEGIN

/** Log level for catta_log_xxx() */
typedef enum {
    CATTA_LOG_ERROR  = 0,    /**< Error messages */
    CATTA_LOG_WARN   = 1,    /**< Warning messages */
    CATTA_LOG_NOTICE = 2,    /**< Notice messages */
    CATTA_LOG_INFO   = 3,    /**< Info messages */
    CATTA_LOG_DEBUG  = 4,    /**< Debug messages */
    CATTA_LOG_LEVEL_MAX
} CattaLogLevel;

/** Prototype for a user supplied log function */
typedef void (*CattaLogFunction)(CattaLogLevel level, const char *txt);

/** Set a user supplied log function, replacing the default which
 * prints to log messages unconditionally to STDERR. Pass NULL for
 * resetting to the default log function */
void catta_set_log_function(CattaLogFunction function);

/** Issue a log message using a va_list object */
void catta_log_ap(CattaLogLevel level, const char *format, va_list ap);

/** Issue a log message by passing a log level and a format string */
void catta_log(CattaLogLevel level, const char*format, ...) CATTA_GCC_PRINTF_ATTR23;

/** Shortcut for catta_log(CATTA_LOG_ERROR, ...) */
void catta_log_error(const char*format, ...) CATTA_GCC_PRINTF_ATTR12;

/** Shortcut for catta_log(CATTA_LOG_WARN, ...) */
void catta_log_warn(const char*format, ...) CATTA_GCC_PRINTF_ATTR12;

/** Shortcut for catta_log(CATTA_LOG_NOTICE, ...) */
void catta_log_notice(const char*format, ...) CATTA_GCC_PRINTF_ATTR12;

/** Shortcut for catta_log(CATTA_LOG_INFO, ...) */
void catta_log_info(const char*format, ...) CATTA_GCC_PRINTF_ATTR12;

/** Shortcut for catta_log(CATTA_LOG_DEBUG, ...) */
void catta_log_debug(const char*format, ...) CATTA_GCC_PRINTF_ATTR12;

CATTA_C_DECL_END

#endif
