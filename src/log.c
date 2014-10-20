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

#include <stdio.h>
#include <stdarg.h>

#include <catta/log.h>

static CattaLogFunction log_function = NULL;

void catta_set_log_function(CattaLogFunction function) {
    log_function = function;
}

void catta_log_ap(CattaLogLevel level, const char*format, va_list ap) {
    char txt[256];

    vsnprintf(txt, sizeof(txt), format, ap);

    if (log_function)
        log_function(level, txt);
    else
        fprintf(stderr, "%s\n", txt);
}

void catta_log(CattaLogLevel level, const char*format, ...) {
    va_list ap;
    va_start(ap, format);
    catta_log_ap(level, format, ap);
    va_end(ap);
}

void catta_log_error(const char*format, ...) {
    va_list ap;
    va_start(ap, format);
    catta_log_ap(CATTA_LOG_ERROR, format, ap);
    va_end(ap);
}

void catta_log_warn(const char*format, ...) {
    va_list ap;
    va_start(ap, format);
    catta_log_ap(CATTA_LOG_WARN, format, ap);
    va_end(ap);
}

void catta_log_notice(const char*format, ...) {
    va_list ap;
    va_start(ap, format);
    catta_log_ap(CATTA_LOG_NOTICE, format, ap);
    va_end(ap);
}

void catta_log_info(const char*format, ...) {
    va_list ap;
    va_start(ap, format);
    catta_log_ap(CATTA_LOG_INFO, format, ap);
    va_end(ap);
}

void catta_log_debug(const char*format, ...) {
    va_list ap;
    va_start(ap, format);
    catta_log_ap(CATTA_LOG_DEBUG, format, ap);
    va_end(ap);
}
