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

#include <assert.h>

#include <catta/gccmacro.h>

#include "../src/utf8.h"

int main(CATTA_GCC_UNUSED int argc, CATTA_GCC_UNUSED char *argv[]) {

    assert(catta_utf8_valid("hallo"));
    assert(!catta_utf8_valid("üxknürz"));
    assert(catta_utf8_valid("Ã¼xknÃ¼rz"));

    return 0;
}
