#ifndef foowincompatfoo
#define foowincompatfoo

#undef WINVER
#undef _WIN32_WINNT

#define WINVER 0x0600       // Vista
#define _WIN32_WINNT WINVER

#include <winsock2.h>
#include <ws2tcpip.h>


struct utsname {
   char sysname[9];    /* Operating system name (e.g., "Linux") */
   char nodename[MAX_COMPUTERNAME_LENGTH+1];
                       /* Name within "some implementation-defined network" */
   char release[9];    /* Operating system release (e.g., "2.6.28") */
   char version[9];    /* Operating system version */
   char machine[9];    /* Hardware identifier */
};

int uname(struct utsname *buf);


#endif
