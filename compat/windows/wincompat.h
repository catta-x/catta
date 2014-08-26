#ifndef foowincompatfoo
#define foowincompatfoo

#undef WINVER
#undef _WIN32_WINNT

#define WINVER 0x0600       // Vista
#define _WIN32_WINNT WINVER

#include <winsock2.h>

#endif
