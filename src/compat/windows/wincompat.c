#include "wincompat.h"
#include <errno.h>

int uname(struct utsname *buf)
{
    SYSTEM_INFO si;
    const char *arch = "unknown";

    memset(buf, 0, sizeof(struct utsname));

    // operating system
    strncpy(buf->sysname, "Windows", sizeof(buf->sysname)-1);
    strncpy(buf->release, "unknown", sizeof(buf->sysname)-1);   // we don't need it
    strncpy(buf->version, "unknown", sizeof(buf->sysname)-1);   // we don't need it

    // computer (node) name
    if(GetComputerName(buf->nodename, sizeof(buf->nodename)-1) == 0) {
        errno = EFAULT;
        return -1;
    }

    // hardware type
    GetSystemInfo(&si);
    switch(si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "amd64"; break;
        case PROCESSOR_ARCHITECTURE_ARM:   arch = "arm";   break;
        case PROCESSOR_ARCHITECTURE_IA64:  arch = "ia64";  break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86";   break;
        default: arch = "unknown";
    }
    strncpy(buf->machine, arch, sizeof(buf->machine)-1);

    return 0;
}
