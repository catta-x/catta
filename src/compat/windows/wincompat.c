#include "wincompat.h"
#include <errno.h>

int uname(struct utsname *buf)
{
    memset(buf, 0, sizeof(struct utsname));
    strncpy(buf->sysname, "Windows", sizeof(buf->sysname)-1);
    if(GetComputerName(buf->nodename, sizeof(buf->nodename)-1) == 0) {
        errno = EFAULT;
        return -1;
    }

    return 0;
}
