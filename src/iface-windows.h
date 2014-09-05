#ifndef fooifacewindowshfoo
#define fooifacewindowshfoo

#include "hashmap.h"

typedef struct CattaInterfaceMonitorOSDep {
    CattaHashmap *idxmap;   // maps adapter LUIDs to stable int indexes
    int nidx;               // number of assigned indexes (= size of idxmap)
} CattaInterfaceMonitorOSDep;

#endif
