#ifndef fooifacewindowshfoo
#define fooifacewindowshfoo

#include <catta/llist.h>
#include <pthread.h>

// we register with Windows to receive callbacks when IP interfaces change.
// we save these events in the structures below and pick them up from our
// own mainloop which we wake via a pipe.

typedef struct ChangeEvent ChangeEvent;

typedef struct CattaInterfaceMonitorOSDep {
    pthread_mutex_t mutex;  // guards access to event queues and the pipe

    CATTA_LLIST_HEAD(ChangeEvent, events);

    int pipefd[2];      // used to wake up the mainloop and check for events

    // handles for deregistering the handler and notification callbacks
    HANDLE icnhandle;   // interface change notification handle
    HANDLE acnhandle;   // address change notification handle
    CattaWatch *watch;
} CattaInterfaceMonitorOSDep;

#endif
