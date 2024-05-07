#ifndef SYNC_H
#define SYNC_H

#include <stdlib.h>

#define struct_node size_t next
typedef volatile struct node {
    struct_node;
} node_t;

#define TRUE    1
#define FALSE   0

/* START [debug] */
#define VERBOSE

#define META 0
#define TERM 1
#define SYS  3
#define DMON 4
#define LOG  5
/* END [debug] */

#ifdef VERBOSE
#include <stdio.h>
#include <sys/file.h>
#define syncprintf(args...) fprintf(stdout, args);
#define log(type, msg, args...) \
    do {\
        switch(type) {\
            case META: syncprintf("╭[META] " msg "\n", ##args); break;\
            case SYS : syncprintf("├[SYS] " msg "\n", ##args); break;\
            case DMON: syncprintf("├──[DAEMON] " msg "\n", ##args); break;\
            case TERM: syncprintf("├────[TERMINAL] " msg "\n", ##args); break;\
            default  : syncprintf("├[LOG] " msg "\n", ##args);\
        }\
    } while(FALSE)
#else
#define log(type, msg, ...)
#endif

#define FAA(ptr, delta)      __sync_fetch_and_add((ptr), (delta))
#define CAS(ptr, prev, next) __sync_bool_compare_and_swap((ptr), (prev), (next))

#endif // SYNC_H
