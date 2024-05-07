#ifndef TERMINAL_H
#define TERMINAL_H

#include "defs.h"

extern size_t base_addr;

typedef volatile struct term {
    volatile size_t head;
    volatile size_t tail;
} term_t;

void enqueue(term_t *terminal, node_t *node);

node_t *dequeue(term_t *terminal);

node_t *peek(term_t *terminal);

#endif // TERMINAL_H
