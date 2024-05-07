//
// Created by David Li on 6/13/23.
//

#ifndef MC_H
#define MC_H

#include <stdint.h>
#include <stdio.h>

#include "defs.h"
#include "terminal.h"

#define STATE_FREE      0b0000
#define STATE_ALLOCATED 0b0001
#define STATE_REQUEST   0b0010
#define STATE_RESPONSE  0b0100
#define STATE_QUEUED    0b1000
#define STATE_RETURN    0b1100
#define STATE_INIT      728

#define TO_OFFSET(ptr) ((size_t) ptr - base_addr)
#define TO_NODE(offset) ((node_t *) (offset + base_addr))

typedef volatile uint32_t state_t;
typedef uint32_t          opcode_t;
typedef uint64_t          procid_t;

typedef struct mc {
    struct_node;
    procid_t procid;
    state_t  state;
    opcode_t opcode;
    uint64_t args[8];
    uint64_t ret;
    uint8_t  payload[2][4096];
}                         mc_t;

typedef struct metadata {
    state_t           state;
    term_t            terminal;
    uint16_t          mc_cnt;
    volatile uint16_t mc_alloc;
    size_t            mc_base;
}                         meta_t;

meta_t *
smr_init(void *base_ptr, size_t size);

#endif // MC_H
