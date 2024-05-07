#include <string.h>

#include "mc.h"

#define roundup(x, mod) ((((x) - 1) | ((mod) - 1)) + 1)

size_t base_addr = 0x0;


meta_t *
smr_init(void *base_ptr, size_t size) {
    for (int i = 0; i < size - 1; ++i)
        ((char *) base_ptr)[i] = 0;
    meta_t *meta;
    // check base pointer alignment
    if ((uintptr_t) base_ptr & (sizeof(uintptr_t) - 1)) return NULL;
    // metadata at the beginning of the smr
    meta = (meta_t *) base_ptr;
    // initialize terminal
    base_addr = (size_t) base_ptr;
    // round up to have the size aligned
    size = roundup(size - sizeof(meta_t) + 1, sizeof(mc_t));
    // initialize from host
    meta->state         = STATE_INIT;
    // mc allocation
    meta->mc_cnt        = size / sizeof(mc_t);
    meta->mc_alloc      = 1;
    // base offset
    meta->mc_base       = sizeof(meta_t);
    // terminal initialization with the first dummy node
    meta->terminal.head = meta->mc_base;
    meta->terminal.tail = meta->mc_base;
    // clear all MCs including NULL for dummy->next
    // memset((meta + 1), 0, size);

    log(META, "SHM region [ at:%p | meta:%lu | mc[%hu]:%lu ]", meta, sizeof(meta_t), meta->mc_cnt, size);

    return meta;
}