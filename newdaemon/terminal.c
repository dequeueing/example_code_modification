#include <stddef.h>

#include "terminal.h"
#include "mc.h"

void
enqueue(term_t *terminal, node_t *node) {
    node_t *tail;
    size_t next;
    node->next = (volatile size_t) NULL;

    while (TRUE) {
        tail = TO_NODE(terminal->tail);
        next = tail->next;

        if (TO_OFFSET(tail) != terminal->tail) continue; // inconsistent

        if (next) {
            // fix the tail as it's not pointing to the last node
            (void) CAS(&(terminal->tail), TO_OFFSET(tail), next);
        } else if (CAS(&(tail->next), next, TO_OFFSET(node)))
            break;
    }

    (void) CAS(&(terminal->tail), TO_OFFSET(tail), TO_OFFSET(node));

    log(TERM,
        "[-->] terminal %p tail[ to:%p ] -> new node[ at:%p | next:%p ] -> old tail[ at:%p ]",
        terminal, TO_NODE(terminal->tail), node, TO_NODE(node->next), tail);
}

node_t *
dequeue(term_t *terminal) {
    node_t *head;
    size_t tail, next;

    while (TRUE) {
        head = TO_NODE(terminal->head);
        tail = terminal->tail;
        next = head->next;

        if (TO_OFFSET(head) != terminal->head) continue; // inconsistent

        if (TO_OFFSET(head) == tail) {
            if (!next) return NULL;
            // fix the tail as it's not pointing to the last node
            (void) CAS(&(terminal->tail), tail, next);
        } else if (CAS(&(terminal->head), TO_OFFSET(head), next))
            break;
    }

    mc_t *mc = (mc_t *) head;
    mc->state = mc->state == STATE_RESPONSE // the MC could have been used by guest
                ? STATE_QUEUED
                : STATE_FREE;
    // TODO: free head MC with allocator

    log(TERM, "[<--] terminal %p dequeued node[ at:%p | next:%p ] now[ at:%p | next:%p ]",
        terminal, head, TO_NODE(head->next), TO_NODE(next), (node_t *) TO_NODE(next)->next);

    return TO_NODE(next);
}

node_t *
peek(term_t *terminal) {
    return (node_t *) TO_NODE(terminal->head)->next;
}