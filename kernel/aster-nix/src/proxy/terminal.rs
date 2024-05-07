
use crate::proxy::BASE_ADDR;
use core::fmt;
use core::fmt::Formatter;

use super::sync::Anp;

#[derive(Debug)]
#[repr(C)]
pub struct Node {
    pub next: Anp<Node>,
}

/// Lock-free FIFO queue, based upon the paper:
/// Maged M. Michael and Michael L. Scott. 1996. Simple, fast, and practical non-blocking and
/// blocking concurrent queue algorithms.
/// Used for terminal's MC transportation.
#[repr(C)]
#[derive(Debug)]
pub struct Terminal {
    pub(crate) head: Anp<Node>,
    pub(crate) tail: Anp<Node>,
}

impl fmt::Display for Terminal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Terminal[0x{:x}] {{ head: {}, tail: {} }}",
            self as *const _ as usize, self.head, self.tail
        )
    }
}

impl Terminal {
    // fixme: eliminate unsafe
    pub unsafe fn enqueue(&mut self, mut node: Anp<Node>) {
        let mut tail: Anp<Node> = Anp::null();
        let mut next: usize;
        node.as_mut().next.raw = 0;

        'enqueue: loop {
            tail.raw = self.tail.raw + BASE_ADDR;
            next = tail.as_ref().next.raw;

            if tail.raw - BASE_ADDR != self.tail.raw {
                continue;
            } // inconsistent

            if next != 0 {
                // fix the tail as it's not pointing to the last node
                self.tail.compare_exchange(tail.raw - BASE_ADDR, next).ok();
            } else if tail
                .as_ref()
                .next
                .compare_exchange(next, node.raw - BASE_ADDR)
                .is_ok()
            {
                break 'enqueue;
            }
        }

        self.tail
            .compare_exchange(tail.raw, node.raw - BASE_ADDR)
            .ok();

        #[cfg(feature = "verbose")]
        {
            println!("[TERMINAL] enqueued node {}", node);
        }
    }
}
