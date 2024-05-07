pub mod fs;
pub mod mc;
pub mod net;
pub mod net_std;
pub mod path;
// pub mod sm;
pub mod socket;
mod sync;
mod terminal;

use core::{mem::size_of, sync::atomic::Ordering};

// use num_traits::cast::FromPrimitive;
use crate::{proxy::mc::{MCOpcode, Metadata, MC, META, STATE_INIT}, syscall::SyscallReturn, prelude::*};
// use crate::utils::error::SyscallReturn; // fixme: wrap the return result of syscall

const BASE_ADDR: usize = 0x800000000 + 0xffff_8000_0000_0000;
const SHM_SIZE: usize = 4096 * 64;

/// Sends a message proxying the corresponding syscall to the host.
#[inline(always)]
pub fn proxy_syscall(process_id: usize, syscall_id: usize, args: [u64; 8]) -> Result<SyscallReturn> {
    MC::alloc().proxy(process_id, syscall_id, args).free()
}

// pub fn sm_init() {
//     STATE_MACHINE.lock().init();
// }

/// Initialize the shared memory region
pub fn init() {
    //println!("start to init SMR");
    let meta: &mut Metadata;
    unsafe {
        META.raw = BASE_ADDR;
        meta = META.as_mut();
    }
    // initialized in host
    if meta.state == STATE_INIT {
        #[cfg(feature = "verbose")]
        println!(
            "[META] SMR region initialized by host [ at:{:p} | meta:{} | mc[{}] ]",
            unsafe { META.as_ptr() },
            size_of::<Metadata>(),
            meta.mc_cnt
        );
        return;
    }
    // clear all MCs including NULL for dummy->next
    unsafe {
        META.as_ptr().write_bytes(0, SHM_SIZE);
    }
    // roundup
    let size: usize = ((SHM_SIZE - size_of::<Metadata>()) | (size_of::<MC>() - 1)) + 1;
    // initialize from guest
    meta.state = STATE_INIT;
    // mc allocation
    meta.mc_cnt = (size / size_of::<MC>()) as u16;
    meta.mc_alloc.store(1, Ordering::Relaxed);
    // base offset
    meta.mc_base = size_of::<Metadata>();
    // terminal initialization with the first dummy node
    meta.terminal.head.raw = meta.mc_base;
    meta.terminal.tail.raw = meta.mc_base;

    // printf!(
    //     "[META] Initialized SMR region [ at:{:p} | meta:{} | mc[{}]:{} ]",
    //     unsafe { META.as_ptr() },
    //     size_of::<Metadata>(),
    //     meta.mc_cnt,
    //     size
    // );
}

macro_rules! expand_args {
    () => {
        [0, 0, 0, 0, 0, 0, 0, 0]
    };
    ($a0: expr) => {
        [$a0 as u64, 0, 0, 0, 0, 0, 0, 0]
    };
    ($a0: expr, $a1: expr) => {
        [$a0 as u64, $a1 as u64, 0, 0, 0, 0, 0, 0]
    };
    ($a0: expr, $a1: expr, $a2: expr) => {
        [$a0 as u64, $a1 as u64, $a2 as u64, 0, 0, 0, 0, 0]
    };
    ($a0: expr, $a1: expr, $a2: expr, $a3: expr) => {
        [$a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64, 0, 0, 0, 0]
    };
    ($a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr) => {
        [
            $a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64, $a4 as u64, 0, 0, 0,
        ]
    };
    ($a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr) => {
        [
            $a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64, $a4 as u64, $a5 as u64, 0, 0,
        ]
    };
    ($a0: expr, $a1: expr, $a2: expr, $a3: expr, $a4: expr, $a5: expr, $a6: expr) => {
        [
            $a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64, $a4 as u64, $a5 as u64, $a6 as u64, 0,
        ]
    };
}

pub(crate) use expand_args;

// use self::sm::STATE_MACHINE;
