use alloc::ffi::CString;
use aster_frame::io_mem::IoMem;
use aster_util::safe_ptr::SafePtr;
use spin::Once;
use core::{
    mem::size_of,
    sync::atomic::{AtomicU16, AtomicU32, Ordering},
};

// use num_traits::FromPrimitive;

use crate::{
    proxy::{
        // sync::Anp,
        terminal::{Node, Terminal},
        BASE_ADDR,
    }, 
    syscall::SyscallReturn,
    prelude::*,
    // utils::error::{SyscallErr, SyscallReturn},
};

use super::sync::Anp;

pub type MCState = u32;
pub type MCOpcode = u32;
pub type MCProcID = u64;

// mc states
pub(crate) const STATE_FREE: MCState = 0b0000;
pub(crate) const STATE_ALLOCATED: MCState = 0b0001;
pub(crate) const STATE_REQUEST: MCState = 0b0010;
pub(crate) const STATE_RESPONSE: MCState = 0b0100;
pub(crate) const STATE_QUEUED: MCState = 0b1000;
pub(crate) const STATE_RETURN: MCState = 0b1100;
pub(crate) const STATE_INIT: MCState = 728;

pub const PAYLOAD_SIZE: usize = 4096;
pub const PAYLOAD_CNT: usize = 2;

#[derive(Debug)]
#[repr(C)]
pub struct MC {
    pub node: Node,
    pub procid: MCProcID,
    pub state: AtomicU32,
    pub opcode: MCOpcode,
    pub args: [u64; 8],
    pub ret: u64,
    pub payload: [[u8; PAYLOAD_SIZE]; PAYLOAD_CNT],
}

#[derive(Debug)]
#[repr(C)]
pub(crate) struct Metadata {
    pub state: MCState,
    pub terminal: Terminal,
    pub mc_cnt: u16,
    pub mc_alloc: AtomicU16,
    pub mc_base: usize,
}

pub(crate) static mut META: Anp<Metadata> = Anp::null();
/// Metadata in memory I/O region
// pub(crate) static META: Once<SafePtr<IoMem,>> = Anp::null();

impl MC {
    /// Allocates a free MC in the shared memory region. This is guaranteed to be successful
    pub fn alloc() -> &'static mut MC {
        loop {
            if let Some(mc) = MC::try_alloc() {
                break mc;
            }
        }
    }
    /// Try to allocate the next MC in the circular array of MCs inside the shared memory region. Will return `None` if
    /// the next MC is not free.
    pub fn try_alloc() -> Option<&'static mut MC> {
        // fixme: no unsafe
        let mc = unsafe {
            ((META.as_ref().mc_base
                + BASE_ADDR
                + (META.as_ref().mc_alloc.fetch_add(1, Ordering::Relaxed) % META.as_ref().mc_cnt)
                    as usize
                    * size_of::<MC>()) as *const Self)
                .cast_mut()
                .as_mut()
                .unwrap()
        };
        // let mc = &mut MC::new(); // fixme no unsafe 
        match mc.state.load(Ordering::Relaxed) {
            STATE_FREE => {
                mc.state.store(STATE_ALLOCATED, Ordering::Relaxed);
                Some(mc)
            }
            _ => None,
        }
    }
    /// Frees a MC or prepare the MC to be fred by the terminal when relieved from the dummy position.
    pub fn free(&mut self) -> Result<SyscallReturn> {
        let ret: isize = self.ret as isize;

        match self.state.load(Ordering::Relaxed) {
            STATE_RESPONSE => {
                self.state.store(STATE_QUEUED, Ordering::Relaxed);
            }
            STATE_QUEUED => {
                self.state.store(STATE_FREE, Ordering::Relaxed);
            }
            _ => {
                #[cfg(feature = "verbose")]
                {
                    println!("[MC] error, freeing MC with state {}", self.state);
                }
            }
        };
        Ok(SyscallReturn::Return(ret))

        // if ret < 0 {
        //     Err(Error::from_isize(-ret).unwrap())
        // } else {
        //     Ok(SyscallReturn::Return(ret as usize))
        // }
    }
    /// Dispatch the current MC for it to be discoverable by the host.
    pub fn dispatch(&mut self) {
        self.state.store(STATE_REQUEST, Ordering::Relaxed);
        unsafe {
            META.as_mut()
                .terminal
                .enqueue(Anp::to(&self.node as *const _ as *mut Node));
        }
        #[cfg(feature = "verbose")]
        {
            println!("[MC] dispatched {}", &self);
        }
    }
    /// Use the MC to proxy a system call.
    pub fn proxy(&mut self, process_id: usize, syscall_id: usize, args: [u64; 8]) -> &mut MC {
        // set syscall fields
        self.args = args;
        self.opcode = syscall_id as MCOpcode;
        self.procid = process_id as MCProcID;
        // dispatch to terminal
        self.dispatch();
        // println!("[MC] proxy started");
        // obstructive polling
        while self.state.load(Ordering::Relaxed) & STATE_RETURN == 0 {
            // println!("[MC] state:{}", self.state);
        }
        // this MC must be fred after use
        //println!("[MC] proxy completed");
        self
    }
    pub fn set_info(&mut self, process_id: usize, syscall_id: usize, args: [u64; 8]) {
        self.args = args;
        self.opcode = syscall_id as MCOpcode;
        self.procid = process_id as MCProcID;
    }
    /// Copy the data from the pointer to the indexed payload of the MC.
    pub fn set_payload<T>(&mut self, idx: usize, ptr: *const T, len: usize) {
        unsafe {
            core::ptr::copy(ptr as *const u8, self.payload[idx].as_mut_ptr(), len);
        }
    }
    /// Copy the data from the string to the indexed payload of the MC.
    pub fn set_string(&mut self, idx: usize, str: &str) {
        let c_filename = CString::new(str).unwrap();
        unsafe {
            core::ptr::copy(
                c_filename.as_bytes().as_ptr(),
                self.payload[idx].as_mut_ptr(),
                c_filename.to_bytes().len() + 1,
            );
        }
    }
    /// Copy the data from the indexed payload of the MC to the pointer.
    pub fn get_payload<T>(&mut self, idx: usize, ptr: *const T, len: usize) {
        unsafe {
            core::ptr::copy(self.payload[idx].as_ptr(), ptr as *mut u8, len);
        }
    }
}
