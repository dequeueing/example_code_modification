use alloc::vec::Vec;
use aster_frame::arch::console::print;
use core::mem::size_of;
use core::sync::atomic::Ordering;

use super::mc::{MC, PAYLOAD_CNT, PAYLOAD_SIZE, STATE_RETURN};
use super::{expand_args, proxy_syscall};
use crate::syscall::fstatat::{STAT, TimeSpec};
// use crate::fs::OpenFlags;
// use crate::processor::current_process; // fixme: current!().pid()

use crate::proxy::path::convert_dirfd_to_path;
use crate::time::timespec_t;
// use crate::proxy::sm::STATE_MACHINE;
use crate::{current, syscall};
use crate::syscall::SyscallReturn;
use crate::prelude::*;
// use crate::timer::ffi::TimeSpec;
// use crate::utils::error::{SyscallErr, Result<SyscallReturn>};

pub fn proxy_sys_openat(dirfd: usize, filename: &str, flag: OpenFlags, mode: usize) -> Result<SyscallReturn> {
    //println!("In proxy open");
    let dirent_name = convert_dirfd_to_path(dirfd, filename);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_open(dirent_name.as_str(), flag, mode));
    let mc = MC::alloc();
    mc.set_string(0, filename);
    //println!("After set data");
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_OPEN as usize,
            expand_args!(dirfd, flag.bits() as usize, mode),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_open(dirent_name.as_str(), flag, mode, r));
    r
}

pub fn proxy_sys_dup(oldfd: usize) -> Result<SyscallReturn> {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_dup(oldfd));
    let mc = MC::alloc();
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_DUP as usize,
            expand_args!(oldfd),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_dup(r));
    r
}

pub fn proxy_sys_unlinkat(dirfd: usize, pathname: &str, flags: u32) -> Result<SyscallReturn> {
    let dirent_name = convert_dirfd_to_path(dirfd, pathname);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_unlink(dirent_name.as_str()));
    let mc = MC::alloc();
    mc.set_string(0, pathname);
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_UNLINK as usize,
            expand_args!(dirfd, flags as usize),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_unlink(pathname, r));
    r
}

pub fn proxy_sys_mkdirat(dirfd: usize, pathname: &str, mode: usize) -> Result<SyscallReturn> {
    let dirent_name = convert_dirfd_to_path(dirfd, pathname);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_mkdir(dirent_name.as_str()));
    let mc = MC::alloc();
    mc.set_string(0, pathname);
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_MKDIR as usize,
            expand_args!(dirfd, mode),
        )
        .free();

    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_mkdir(dirent_name.as_str(), mode, r));

    return Ok(SyscallReturn::Return(0));
    // match r {
    //     Ok(_) => {
    //         return r;
    //     }
    //     Err(e) => {
    //         log::error!("mkdirat failed: {:?}", e);
    //         let e = SyscallErr::EEXIST;
    //         return Err(e);
    //     }
    // }
}

pub fn proxy_sys_close(fd: usize) -> Result<SyscallReturn> {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_close(fd) == true);

    let r = proxy_syscall(
        current!().pid() as usize,
        syscall::SYS_CLOSE as usize,
        expand_args!(fd),
    );
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_close(fd, r));
    r
}

pub fn proxy_sys_write(fd: usize, buf: &[u8]) -> Result<SyscallReturn> {
    let len = buf.len();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_write(fd, len));
    let mc = MC::alloc();
    mc.set_payload(0, buf.as_ptr(), buf.len());
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_WRITE as usize,
            expand_args!(fd, buf.len()),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_write(fd, len, r));
    r
}

// pub fn proxy_sys_writev(fd: usize, iovs: &[Iovec]) -> Result<SyscallReturn> {
//     let mc = MC::alloc();
//     mc.set_payload(0, iovs.as_ptr(), iovs.len());
//     mc.proxy(
//         current!().pid(),
//         syscall::SYS_WRITEV,
//         expand_args!(fd, iovs.len()),
//     )
//     .free()
//     // TODO: add WRITEV handler in daemon
// }

pub fn proxy_sys_pwrite(fd: usize, buf: &[u8], offset: usize) -> Result<SyscallReturn> {
    let len = buf.len();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_pwrite(fd, len, offset));
    let mc = MC::alloc();
    mc.set_payload(0, buf.as_ptr(), buf.len());
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_PWRITE64 as usize,
            expand_args!(fd, buf.len(), offset),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_pwrite(fd, len, offset, r));
    r
}

pub fn proxy_sys_read(fd: usize, buf: &mut [u8]) -> Result<SyscallReturn> {
    let mut len = buf.len();
    log::info!("proxy_sys_read: fd: {}, len: {}", fd, len);

    if len <= PAYLOAD_SIZE {
        #[cfg(feature = "verify_syscall")]
        assert!(STATE_MACHINE.lock().pre_verify_read(fd, len));

        let mc = MC::alloc().proxy(
            current!().pid() as usize,
            syscall::SYS_READ as usize,
            expand_args!(fd, buf.len()),
        );

        mc.get_payload(0, buf.as_ptr(), buf.len());
        let r = mc.free();
        #[cfg(feature = "verify_syscall")]
        assert!(STATE_MACHINE.lock().post_verify_read(fd, len, r));
        return r;
    }
    let mut offset: usize = 0;
    let mut completed: usize = 0;
    //let mut ret = Ok(0);
    let mut cnt: isize = 0;
    let payload_size = PAYLOAD_SIZE * PAYLOAD_CNT;

    while completed != len {
        let mut pending: Vec<&mut MC> = Vec::new();
        let mut size: usize = 0;

        while let Some(mc) = MC::try_alloc() {
            size = len - offset;
            if size == 0 {
                break;
            }
            if payload_size < size {
                size = payload_size
            };

            mc.set_info(
                current!().pid() as usize,
                syscall::SYS_READ as usize,
                expand_args!(fd, size, offset),
            );
            mc.dispatch();
            pending.push(mc);

            offset += size;
        }

        while let Some(mc) = pending.pop() {
            while mc.state.load(Ordering::Relaxed) & STATE_RETURN == 0 {}

            completed += mc.args[1] as usize;

            mc.get_payload(
                0,
                buf.as_ptr().wrapping_add(mc.args[2] as usize),
                mc.args[1] as usize,
            );

            if let ret = mc.free().unwrap() {
                // if let ret = SyscallReturn::Return(r) {
                //     cnt += r;
                // }
                match ret {
                    SyscallReturn::Return(temp) => {
                        cnt += temp;
                    },
                    SyscallReturn::NoReturn => {
                        
                    }
                }
            }
        }
    }
    Ok(SyscallReturn::Return(cnt))
}

pub fn proxy_sys_pread(fd: usize, buf: &mut [u8], offset: usize) -> Result<SyscallReturn> {
    let len = buf.len();

    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_pread(fd, len, offset));
    let mc = MC::alloc().proxy(
        current!().pid() as usize,
        syscall::SYS_PREAD64 as usize,
        expand_args!(fd, buf.len(), offset),
    );
    mc.get_payload(0, buf.as_ptr(), mc.ret as usize);
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_pread(fd, len, offset, r));
    r
}

pub fn proxy_sys_getdents(fd: usize, buf: &mut [u8]) -> Result<SyscallReturn> {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_getdents(fd));
    let mc = MC::alloc().proxy(
        current!().pid() as usize,
        syscall::SYS_GETDENTS as usize,
        expand_args!(fd, buf.len()),
    );
    mc.get_payload(0, buf.as_ptr(), buf.len());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_getdents(fd, buf.as_ptr() as usize, r));
    r
}

/// FIXME: need to think proxy problem
/// should not proxy it
pub fn proxy_sys_chdir(path: &str) -> Result<SyscallReturn> {
    let mc = MC::alloc();
    mc.set_string(0, path);
    mc.proxy(
        current!().pid() as usize,
        syscall::SYS_CHDIR as usize,
        expand_args!(),
    )
    .free()
}

pub fn proxy_sys_renameat2(
    olddirfd: usize,
    oldpath: &str,
    newdirfd: usize,
    newpath: &str,
    flags: u32,
) -> Result<SyscallReturn> {
    let dirent_oldpath = convert_dirfd_to_path(olddirfd, oldpath);
    let dirent_newpath = convert_dirfd_to_path(newdirfd, newpath);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_renameat2(dirent_oldpath.as_str(), dirent_newpath.as_str()));
    let mc = MC::alloc();
    mc.set_string(0, oldpath);
    mc.set_string(1, newpath);
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_RENAMEAT2 as usize,
            expand_args!(olddirfd, newdirfd, flags as usize),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_renameat2(
        &dirent_oldpath.as_str(),
        &dirent_newpath.as_str(),
        r,
    ));
    r

    // TODO: add SYS_REMANEAT2 daemon handler
}

pub fn proxy_sys_fstatat(dirfd: usize, path: &str, buf: &mut STAT, flag: u32) -> Result<SyscallReturn> {
    let convert_path = convert_dirfd_to_path(dirfd, path);

    //println!("fstatat path: {}", path);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_fstatat(convert_path.as_str()));
    let mc = MC::alloc();
    mc.set_string(0, path);
    mc.proxy(
        current!().pid() as usize,
        syscall::SYS_FSTATAT as usize,
        expand_args!(dirfd, flag as usize),
    );
    mc.get_payload(1, buf as *mut STAT, size_of::<STAT>());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_fstatat(path, buf as *mut STAT as usize, r));
    r
}

pub fn proxy_sys_fstat(fd: usize, buf: &mut STAT) -> Result<SyscallReturn> {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_fstat(fd));
    let mc = MC::alloc().proxy(
        current!().pid() as usize,
        syscall::SYS_FSTAT as usize,
        expand_args!(fd, buf as *mut STAT as usize),
    );
    mc.get_payload(0, buf as *mut STAT, size_of::<STAT>());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_fstat(fd, buf as *mut STAT as usize, r));
    r
}

pub fn proxy_sys_faccessat(dirfd: usize, pathname: &str, mode: u32, flags: u32) -> Result<SyscallReturn> {
    let convert_path = convert_dirfd_to_path(dirfd, pathname);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_faccessat(convert_path.as_str(), mode));
    let mc = MC::alloc();
    mc.set_string(0, pathname);
    let r = mc
        .proxy(
            current!().pid() as usize,
            syscall::SYS_FACCESSAT as usize,
            expand_args!(dirfd, mode as usize, flags as usize),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_faccessat(r));
    r
}

#[allow(unused)]
pub fn proxy_sys_utimensat(
    dirfd: usize,
    pathname: &str,
    times: &mut TimeSpec,
    flags: u32,
) -> Result<SyscallReturn> {
    let mc = MC::alloc();
    mc.set_string(0, pathname);
    mc.proxy(
        current!().pid() as usize,
        syscall::SYS_UTIMENSAT as usize,
        expand_args!(dirfd, flags as usize),
    );
    mc.get_payload(0, times as *mut TimeSpec, size_of::<TimeSpec>());
    mc.free()
    // TODO: add SYS_UTIMENSAT daemon handler
}

// only allowed to set the offset between 0 and the file size
pub fn proxy_sys_lseek(fd: usize, offset: isize, whence: u8) -> Result<SyscallReturn> {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_lseek(fd, offset, whence));
    let ret = proxy_syscall(
        current!().pid() as usize,
        syscall::SYS_LSEEK as usize,
        expand_args!(fd, offset as usize, whence as usize),
    );
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_lseek(fd, offset, whence, ret));
    ret
}

// FIXME
pub fn proxy_sys_fcntl(fd: usize, cmd: usize, arg: usize) -> Result<SyscallReturn> {
    proxy_syscall(
        current!().pid() as usize,
        syscall::SYS_FCNTL as usize,
        expand_args!(fd, cmd, arg),
    )
}

pub fn proxy_sys_readlinkat(dirfd: usize, path_name: &str, buf: &mut [u8]) -> Result<SyscallReturn> {
    let convert_path = convert_dirfd_to_path(dirfd, path_name);
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_readlinkat(convert_path.as_str()));
    let mc = MC::alloc();
    mc.set_string(0, path_name);
    mc.proxy(
        current!().pid() as usize,
        syscall::SYS_READLINKAT as usize,
        expand_args!(dirfd, buf.len()),
    );
    mc.get_payload(1, buf.as_mut_ptr(), buf.len());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_readlinkat(buf.as_mut_ptr() as usize, r));
    r
}

pub fn proxy_sys_ftruncate(fd: usize, len: usize) -> Result<SyscallReturn> {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_ftruncate(fd, len));
    let r = proxy_syscall(
        current!().pid() as usize,
        syscall::SYS_FTRUNCATE as usize,
        expand_args!(fd, len),
    );
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_ftruncate(fd, len, r));
    r
}

// pub fn proxy_sys_pselect(
//     nfds: usize,
//     readfds: &mut FdSet,
//     writefds: &mut FdSet,
//     exceptfds: &mut FdSet,
//     _timeout: Option<TimeSpec>,
//     _sigmask: Option<SigSet>,
// ) -> Result<SyscallReturn> {
//     set_data1(readfds as *mut FdSet as usize, mem::size_of::<FdSet>());
//     set_data2(writefds as *mut FdSet as usize, mem::size_of::<FdSet>());
//     set_data3(exceptfds as *mut FdSet as usize, mem::size_of::<FdSet>());
//     // let timeout_addr = PhysAddr::from(KernelAddr::from(timeout as *mut TimeSpec as usize)).into();
//     proxy_syscall!(
//         syscall::SYS_PSELECT6,
//         nfds,
//         get_addr1(),
//         get_addr2(),
//         get_addr3(),
//         0,
//         0
//     )
// }

bitflags! {
    /// Open file flags
    pub struct OpenFlags: u32 {
        const APPEND = 1 << 10;
        const ASYNC = 1 << 13;
        const DIRECT = 1 << 14;
        const DSYNC = 1 << 12;
        const EXCL = 1 << 7;
        const NOATIME = 1 << 18;
        const NOCTTY = 1 << 8;
        const NOFOLLOW = 1 << 17;
        const PATH = 1 << 21;
        /// TODO: need to find 1 << 15
        const TEMP = 1 << 15;
        /// Read only
        const RDONLY = 0;
        /// Write only
        const WRONLY = 1 << 0;
        /// Read & Write
        const RDWR = 1 << 1;
        /// Allow create
        const CREATE = 1 << 6;
        /// Clear file and return an empty one
        const TRUNC = 1 << 9;
        /// Directory
        const DIRECTORY = 1 << 16;
        /// Enable the close-on-exec flag for the new file descriptor
        const CLOEXEC = 1 << 19;
        /// When possible, the file is opened in nonblocking mode
        const NONBLOCK = 1 << 11;
    }
}