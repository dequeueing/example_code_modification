// SPDX-License-Identifier: MPL-2.0

use super::{SyscallReturn, SYS_OPENAT};
use crate::{
    fs::{
        file_handle::FileLike,
        file_table::{FdFlags, FileDescripter},
        fs_resolver::{FsPath, AT_FDCWD},
        utils::CreationFlags,
    },
    log_syscall_entry,
    prelude::*,
    proxy::fs::proxy_sys_openat,
    syscall::constants::MAX_FILENAME_LEN,
    util::read_cstring_from_user,
};

pub fn sys_openat(
    dirfd: FileDescripter,
    pathname_addr: Vaddr,
    flags: u32,
    mode: u16,
) -> Result<SyscallReturn> {
    log_syscall_entry!(SYS_OPENAT);
    let pathname = read_cstring_from_user(pathname_addr, MAX_FILENAME_LEN)?;
    debug!(
        "dirfd = {}, pathname = {:?}, flags = {}, mode = {}",
        dirfd, pathname, flags, mode
    );

    proxy_sys_openat(
        dirfd as usize,
        pathname.to_str().unwrap(),
        crate::proxy::fs::OpenFlags::from_bits_truncate(flags),
        mode as usize,
    )

    // let current = current!();
    // let file_handle = {
    //     let pathname = pathname.to_string_lossy();
    //     let fs_path = FsPath::new(dirfd, pathname.as_ref())?;
    //     let mask_mode = mode & !current.umask().read().get();
    //     let inode_handle = current.fs().read().open(&fs_path, flags, mask_mode)?;
    //     Arc::new(inode_handle)
    // };
    // let mut file_table = current.file_table().lock();
    // let fd = {
    //     let fd_flags =
    //         if CreationFlags::from_bits_truncate(flags).contains(CreationFlags::O_CLOEXEC) {
    //             FdFlags::CLOEXEC
    //         } else {
    //             FdFlags::empty()
    //         };
    //     file_table.insert(file_handle, fd_flags)
    // };
    // Ok(SyscallReturn::Return(fd as _))
}

pub fn sys_open(pathname_addr: Vaddr, flags: u32, mode: u16) -> Result<SyscallReturn> {
    self::sys_openat(AT_FDCWD, pathname_addr, flags, mode)
}

/// File for output busybox ash log.
struct BusyBoxTraceFile;

impl FileLike for BusyBoxTraceFile {
    fn write(&self, buf: &[u8]) -> Result<usize> {
        debug!("ASH TRACE: {}", core::str::from_utf8(buf)?);
        Ok(buf.len())
    }
}

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
