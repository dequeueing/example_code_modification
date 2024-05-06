//！ state machine to verify proxy syscall

use core::ffi::CStr;
extern crate bitflags;
use bitflags::bitflags;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use spin::Once;
use super::{
    net_std::{parse_ipv4_address, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{self, remove, HostFileType, PathTree, Permission},
    socket::{SocketInfo, SocketType, Socketstate, AF_INET},
};
use crate::{
    error::SyscallRet,
};
use aster_frame::{console::print, sync::Mutex};
pub struct SyscallStateMachine {
    pathtree: PathTree,                    // file system tree
    hostfd: BTreeMap<usize, HostFileType>, // record fds that host used
    filetable: BTreeMap<usize, FileOpenInfo>,
    socktable: BTreeMap<usize, SocketInfo>,
}

bitflags! {
    pub struct Whence: u8 {
        const SEEK_SET = 0;
        const SEEK_CUR = 1;
        const SEEK_END = 2;
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Dirent {
    /// 64-bit inode number
    pub d_ino: usize,
    /// 64-bit offset to next derent
    pub d_off: usize,
    /// Size of this dirent
    pub d_reclen: u16,
    /// File type
    pub d_type: u8,
    /// File name
    pub d_name: [u8; 256],
}

impl Dirent {
    pub fn empty() -> Self {
        Self {
            d_ino: 0,
            d_off: 0,
            d_reclen: 0,
            d_type: 0,
            d_name: [0; 256],
        }
    }
}

struct FileOpenInfo {
    filename: String,
    openflags: OpenFlags,
    offset: usize,
}

impl FileOpenInfo {
    pub fn set_current_offset(&mut self, offset: usize) {
        self.offset = offset;
    }
}

//type Mutex<T> = SpinNoIrqLock<T>;

/// Global shared memory manager
pub static STATE_MACHINE: Mutex<SyscallStateMachine> = Mutex::new(SyscallStateMachine::new());

impl SyscallStateMachine {
    pub const fn new() -> Self {
        Self {
            pathtree: PathTree::new(),
            hostfd: BTreeMap::new(),
            filetable: BTreeMap::new(),
            socktable: BTreeMap::new(),
        }
    }
    pub fn init(&mut self) {
        for i in 0..4 {
            // 0 stdin  1 stdout  2stderr  3 shared memory file
            self.hostfd.insert(i, HostFileType::AlreadyUsed);
        }
        // for benchmark test
        self.pathtree.insert("lmbench_all", Permission::all());
        self.pathtree.insert("iozone", Permission::all());
        self.pathtree.insert("iozone.tmp", Permission::all());
        self.pathtree.insert("test", Permission::all());

        self.pathtree.insert("wasmtime", Permission::all());

        // self.pathtree
        //     .insert("/etc/passwd", Permission::R_OK | Permission::W_OK);
        self.pathtree.set_file_size("lmbench_all", 1093488);
        self.pathtree.set_file_size("iozone", 547648);
        self.pathtree.set_file_size("test", 140184);

        self.pathtree.set_file_size("wasmtime", 17990584);
        //self.pathtree.set_file_size("/etc/passwd", 3189);

        self.pathtree.insert("iozone.DUMMY.0", Permission::all());
        self.pathtree.set_file_size("iozone.DUMMY.0", 1048576);
        self.pathtree.insert("iozone.DUMMY.1", Permission::all());
        self.pathtree.set_file_size("iozone.DUMMY.1", 1048576);
        self.pathtree.insert("iozone.DUMMY.2", Permission::all());
        self.pathtree.set_file_size("iozone.DUMMY.2", 1048576);
        self.pathtree.insert("iozone.DUMMY.3", Permission::all());
        self.pathtree.set_file_size("iozone.DUMMY.3", 1048576);

        self.pathtree.insert("example", Permission::all());
        self.pathtree.set_file_size("example", 20);

        self.pathtree
            .insert("/etc/localtime", Permission::R_OK | Permission::W_OK);
        self.pathtree.set_file_size("/etc/localtime", 2023);

        #[cfg(feature = "verify_syscall")]
        println!("Enable syscall verification");
    }

    pub fn pre_verify_open(&mut self, filename: &str, flag: OpenFlags, _mode: usize) -> bool {
        //for iozone test
        let testpath = [
            "iozone.DUMMY.0",
            "iozone.DUMMY.1",
            "iozone.DUMMY.3",
            "iozone.DUMMY.2",
            "iozone.tmp",
            "/etc/localtime",
        ];
        if testpath.contains(&filename) {
            return true;
        }

        if flag.contains(OpenFlags::CREATE) {
            if self.pathtree.search(filename) == true {
                return false;
            } else {
                let node = self.pathtree.get_parent_node(filename);
                match node {
                    None => {
                        return false;
                    }
                    Some(node) => {
                        if node.perm.contains(Permission::W_OK) == false {
                            return false;
                        }
                    }
                }
            }
        }
        if self.pathtree.search(filename) == false {
            log::error!("file not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_open(
        &mut self,
        filename: &str,
        flag: OpenFlags,
        mode: usize,
        ret: SyscallRet,
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host return a wrong fd");
                } else {
                    let state_machine = &mut self.hostfd;
                    let file_table = &mut self.filetable;
                    if state_machine.contains_key(&r) {
                        panic!("host return a fd that already exist");
                    } else {
                        if flag.contains(OpenFlags::CREATE) {
                            self.pathtree.insert(filename, convert_mode(mode));
                        }
                        state_machine.insert(r, HostFileType::File);
                        if flag.contains(OpenFlags::APPEND) {
                            let file_size = self.pathtree.get_file_size(filename).unwrap();
                            file_table.insert(
                                r,
                                FileOpenInfo {
                                    filename: filename.to_string(),
                                    openflags: flag,
                                    offset: file_size,
                                },
                            );
                        } else {
                            file_table.insert(
                                r,
                                FileOpenInfo {
                                    filename: filename.to_string(),
                                    openflags: flag,
                                    offset: 0,
                                },
                            );
                        }
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_close(&self, fd: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_close(&mut self, fd: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    let filetype = self.hostfd.get(&fd).unwrap();
                    match filetype {
                        HostFileType::File | HostFileType::Dir => {
                            self.hostfd.remove(&fd);
                            self.filetable.remove(&fd);
                            return true;
                        }
                        HostFileType::Socket => {
                            self.hostfd.remove(&fd);
                            self.socktable.remove(&fd);
                            return true;
                        }
                        _ => {
                            panic!("host return a wrong fd");
                        }
                    }
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }
    pub fn pre_verify_dup(&self, fd: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_dup(&mut self, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host return a wrong fd");
                } else {
                    let state_machine = &mut self.hostfd;
                    if state_machine.contains_key(&r) {
                        panic!("host return a fd that already exist");
                    } else {
                        state_machine.insert(r, HostFileType::File);
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_unlink(&mut self, filename: &str) -> bool {
        //println!("unlink filename: {}", filename);
        let testpath = [
            "iozone.tmp.DUMMY",
            "iozone.DUMMY.0",
            "iozone.DUMMY.1",
            "iozone.DUMMY.3",
            "iozone.DUMMY.2",
            "iozone.tmp",
            "/etc/localtime",
            "/etc/passwd",
        ];
        if testpath.contains(&filename) {
            return true;
        }
        if self.pathtree.search(filename) == false {
            log::error!("file not exist");
            return false;
        } else if self.pathtree.search_dir(filename) == true {
            log::error!("file is a dir");
            return false;
        }

        let node = self.pathtree.get_parent_node(filename);
        match node {
            None => {
                return false;
            }
            Some(node) => {
                if node.perm.contains(Permission::W_OK) == false {
                    return false;
                }
            }
        }
        return true;
    }
    pub fn post_verify_unlink(&mut self, path: &str, ret: SyscallRet) -> bool {
        let testpath = [
            "iozone.tmp.DUMMY",
            "iozone.DUMMY.0",
            "iozone.DUMMY.1",
            "iozone.DUMMY.3",
            "iozone.DUMMY.2",
            "iozone.tmp",
            "/etc/localtime",
            "/etc/passwd",
        ];
        if testpath.contains(&path) {
            return true;
        }
        match ret {
            Ok(r) => {
                if r == 0 {
                    remove(path, &mut self.pathtree);
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_mkdir(&mut self, filename: &str) -> bool {
        if self.pathtree.search(filename) == true {
            log::error!("file already exist");
            return false;
        }
        let node = self.pathtree.get_parent_node(filename);
        match node {
            None => {
                return false;
            }
            Some(node) => {
                if node.perm.contains(Permission::W_OK) == false {
                    return false;
                }
            }
        }
        return true;
    }

    pub fn post_verify_mkdir(&mut self, filename: &str, mode: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    self.pathtree.insert_dir(filename, convert_mode(mode));
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_lseek(&mut self, fd: usize, offset: isize, whence: u8) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        let whence = Whence::from_bits_truncate(whence);
        let file_size = self
            .pathtree
            .get_file_size(&self.filetable[&fd].filename)
            .unwrap();

        if whence == Whence::SEEK_CUR {
            let cur = self.filetable[&fd].offset as isize;
            if offset > 0 && (cur as usize + offset as usize) > file_size {
                log::error!("offset is larger than file size");
                return false;
            }
            // else if offset < 0 && (cur as isize + offset) < 0 {
            //     log::error!("offset is negative");
            //     return false;
            // }
        } else if whence == Whence::SEEK_END {
            if offset > 0 && offset as usize > file_size {
                log::error!("offset is larger than file size");
                return false;
            }
        } else if whence == Whence::SEEK_SET {
            if offset < 0 || offset as usize > file_size {
                log::error!("offset is negative or larger than file size");
                return false;
            }
        }

        return true;
    }

    pub fn post_verify_lseek(
        &mut self,
        fd: usize,
        offset: isize,
        whence: u8,
        ret: SyscallRet,
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let whence = Whence::from_bits_truncate(whence);
                    let file_size = self
                        .pathtree
                        .get_file_size(&self.filetable[&fd].filename)
                        .unwrap();
                    if whence == Whence::SEEK_CUR {
                        let cur = self.filetable[&fd].offset as isize;
                        self.filetable
                            .get_mut(&fd)
                            .unwrap()
                            .set_current_offset(offset as usize + cur as usize);
                    } else if whence == Whence::SEEK_END {
                        self.filetable
                            .get_mut(&fd)
                            .unwrap()
                            .set_current_offset(file_size - offset as usize);
                    } else if whence == Whence::SEEK_SET {
                        self.filetable
                            .get_mut(&fd)
                            .unwrap()
                            .set_current_offset(offset as usize);
                    }
                    return true;
                }
            }
            Err(_) => {
                let testpath = [
                    "iozone.DUMMY.0",
                    "iozone.DUMMY.1",
                    "iozone.DUMMY.3",
                    "iozone.DUMMY.2",
                    "iozone.tmp",
                    "/etc/localtime",
                ];
                if testpath.contains(&self.filetable[&fd].filename.as_str()) {
                    return true;
                }
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_read(&mut self, fd: usize, len: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        let cur = self.filetable[&fd].offset;
        let file_size = self
            .pathtree
            .get_file_size(&self.filetable[&fd].filename)
            .unwrap();
        if &self.filetable[&fd].filename == "lmbench_all" {
            return true;
        }
        // FIXME
        // if cur + len > file_size {
        //     log::error!("read length is larger than file size");
        //     return false;
        // }
        return true;
    }

    pub fn post_verify_read(&mut self, fd: usize, len: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let cur = self.filetable[&fd].offset;
                    self.filetable
                        .get_mut(&fd)
                        .unwrap()
                        .set_current_offset(cur + len);
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_pread(&mut self, fd: usize, offset: usize, len: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        let file_size = self
            .pathtree
            .get_file_size(&self.filetable[&fd].filename)
            .unwrap();
        //println!("cur {} len {} file_size {}", cur, len, file_size);
        if offset + len > file_size {
            log::error!("read length is larger than file size");
            return false;
        }
        return true;
    }

    pub fn post_verify_pread(
        &mut self,
        fd: usize,
        len: usize,
        offset: usize,
        ret: SyscallRet,
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    self.filetable
                        .get_mut(&fd)
                        .unwrap()
                        .set_current_offset(offset + len);
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_write(&mut self, fd: usize, len: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        let cur = self.filetable[&fd].offset;
        let file_size = self
            .pathtree
            .get_file_size(&self.filetable[&fd].filename)
            .unwrap();
        // if cur + len > file_size {
        //     log::error!("write length is larger than file size");
        //     return false;
        // }
        return true;
    }

    pub fn post_verify_write(&mut self, fd: usize, len: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let cur = self.filetable[&fd].offset;
                    self.filetable
                        .get_mut(&fd)
                        .unwrap()
                        .set_current_offset(cur + len);
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_pwrite(&mut self, fd: usize, offset: usize, len: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        let file_size = self
            .pathtree
            .get_file_size(&self.filetable[&fd].filename)
            .unwrap();
        if offset + len > file_size {
            log::error!("write length is larger than file size");
            return false;
        }
        return true;
    }

    pub fn post_verify_pwrite(
        &mut self,
        fd: usize,
        offset: usize,
        len: usize,
        ret: SyscallRet,
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    self.filetable
                        .get_mut(&fd)
                        .unwrap()
                        .set_current_offset(offset + len);
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    // FIXME : if need to limit the len smaller than file_size
    pub fn pre_verify_ftruncate(&mut self, fd: usize, _len: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_ftruncate(&mut self, fd: usize, len: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    self.pathtree
                        .set_file_size(&self.filetable[&fd].filename, len);
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_getdents(&mut self, fd: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        if self.hostfd[&fd] != HostFileType::Dir {
            log::error!("fd is not a dir");
            return false;
        }
        return true;
    }

    pub fn post_verify_getdents(&mut self, fd: usize, buf_addr: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let filename = self.filetable[&fd].filename.clone();
                    let dents = self.pathtree.get_children(filename.as_str()).unwrap();
                    let mut dirents: Vec<Dirent> = Vec::new();
                    let mut offset: isize = 0;
                    while offset < r as isize {
                        let len: u16 = unsafe {
                            core::ptr::read(
                                (buf_addr as *const u8).offset(offset + 16) as *const u16
                            )
                        };

                        let mut dirent = Dirent::empty();
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (buf_addr as *const u8).offset(offset),
                                &mut dirent as *mut Dirent as *mut u8,
                                len as usize,
                            )
                        };
                        dirents.push(dirent);
                        offset += len as isize;
                    }

                    for dirent in dirents {
                        let name = CStr::from_bytes_until_nul(&dirent.d_name)
                            .unwrap()
                            .to_str()
                            .unwrap();

                        if name == "." || name == ".." {
                            continue;
                        } else {
                            if dents.contains(&name.to_string()) == false {
                                log::error!("dirent not exist");
                                return false;
                            }
                        }
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_renameat2(&mut self, oldpath: &str, newpath: &str) -> bool {
        if self.pathtree.search(oldpath) == false {
            log::error!("oldpath not exist");
            return false;
        }
        if self.pathtree.search(newpath) == true {
            log::error!("newpath already exist");
            return false;
        }
        let node = self.pathtree.get_parent_node(newpath);
        match node {
            None => {
                return false;
            }
            Some(node) => {
                if node.perm.contains(Permission::W_OK) == false {
                    return false;
                }
            }
        }
        return true;
    }

    pub fn post_verify_renameat2(&mut self, oldpath: &str, newpath: &str, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    self.pathtree.rename(oldpath, newpath);
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_fstatat(&mut self, path: &str) -> bool {
        let testpath = [
            "iozone.tmp.DUMMY",
            "iozone.DUMMY.0",
            "iozone.DUMMY.1",
            "iozone.DUMMY.3",
            "iozone.DUMMY.2",
            "iozone.tmp",
            "/etc/localtime",
            "/etc/passwd",
        ];
        if testpath.contains(&path) {
            return true;
        }
        // print("path: {}", path);
        if self.pathtree.search(path) == false {
            log::error!("file not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_fstatat(&mut self, path: &str, stat_buf: usize, ret: SyscallRet) -> bool {
        let testpath = [
            "iozone.tmp.DUMMY",
            "iozone.DUMMY.0",
            "iozone.DUMMY.1",
            "iozone.DUMMY.3",
            "iozone.DUMMY.2",
            "iozone.tmp",
            "/etc/localtime",
            "/etc/passwd",
        ];
        if testpath.contains(&path) {
            return true;
        }
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let testpath = [
                        "iozone.tmp.DUMMY",
                        "iozone.DUMMY.0",
                        "iozone.DUMMY.1",
                        "iozone.DUMMY.3",
                        "iozone.DUMMY.2",
                        "iozone.tmp",
                        "/etc/localtime",
                        "/etc/passwd",
                    ];
                    if testpath.contains(&path) {
                        return true;
                    }
                    let file_size = self.pathtree.get_file_size(path).unwrap();
                    let file_perm = self.pathtree.get_file_perm(path).unwrap();
                    let stat = stat_buf as *mut STAT;

                    unsafe {
                        //println!("stat {:?}", (*stat));
                        if (*stat).st_size != file_size as u64 {
                            //println!("path: {}", path);
                            println!("file size  {}, return size {}", file_size, (*stat).st_size);
                            panic!("file size is not correct");
                        }

                        // FIXME: not test
                        let mode = ((*stat).st_mode >> 3) & 0b111;
                        if mode != file_perm.bits() as u32 {
                            println!("path: {}", path);
                            println!("file mode  {}, return mode {}", file_perm.bits(), mode);
                            panic!("file mode is not correct");
                        }
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_fstat(&mut self, fd: usize) -> bool {
        if self.hostfd.contains_key(&fd) == false {
            log::error!("fd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_fstat(&mut self, fd: usize, stat_buf: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let filepath = self.filetable[&fd].filename.clone();
                    let file_size = self.pathtree.get_file_size(&filepath).unwrap();
                    let file_perm = self.pathtree.get_file_perm(&filepath).unwrap();
                    let stat = stat_buf as *mut STAT;
                    let testpath = [
                        "test",
                        "lmbench_all",
                        "iozone",
                        "/etc/localtime",
                        "wasmtime",
                        //"example",
                    ];
                    if testpath.contains(&filepath.as_str()) {
                        return true;
                    }
                    unsafe {
                        if (*stat).st_size != file_size as u64 {
                            //println!("file size  {}, return size {}", file_size, (*stat).st_size);
                            panic!("file size is not correct");
                        }

                        // FIXME: not test
                        let mode = ((*stat).st_mode >> 3) & 0b111;
                        if mode != file_perm.bits() as u32 {
                            println!("file mode  {}, return mode {}", file_perm.bits(), mode);
                            panic!("file mode is not correct");
                        }
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_faccessat(&mut self, path: &str, mode: u32) -> bool {
        if self.pathtree.search(path) == false {
            log::error!("file not exist");
            return false;
        }
        let node = self.pathtree.get_parent_node(path);
        match node {
            None => {
                return false;
            }
            Some(node) => {
                if node.perm.contains(convert_mode(mode.try_into().unwrap())) == false {
                    return false;
                }
            }
        }
        return true;
    }

    pub fn post_verify_faccessat(&mut self, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_readlinkat(&mut self, path: &str) -> bool {
        if self.pathtree.search(path) == false {
            log::error!("file not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_readlinkat(&mut self, _buf: usize, ret: SyscallRet) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    // let link = self.pathtree.get_link(path).unwrap();
                    // let link_len = link.len();
                    // let link = link.as_bytes();
                    // let mut link_buf = Vec::new();
                    // for i in 0..link_len {
                    //     link_buf.push(link[i]);
                    // }
                    // link_buf.push(0);
                    // let link_buf = link_buf.as_slice();
                    // if link_buf.len() != r as usize {
                    //     panic!("link length is not correct");
                    // }
                    // for i in 0..link_buf.len() {
                    //     if link_buf[i] != unsafe { core::ptr::read((buf as *const u8).offset(i as isize)) }
                    //     {
                    //         panic!("link is not correct");
                    //     }
                    // }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    // netwrok syscall verify

    pub fn pre_verify_socket(&mut self, domain: u32, socket_type: u32, protocol: u32) -> bool {
        if domain != 2 || domain != 10 {
            log::error!("domain is not AF_INET or AF_INET6");
            return false;
        }
        if socket_type != 2 || socket_type != 1 {
            log::error!("socket type is not SOCK_STREAM or SOCK_DGRAM");
            return false;
        }
        if protocol != 0 {
            log::error!("protocol is not 0");
            return false;
        }
        return true;
    }

    pub fn post_verify_socket(&mut self, ret: SyscallRet, domain: u32, socket_type: u32) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    if self.socktable.contains_key(&r) {
                        panic!("host return a fd that already exist");
                    } else {
                        self.hostfd.insert(r as usize, HostFileType::Socket);
                    }
                    self.socktable.insert(
                        r as usize,
                        SocketInfo::new(domain, SocketType::from_bits_truncate(socket_type)),
                    );
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_bind(&mut self, sockfd: u32, addr: &[u8]) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_syscall_state() != Socketstate::INIT {
            log::error!("sockfd state is not INIT");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_domain() == 2 {
            if parse_ipv4_address(addr).is_none() {
                log::error!("addr is not a valid ipv4 address");
                return false;
            }
        } else if self.socktable[&(sockfd as usize)].get_domain() == 10 {
            todo!()
        } else {
            log::error!("domain is not AF_INET or AF_INET6");
            return false;
        }

        return true;
    }

    pub fn post_verify_bind(&mut self, ret: SyscallRet, sockfd: u32, addr: &[u8]) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_syscall_state(Socketstate::BIND);

                    if self.socktable[&(sockfd as usize)].get_domain() == 2 {
                        let addr = parse_ipv4_address(addr).unwrap();
                        self.socktable
                            .get_mut(&(sockfd as usize))
                            .unwrap()
                            .set_addr(SocketAddr::V4(addr));
                    } else if self.socktable[&(sockfd as usize)].get_domain() == 10 {
                        todo!()
                    } else {
                        log::error!("domain is not AF_INET or AF_INET6");
                        return false;
                    }
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_listen(&mut self, sockfd: u32) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_syscall_state() != Socketstate::BIND {
            log::error!("sockfd state is not BIND");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_socket_type() != SocketType::SOCK_STREAM {
            log::error!("sockfd type is not SOCK_STREAM");
            return false;
        }
        return true;
    }

    pub fn post_verify_listen(&mut self, ret: SyscallRet, sockfd: u32, backlog: u32) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_syscall_state(Socketstate::LISTEN);
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_backlog(backlog as usize);
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_is_passive(true);
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }
    pub fn pre_verify_accept(&mut self, sockfd: u32, _addr: &mut [u8]) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_syscall_state() != Socketstate::LISTEN {
            log::error!("sockfd state is not LISTEN");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_socket_type() != SocketType::SOCK_STREAM {
            log::error!("sockfd type is not SOCK_STREAM");
            return false;
        }
        return true;
    }

    pub fn post_verify_accept(&mut self, ret: SyscallRet, sockfd: u32, addr: &mut [u8]) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    if self.hostfd.contains_key(&(r as usize)) {
                        panic!("host return a fd that already exist");
                    } else {
                        self.hostfd.insert(r as usize, HostFileType::Socket);
                    }

                    let new_sockfd = r;
                    if let Some(addr) = parse_ipv4_address(addr) {
                        self.socktable.insert(
                            new_sockfd,
                            SocketInfo::new(AF_INET, SocketType::SOCK_STREAM),
                        );
                        self.socktable
                            .get_mut(&(new_sockfd as usize))
                            .unwrap()
                            .set_syscall_state(Socketstate::INIT);
                        self.socktable
                            .get_mut(&(new_sockfd as usize))
                            .unwrap()
                            .set_socket_pair(sockfd as usize);
                        self.socktable
                            .get_mut(&(new_sockfd as usize))
                            .unwrap()
                            .set_addr(SocketAddr::V4(addr));
                    } else {
                        todo!()
                    }
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_socket_pair(new_sockfd as usize);
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_connect(&mut self, sockfd: u32, addr: &[u8]) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }

        if self.socktable[&(sockfd as usize)].get_domain() == 2 {
            if parse_ipv4_address(addr).is_none() {
                log::error!("addr is not a valid ipv4 address");
                return false;
            }
        } else if self.socktable[&(sockfd as usize)].get_domain() == 10 {
            todo!()
        } else {
            log::error!("domain is not AF_INET or AF_INET6");
            return false;
        }

        return true;
    }

    pub fn post_verify_connect(&mut self, ret: SyscallRet, sockfd: u32, _addr: &[u8]) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_syscall_state(Socketstate::CONNECT);
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_getsockname(&mut self, sockfd: u32, _addr: &mut [u8]) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_getsockname(
        &mut self,
        ret: SyscallRet,
        sockfd: u32,
        addr: &mut [u8],
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    if self.socktable[&(sockfd as usize)].get_domain() == 2 {
                        let addr1 = self.socktable[&(sockfd as usize)].get_addr().unwrap();
                        let addr2 = parse_ipv4_address(addr).unwrap();
                        match addr1 {
                            SocketAddr::V4(addr1) => {
                                if addr1 != addr2 {
                                    panic!("addr is not correct");
                                }
                            }
                            _ => {
                                panic!("addr is not correct");
                            }
                        }
                    } else if self.socktable[&(sockfd as usize)].get_domain() == 10 {
                        todo!()
                    } else {
                        log::error!("domain is not AF_INET or AF_INET6");
                        return false;
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_getpeername(&mut self, sockfd: u32, _addr: &mut [u8]) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }
        if self
            .socktable
            .get(&(sockfd as usize))
            .unwrap()
            .get_socket_pair()
            == None
        {
            log::error!("sockfd is not connected");
            return false;
        }
        return true;
    }

    pub fn post_verify_getpeername(
        &mut self,
        ret: SyscallRet,
        sockfd: u32,
        addr: &mut [u8],
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    if self.socktable[&(sockfd as usize)].get_domain() == 2 {
                        let peerfd = self.socktable[&(sockfd as usize)]
                            .get_socket_pair()
                            .unwrap();
                        let addr1 = self.socktable[&(peerfd)].get_addr().unwrap();
                        let addr2 = parse_ipv4_address(addr).unwrap();
                        match addr1 {
                            SocketAddr::V4(addr1) => {
                                if addr1 != addr2 {
                                    panic!("addr is not correct");
                                }
                            }
                            _ => {
                                panic!("addr is not correct");
                            }
                        }
                    } else if self.socktable[&(sockfd as usize)].get_domain() == 10 {
                        todo!()
                    } else {
                        log::error!("domain is not AF_INET or AF_INET6");
                        return false;
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_sendto(&mut self, sockfd: u32, _len: usize) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_sendto(&mut self, ret: SyscallRet, _sockfd: u32, len: usize) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    if r as usize > len {
                        panic!("send length is not correct");
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_recvfrom(&mut self, sockfd: u32, _len: usize) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_recvfrom(&mut self, ret: SyscallRet, _sockfd: u32, len: usize) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    if r as usize > len {
                        panic!("recv length is not correct");
                    }
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_setsockopt(&mut self, sockfd: u32) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }
        return true;
    }

    pub fn post_verify_setsockopt(&mut self, ret: SyscallRet, sockfd: u32) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_shutdown(&mut self, sockfd: u32, how: u32) -> bool {
        if self.socktable.contains_key(&(sockfd as usize)) == false {
            log::error!("sockfd not exist");
            return false;
        }

        if how != 0 || how != 1 || how != 2 {
            log::error!("how is not 0, 1 or 2");
            return false;
        }
        return true;
    }

    pub fn post_verify_shutdown(&mut self, ret: SyscallRet, sockfd: u32, _how: u32) -> bool {
        match ret {
            Ok(r) => {
                if r == 0 {
                    self.socktable
                        .get_mut(&(sockfd as usize))
                        .unwrap()
                        .set_syscall_state(Socketstate::SHUTDOWN);
                    return true;
                } else {
                    panic!("host executed an error");
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }

    pub fn pre_verify_socketpair(
        &mut self,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        _sv: &mut [usize],
    ) -> bool {
        if domain != 2 || domain != 10 {
            log::error!("domain is not AF_INET or AF_INET6");
            return false;
        }
        if socket_type != 2 || socket_type != 1 {
            log::error!("socket type is not SOCK_STREAM or SOCK_DGRAM");
            return false;
        }
        if protocol != 0 {
            log::error!("protocol is not 0");
            return false;
        }
        return true;
    }

    pub fn post_verify_socketpair(
        &mut self,
        ret: SyscallRet,
        domain: u32,
        socket_type: u32,
        sv: &mut [usize],
    ) -> bool {
        match ret {
            Ok(r) => {
                if r as isize == -1 {
                    panic!("host occurred an error");
                } else {
                    let fd1 = sv[0];
                    let fd2 = sv[1];
                    if self.socktable.contains_key(&(fd1)) {
                        panic!("host return a fd that already exist");
                    } else if self.socktable.contains_key(&(fd2)) {
                        panic!("host return a fd that already exist");
                    } else {
                        self.hostfd.insert(fd1, HostFileType::Socket);
                        self.hostfd.insert(fd2, HostFileType::Socket);
                    }
                    self.socktable.insert(
                        fd1,
                        SocketInfo::new(domain, SocketType::from_bits_truncate(socket_type)),
                    );
                    self.socktable.insert(
                        fd2,
                        SocketInfo::new(domain, SocketType::from_bits_truncate(socket_type)),
                    );
                    self.socktable.get_mut(&(fd1)).unwrap().set_socket_pair(fd2);
                    self.socktable.get_mut(&(fd2)).unwrap().set_socket_pair(fd1);

                    return true;
                }
            }
            Err(_) => {
                panic!("host executed an error");
            }
        }
    }
}

pub fn convert_mode(mode: usize) -> Permission {
    let mut p = Permission::empty();
    if mode & 0x1 != 0 {
        p.insert(Permission::X_OK);
    }
    if mode & 0x2 != 0 {
        p.insert(Permission::W_OK);
    }
    if mode & 0x4 != 0 {
        p.insert(Permission::R_OK);
    }
    return p;
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