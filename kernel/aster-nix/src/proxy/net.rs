use alloc::vec::Vec;

use super::sm::STATE_MACHINE;
use crate::{
    processor::current_process,
    proxy::{expand_args, mc::MC},
    syscall,
    utils::error::SyscallRet,
};

pub fn proxy_sys_socket(domain: u32, socket_type: u32, protocol: u32) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_socket(domain, socket_type, protocol));

    let mc = MC::alloc();
    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_SOCKET,
            expand_args!(domain, socket_type, protocol),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_socket(r, domain, socket_type));
    r
}

pub fn proxy_sys_bind(sockfd: u32, addr: &[u8]) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_bind(sockfd, addr));
    let mc = MC::alloc();
    mc.set_payload(0, addr.as_ptr(), addr.len());
    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_BIND,
            expand_args!(sockfd, addr.len()),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_bind(r, sockfd, addr));
    r
}

pub fn proxy_sys_listen(sockfd: u32, backlog: u32) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_listen(sockfd));
    let mc = MC::alloc();
    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_LISTEN,
            expand_args!(sockfd, backlog),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_listen(r, sockfd, backlog));
    r
}

pub fn proxy_sys_accept(sockfd: u32, addr: &mut Vec<u8>) -> SyscallRet {
    addr.clear();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_accept(sockfd, addr));
    let mc = MC::alloc();
    mc.proxy(
        current_process().pid(),
        syscall::SYSCALL_ACCEPT,
        expand_args!(sockfd, addr.as_ptr() as usize, addr.len()),
    );
    mc.get_payload(0, addr.as_ptr(), addr.len());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_accept(r, sockfd, addr));
    r
}

pub fn proxy_sys_connect(sockfd: u32, addr: &[u8]) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_connect(sockfd, addr));

    let mc = MC::alloc();
    mc.set_payload(0, addr.as_ptr(), addr.len());
    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_CONNECT,
            expand_args!(sockfd, addr.len()),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_connect(r, sockfd, addr));
    r
}

pub fn proxy_getsockname(sockfd: u32, addr: &mut Vec<u8>) -> SyscallRet {
    addr.clear();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_getsockname(sockfd, addr));
    let mc = MC::alloc();
    mc.proxy(
        current_process().pid(),
        syscall::SYSCALL_GETSOCKNAME,
        expand_args!(sockfd, addr.as_ptr(), addr.len()),
    );

    mc.get_payload(0, addr.as_ptr(), addr.len());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_getsockname(r, sockfd, addr));
    r
}

pub fn proxy_getpeername(sockfd: u32, addr: &mut Vec<u8>) -> SyscallRet {
    addr.clear();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_getpeername(sockfd, addr));

    let mc = MC::alloc();
    mc.proxy(
        current_process().pid(),
        syscall::SYSCALL_GETPEERNAME,
        expand_args!(sockfd, addr.as_ptr(), addr.len()),
    );
    mc.get_payload(0, addr.as_ptr(), addr.len());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_getpeername(r, sockfd, addr));
    r
}

// FIXME
pub fn proxy_sys_sendto(sockfd: u32, buf: &[u8], flags: u32, addr: &[u8]) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_sendto(sockfd, buf.len()));
    let mc = MC::alloc();
    mc.set_payload(0, buf.as_ptr(), buf.len());
    mc.set_payload(1, addr.as_ptr(), addr.len());

    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_SENDTO,
            expand_args!(sockfd, buf.len(), flags, addr.len()),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_sendto(r, sockfd, buf.len()));
    r
}

pub fn proxy_sys_recvfrom(
    sockfd: u32,
    buf: &mut [u8],
    flags: u32,
    addr: &mut Vec<u8>,
) -> SyscallRet {
    addr.clear();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_recvfrom(sockfd, buf.len()));
    let mc = MC::alloc();
    mc.set_payload(1, addr.as_ptr(), addr.len());
    mc.proxy(
        current_process().pid(),
        syscall::SYSCALL_RECVFROM,
        expand_args!(
            sockfd,
            buf.as_ptr(),
            buf.len(),
            flags,
            addr.as_ptr(),
            addr.len()
        ),
    );
    mc.get_payload(0, buf.as_ptr(), buf.len());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_recvfrom(r, sockfd, buf.len()));
    r
}

// todo: not provided by the kernel
pub fn proxy_sys_getsockopt(
    sockfd: u32,
    level: u32,
    optname: u32,
    optval: &mut Vec<u8>,
) -> SyscallRet {
    optval.clear();
    let mc = MC::alloc();
    mc.proxy(
        current_process().pid(),
        syscall::SYSCALL_GETSOCKOPT,
        expand_args!(sockfd, level, optname, optval.as_ptr(), optval.len()),
    );
    mc.get_payload(0, optval.as_ptr(), optval.len());
    let r = mc.free();
    r
}

pub fn proxy_sys_setsockopt(sockfd: u32, level: u32, optname: u32, optval: &[u8]) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_setsockopt(sockfd));
    let mc = MC::alloc();
    mc.set_payload(0, optval.as_ptr(), optval.len());
    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_SETSOCKOPT,
            expand_args!(sockfd, level, optname, optval.len()),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_setsockopt(r, sockfd));
    r
}

pub fn proxy_sys_shutdown(sockfd: u32, how: u32) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().pre_verify_shutdown(sockfd, how));
    let mc = MC::alloc();
    let r = mc
        .proxy(
            current_process().pid(),
            syscall::SYSCALL_SHUTDOWN,
            expand_args!(sockfd, how),
        )
        .free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE.lock().post_verify_shutdown(r, sockfd, how));
    r
}

pub fn proxy_sys_socketpair(
    domain: u32,
    socket_type: u32,
    protocol: u32,
    sv: &mut [usize],
) -> SyscallRet {
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .pre_verify_socketpair(domain, socket_type, protocol, sv));
    let mc = MC::alloc();
    mc.proxy(
        current_process().pid(),
        syscall::SYSCALL_SOCKETPAIR,
        expand_args!(domain, socket_type, protocol, sv.as_ptr() as usize),
    );
    mc.get_payload(0, sv.as_ptr(), 2 * core::mem::size_of::<usize>());
    let r = mc.free();
    #[cfg(feature = "verify_syscall")]
    assert!(STATE_MACHINE
        .lock()
        .post_verify_socketpair(r, domain, socket_type, sv));
    r
}
