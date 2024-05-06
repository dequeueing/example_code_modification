use super::net_std::{Ipv4Addr, SocketAddr, SocketAddrV4};
extern crate bitflags;
use bitflags::bitflags;
pub struct SocketInfo {
    domain: u32,
    socket_type: SocketType,
    socket_pair: Option<usize>,
    addr: Option<SocketAddr>,
    is_passive: bool,
    backlog: usize,
    how: u32,
    syscall_state: Socketstate,
}

pub const AF_INET: u32 = 2;
pub const _AF_INET6: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socketstate {
    NULL,
    INIT,
    BIND,
    LISTEN,
    CONNECT,
    SHUTDOWN,
}

/// shutdown
#[allow(unused)]
pub const SHUT_RD: u32 = 0;
#[allow(unused)]
pub const SHUT_WR: u32 = 1;
#[allow(unused)]
pub const SHUT_RDWR: u32 = 2;

bitflags! {
    /// socket type
    pub struct SocketType: u32 {
        /// for TCP
        const SOCK_STREAM = 1 << 0;
        /// for UDP
        const SOCK_DGRAM = 1 << 1;
    }
}

impl SocketInfo {
    pub fn new(domain: u32, socket_type: SocketType) -> Self {
        SocketInfo {
            domain: domain,
            socket_type: socket_type,
            socket_pair: None,
            addr: None,
            is_passive: false,
            backlog: 0,
            how: 0,
            syscall_state: Socketstate::NULL,
        }
    }
    pub fn set_domain(&mut self, domain: u32) {
        self.domain = domain;
    }
    pub fn set_socket_type(&mut self, socket_type: SocketType) {
        self.socket_type = socket_type;
    }
    pub fn set_socket_pair(&mut self, socket_pair: usize) {
        self.socket_pair = Some(socket_pair);
    }
    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = Some(addr);
    }
    // pub fn set_addr_len(&mut self, addr_len: usize) {
    //     self.addr_len = addr_len;
    // }
    pub fn set_is_passive(&mut self, is_passive: bool) {
        self.is_passive = is_passive;
    }
    pub fn set_backlog(&mut self, backlog: usize) {
        self.backlog = backlog;
    }
    pub fn set_how(&mut self, how: u32) {
        self.how = how;
    }
    pub fn set_syscall_state(&mut self, syscall_state: Socketstate) {
        self.syscall_state = syscall_state;
    }
    pub fn get_domain(&self) -> u32 {
        self.domain
    }
    pub fn get_socket_type(&self) -> SocketType {
        self.socket_type
    }
    pub fn get_socket_pair(&self) -> Option<usize> {
        self.socket_pair
    }
    pub fn get_addr(&self) -> Option<SocketAddr> {
        match &self.addr {
            Some(addr) => match addr {
                SocketAddr::V4(addr) => {
                    let ip = addr.ip;
                    let port = addr.port;
                    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
                }
                SocketAddr::V6(_) => todo!(),
            },
            None => None,
        }
    }
    // pub fn get_addr_len(&self) -> usize {
    //     self.addr_len
    // }
    pub fn get_is_passive(&self) -> bool {
        self.is_passive
    }
    pub fn get_backlog(&self) -> usize {
        self.backlog
    }
    pub fn get_how(&self) -> u32 {
        self.how
    }
    pub fn get_syscall_state(&self) -> Socketstate {
        self.syscall_state
    }
}
