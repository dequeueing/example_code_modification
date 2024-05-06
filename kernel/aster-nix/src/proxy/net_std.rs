use alloc::vec::Vec;
use core::{cmp::Ordering, mem::transmute, ops::Not};
pub enum SocketAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketAddrV4 {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl SocketAddrV4 {
    pub fn new(ip: Ipv4Addr, port: u16) -> SocketAddrV4 {
        SocketAddrV4 { ip, port }
    }
}
// from "127.0.0.1:8080" to socketaddrv4
pub fn parse_ipv4_address(ip_str: &[u8]) -> Option<SocketAddrV4> {
    // 分割字符串，获取 IP 地址和端口部分
    let ip_str = core::str::from_utf8(ip_str).ok()?;
    let parts: Vec<&str> = ip_str.split(':').collect();
    if parts.len() != 2 {
        return None; // 格式不正确
    }

    // 解析 IP 地址部分
    let ip_parts: Vec<&str> = parts[0].split('.').collect();
    if ip_parts.len() != 4 {
        return None; // IP 地址格式不正确
    }

    // 将字符串解析为 u8 数组
    let mut ip_bytes: [u8; 4] = [0; 4];
    for (i, part) in ip_parts.iter().enumerate() {
        if let Ok(num) = part.parse::<u8>() {
            ip_bytes[i] = num;
        } else {
            return None; // 无效的数字
        }
    }
    // 解析 port
    let port: u16 = parts[1].parse::<u16>().ok()?;
    let socketv4 = SocketAddrV4 {
        ip: Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]),
        port: port,
    };
    Some(socketv4)
}

pub struct SocketAddrV6 {
    ip: Ipv6Addr,
    port: u16,
    flowinfo: u32,
    scope_id: u32,
}

impl SocketAddrV6 {
    pub fn new(ip: Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> SocketAddrV6 {
        SocketAddrV6 {
            ip,
            port,
            flowinfo,
            scope_id,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum IpAddr {
    /// An IPv4 address.
    V4(Ipv4Addr),
    /// An IPv6 address.
    V6(Ipv6Addr),
}

/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Addr {
    octets: [u8; 4],
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Addr {
    octets: [u8; 16],
}

#[derive(Copy, PartialEq, Eq, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum Ipv6MulticastScope {
    /// Interface-Local scope.
    InterfaceLocal,
    /// Link-Local scope.
    LinkLocal,
    /// Realm-Local scope.
    RealmLocal,
    /// Admin-Local scope.
    AdminLocal,
    /// Site-Local scope.
    SiteLocal,
    /// Organization-Local scope.
    OrganizationLocal,
    /// Global scope.
    Global,
}

impl IpAddr {
    #[must_use]
    #[inline]
    pub const fn is_unspecified(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_global(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_global(),
            IpAddr::V6(ip) => ip.is_global(),
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_multicast(),
            IpAddr::V6(ip) => ip.is_multicast(),
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_documentation(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_documentation(),
            IpAddr::V6(ip) => ip.is_documentation(),
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_benchmarking(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_benchmarking(),
            IpAddr::V6(ip) => ip.is_benchmarking(),
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    #[must_use]
    #[inline]
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, IpAddr::V6(_))
    }
    #[inline]
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]

    pub const fn to_canonical(&self) -> IpAddr {
        match self {
            IpAddr::V4(_) => *self,
            IpAddr::V6(v6) => v6.to_canonical(),
        }
    }
}

impl Ipv4Addr {
    #[must_use]
    #[inline]
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr {
            octets: [a, b, c, d],
        }
    }

    pub const BITS: u32 = 32;

    #[must_use]
    #[inline]
    pub const fn to_bits(self) -> u32 {
        u32::from_be_bytes(self.octets)
    }
    #[must_use]
    #[inline]
    pub const fn from_bits(bits: u32) -> Ipv4Addr {
        Ipv4Addr {
            octets: bits.to_be_bytes(),
        }
    }

    pub const LOCALHOST: Self = Ipv4Addr::new(127, 0, 0, 1);
    pub const UNSPECIFIED: Self = Ipv4Addr::new(0, 0, 0, 0);

    pub const BROADCAST: Self = Ipv4Addr::new(255, 255, 255, 255);

    #[must_use]
    #[inline]
    pub const fn octets(&self) -> [u8; 4] {
        self.octets
    }
    #[must_use]
    #[inline]
    pub const fn is_unspecified(&self) -> bool {
        u32::from_be_bytes(self.octets) == 0
    }
    #[must_use]
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        self.octets()[0] == 127
    }

    #[must_use]
    #[inline]
    pub const fn is_private(&self) -> bool {
        match self.octets() {
            [10, ..] => true,
            [172, b, ..] if b >= 16 && b <= 31 => true,
            [192, 168, ..] => true,
            _ => false,
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_link_local(&self) -> bool {
        matches!(self.octets(), [169, 254, ..])
    }

    #[must_use]
    #[inline]
    pub const fn is_global(&self) -> bool {
        !(self.octets()[0] == 0 // "This network"
            || self.is_private()
            || self.is_shared()
            || self.is_loopback()
            || self.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            ||(self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0)
            || self.is_documentation()
            || self.is_benchmarking()
            || self.is_reserved()
            || self.is_broadcast())
    }

    #[must_use]
    #[inline]
    pub const fn is_shared(&self) -> bool {
        self.octets()[0] == 100 && (self.octets()[1] & 0b1100_0000 == 0b0100_0000)
    }

    #[must_use]
    #[inline]
    pub const fn is_benchmarking(&self) -> bool {
        self.octets()[0] == 198 && (self.octets()[1] & 0xfe) == 18
    }

    #[must_use]
    #[inline]
    pub const fn is_reserved(&self) -> bool {
        self.octets()[0] & 240 == 240 && !self.is_broadcast()
    }

    #[must_use]
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        self.octets()[0] >= 224 && self.octets()[0] <= 239
    }

    #[must_use]
    #[inline]
    pub const fn is_broadcast(&self) -> bool {
        u32::from_be_bytes(self.octets()) == u32::from_be_bytes(Self::BROADCAST.octets())
    }

    #[must_use]
    #[inline]
    pub const fn is_documentation(&self) -> bool {
        matches!(
            self.octets(),
            [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
        )
    }

    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub const fn to_ipv6_compatible(&self) -> Ipv6Addr {
        let [a, b, c, d] = self.octets();
        Ipv6Addr {
            octets: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d],
        }
    }

    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub const fn to_ipv6_mapped(&self) -> Ipv6Addr {
        let [a, b, c, d] = self.octets();
        Ipv6Addr {
            octets: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d],
        }
    }
}

impl From<Ipv4Addr> for IpAddr {
    #[inline]
    fn from(ipv4: Ipv4Addr) -> IpAddr {
        IpAddr::V4(ipv4)
    }
}

impl From<Ipv6Addr> for IpAddr {
    #[inline]
    fn from(ipv6: Ipv6Addr) -> IpAddr {
        IpAddr::V6(ipv6)
    }
}

impl PartialEq<Ipv4Addr> for IpAddr {
    #[inline]
    fn eq(&self, other: &Ipv4Addr) -> bool {
        match self {
            IpAddr::V4(v4) => v4 == other,
            IpAddr::V6(_) => false,
        }
    }
}

impl PartialEq<IpAddr> for Ipv4Addr {
    #[inline]
    fn eq(&self, other: &IpAddr) -> bool {
        match other {
            IpAddr::V4(v4) => self == v4,
            IpAddr::V6(_) => false,
        }
    }
}

impl PartialOrd for Ipv4Addr {
    #[inline]
    fn partial_cmp(&self, other: &Ipv4Addr) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Ipv4Addr> for IpAddr {
    #[inline]
    fn partial_cmp(&self, other: &Ipv4Addr) -> Option<Ordering> {
        match self {
            IpAddr::V4(v4) => v4.partial_cmp(other),
            IpAddr::V6(_) => Some(Ordering::Greater),
        }
    }
}

impl PartialOrd<IpAddr> for Ipv4Addr {
    #[inline]
    fn partial_cmp(&self, other: &IpAddr) -> Option<Ordering> {
        match other {
            IpAddr::V4(v4) => self.partial_cmp(v4),
            IpAddr::V6(_) => Some(Ordering::Less),
        }
    }
}

impl Ord for Ipv4Addr {
    #[inline]
    fn cmp(&self, other: &Ipv4Addr) -> Ordering {
        self.octets.cmp(&other.octets)
    }
}

impl From<Ipv4Addr> for u32 {
    /// Uses [`Ipv4Addr::to_bits`] to convert an IPv4 address to a host byte order `u32`.
    #[inline]
    fn from(ip: Ipv4Addr) -> u32 {
        ip.to_bits()
    }
}

impl From<u32> for Ipv4Addr {
    /// Uses [`Ipv4Addr::from_bits`] to convert a host byte order `u32` into an IPv4 address.
    #[inline]
    fn from(ip: u32) -> Ipv4Addr {
        Ipv4Addr::from_bits(ip)
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    #[inline]
    fn from(octets: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr { octets }
    }
}

impl From<[u8; 4]> for IpAddr {
    #[inline]
    fn from(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }
}

impl Ipv6Addr {
    #[must_use]
    #[inline]
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Ipv6Addr {
        let addr16 = [
            a.to_be(),
            b.to_be(),
            c.to_be(),
            d.to_be(),
            e.to_be(),
            f.to_be(),
            g.to_be(),
            h.to_be(),
        ];
        Ipv6Addr {
            // All elements in `addr16` are big endian.
            // SAFETY: `[u16; 8]` is always safe to transmute to `[u8; 16]`.
            octets: unsafe { transmute::<_, [u8; 16]>(addr16) },
        }
    }

    pub const BITS: u32 = 128;

    #[must_use]
    #[inline]
    pub const fn to_bits(self) -> u128 {
        u128::from_be_bytes(self.octets)
    }

    #[must_use]
    #[inline]
    pub const fn from_bits(bits: u128) -> Ipv6Addr {
        Ipv6Addr {
            octets: bits.to_be_bytes(),
        }
    }

    pub const LOCALHOST: Self = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    pub const UNSPECIFIED: Self = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);

    #[must_use]
    #[inline]
    pub const fn segments(&self) -> [u16; 8] {
        // All elements in `self.octets` must be big endian.
        // SAFETY: `[u8; 16]` is always safe to transmute to `[u16; 8]`.
        let [a, b, c, d, e, f, g, h] = unsafe { transmute::<_, [u16; 8]>(self.octets) };
        // We want native endian u16
        [
            u16::from_be(a),
            u16::from_be(b),
            u16::from_be(c),
            u16::from_be(d),
            u16::from_be(e),
            u16::from_be(f),
            u16::from_be(g),
            u16::from_be(h),
        ]
    }

    #[must_use]
    #[inline]
    pub const fn is_unspecified(&self) -> bool {
        u128::from_be_bytes(self.octets()) == u128::from_be_bytes(Ipv6Addr::UNSPECIFIED.octets())
    }

    #[must_use]
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        u128::from_be_bytes(self.octets()) == u128::from_be_bytes(Ipv6Addr::LOCALHOST.octets())
    }

    #[must_use]
    #[inline]
    pub const fn is_global(&self) -> bool {
        !(self.is_unspecified()
            || self.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
                ))
            || self.is_documentation()
            || self.is_unique_local()
            || self.is_unicast_link_local())
    }

    #[must_use]
    #[inline]
    pub const fn is_unique_local(&self) -> bool {
        (self.segments()[0] & 0xfe00) == 0xfc00
    }

    #[must_use]
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    #[must_use]
    #[inline]
    pub const fn is_unicast_link_local(&self) -> bool {
        (self.segments()[0] & 0xffc0) == 0xfe80
    }

    #[must_use]
    #[inline]
    pub const fn is_documentation(&self) -> bool {
        (self.segments()[0] == 0x2001) && (self.segments()[1] == 0xdb8)
    }

    #[must_use]
    #[inline]
    pub const fn is_benchmarking(&self) -> bool {
        (self.segments()[0] == 0x2001) && (self.segments()[1] == 0x2) && (self.segments()[2] == 0)
    }

    #[must_use]
    #[inline]
    pub const fn is_unicast_global(&self) -> bool {
        self.is_unicast()
            && !self.is_loopback()
            && !self.is_unicast_link_local()
            && !self.is_unique_local()
            && !self.is_unspecified()
            && !self.is_documentation()
            && !self.is_benchmarking()
    }

    #[must_use]
    #[inline]
    pub const fn multicast_scope(&self) -> Option<Ipv6MulticastScope> {
        if self.is_multicast() {
            match self.segments()[0] & 0x000f {
                1 => Some(Ipv6MulticastScope::InterfaceLocal),
                2 => Some(Ipv6MulticastScope::LinkLocal),
                3 => Some(Ipv6MulticastScope::RealmLocal),
                4 => Some(Ipv6MulticastScope::AdminLocal),
                5 => Some(Ipv6MulticastScope::SiteLocal),
                8 => Some(Ipv6MulticastScope::OrganizationLocal),
                14 => Some(Ipv6MulticastScope::Global),
                _ => None,
            }
        } else {
            None
        }
    }

    #[must_use]
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        (self.segments()[0] & 0xff00) == 0xff00
    }

    #[inline]
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]

    pub const fn to_ipv4_mapped(&self) -> Option<Ipv4Addr> {
        match self.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                Some(Ipv4Addr::new(a, b, c, d))
            }
            _ => None,
        }
    }

    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub const fn to_ipv4(&self) -> Option<Ipv4Addr> {
        if let [0, 0, 0, 0, 0, 0 | 0xffff, ab, cd] = self.segments() {
            let [a, b] = ab.to_be_bytes();
            let [c, d] = cd.to_be_bytes();
            Some(Ipv4Addr::new(a, b, c, d))
        } else {
            None
        }
    }
    #[inline]
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    pub const fn to_canonical(&self) -> IpAddr {
        if let Some(mapped) = self.to_ipv4_mapped() {
            return IpAddr::V4(mapped);
        }
        IpAddr::V6(*self)
    }

    #[must_use]
    #[inline]
    pub const fn octets(&self) -> [u8; 16] {
        self.octets
    }
}

impl PartialEq<IpAddr> for Ipv6Addr {
    #[inline]
    fn eq(&self, other: &IpAddr) -> bool {
        match other {
            IpAddr::V4(_) => false,
            IpAddr::V6(v6) => self == v6,
        }
    }
}

impl PartialEq<Ipv6Addr> for IpAddr {
    #[inline]
    fn eq(&self, other: &Ipv6Addr) -> bool {
        match self {
            IpAddr::V4(_) => false,
            IpAddr::V6(v6) => v6 == other,
        }
    }
}

impl PartialOrd for Ipv6Addr {
    #[inline]
    fn partial_cmp(&self, other: &Ipv6Addr) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<Ipv6Addr> for IpAddr {
    #[inline]
    fn partial_cmp(&self, other: &Ipv6Addr) -> Option<Ordering> {
        match self {
            IpAddr::V4(_) => Some(Ordering::Less),
            IpAddr::V6(v6) => v6.partial_cmp(other),
        }
    }
}

impl PartialOrd<IpAddr> for Ipv6Addr {
    #[inline]
    fn partial_cmp(&self, other: &IpAddr) -> Option<Ordering> {
        match other {
            IpAddr::V4(_) => Some(Ordering::Greater),
            IpAddr::V6(v6) => self.partial_cmp(v6),
        }
    }
}

impl Ord for Ipv6Addr {
    #[inline]
    fn cmp(&self, other: &Ipv6Addr) -> Ordering {
        self.segments().cmp(&other.segments())
    }
}

impl From<Ipv6Addr> for u128 {
    /// Uses [`Ipv6Addr::to_bits`] to convert an IPv6 address to a host byte order `u128`.
    #[inline]
    fn from(ip: Ipv6Addr) -> u128 {
        ip.to_bits()
    }
}

impl From<u128> for Ipv6Addr {
    /// Uses [`Ipv6Addr::from_bits`] to convert a host byte order `u128` to an IPv6 address.
    #[inline]
    fn from(ip: u128) -> Ipv6Addr {
        Ipv6Addr::from_bits(ip)
    }
}

impl From<[u8; 16]> for Ipv6Addr {
    #[inline]
    fn from(octets: [u8; 16]) -> Ipv6Addr {
        Ipv6Addr { octets }
    }
}

impl From<[u16; 8]> for Ipv6Addr {
    #[inline]
    fn from(segments: [u16; 8]) -> Ipv6Addr {
        let [a, b, c, d, e, f, g, h] = segments;
        Ipv6Addr::new(a, b, c, d, e, f, g, h)
    }
}

impl From<[u8; 16]> for IpAddr {
    #[inline]
    fn from(octets: [u8; 16]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(octets))
    }
}

impl From<[u16; 8]> for IpAddr {
    #[inline]
    fn from(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }
}

impl Not for Ipv4Addr {
    type Output = Ipv4Addr;

    #[inline]
    fn not(mut self) -> Ipv4Addr {
        for octet in &mut self.octets {
            *octet = !*octet;
        }
        self
    }
}

impl Not for &'_ Ipv4Addr {
    type Output = Ipv4Addr;

    #[inline]
    fn not(self) -> Ipv4Addr {
        !*self
    }
}

impl Not for Ipv6Addr {
    type Output = Ipv6Addr;

    #[inline]
    fn not(mut self) -> Ipv6Addr {
        for octet in &mut self.octets {
            *octet = !*octet;
        }
        self
    }
}

impl Not for &'_ Ipv6Addr {
    type Output = Ipv6Addr;

    #[inline]
    fn not(self) -> Ipv6Addr {
        !*self
    }
}
