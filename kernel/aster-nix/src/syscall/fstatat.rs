use core::time::Duration;

use aster_time::SystemTime;

#[derive(Debug)]
#[repr(C)]
pub struct STAT {
    pub st_dev: u64,
    pub st_ino: u32,
    pub __pad1: u32,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: u64,
    pub st_blksize: u32,
    pub __pad2: u32,
    pub st_blocks: u64,
    pub st_atim: TimeSpec,
    pub st_mtim: TimeSpec,
    pub st_ctim: TimeSpec,
}

impl STAT {
    pub fn new() -> Self {
        // stack_trace!();
        STAT {
            st_dev: 0,
            __pad1: 0,
            st_ino: 0,
            st_mode: 0,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 4096, // TODO: get from fs?
            __pad2: 0,
            st_blocks: 0,
            st_atim: TimeSpec::new(),
            st_mtim: TimeSpec::new(),
            st_ctim: TimeSpec::new(),
        }
    }
}

/// Used for nanosleep
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TimeSpec {
    pub sec: usize,
    pub nsec: usize,
}

impl TimeSpec {
    pub fn new() -> Self {
        // stack_trace!();
        // new a time spec with machine time
        // let current_time = current_time_ms();
        let current_time = SystemTime::now();
        Self {
            sec: current_time.duration_since(&SystemTime::UNIX_EPOCH)?.as_secs(),
            nsec: current_time % 1000 * 1000000,
        }
    }
}

impl From<TimeSpec> for Duration {
    fn from(time_spec: TimeSpec) -> Self {
        Duration::new(time_spec.sec as u64, time_spec.nsec as u32)
    }
}

impl From<Duration> for TimeSpec {
    fn from(duration: Duration) -> Self {
        Self {
            sec: duration.as_secs() as usize,
            nsec: duration.subsec_nanos() as usize,
        }
    }
}