// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use aster_frame::bus::pci::PCI_BUS;
use spin::Once;

use self::driver::IvSharedMemoryDriver;

pub mod device;
pub mod driver;

pub static IVSHMEM_PCI_DRIVER: Once<Arc<IvSharedMemoryDriver>> = Once::new();
pub fn init() {
    IVSHMEM_PCI_DRIVER.call_once(|| Arc::new(IvSharedMemoryDriver::new()));
    PCI_BUS
        .lock()
        .register_driver(IVSHMEM_PCI_DRIVER.get().unwrap().clone());
}
