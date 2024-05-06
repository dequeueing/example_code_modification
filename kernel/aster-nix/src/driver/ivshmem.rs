// SPDX-License-Identifier: MPL-2.0

use log::info;

pub fn init() {
    for (name, dev) in aster_ivshmem::all_devices() {
        info!(
            "Find internal shared memory device, name:{}, memory size:{:x?}",
            name,
            dev.size()
        );
    }
}
