// SPDX-License-Identifier: MPL-2.0

pub mod ivshmem;

use log::info;

pub fn init() {
    // print all the input device to make sure input crate will compile
    for (name, _) in aster_input::all_devices() {
        info!("Found Input device, name:{}", name);
    }
    ivshmem::init()
}
