// SPDX-License-Identifier: MPL-2.0

//! The ivshmem of Asterinas.
#![no_std]
#![forbid(unsafe_code)]
#![feature(strict_provenance)]

pub mod pci;

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{any::Any, fmt::Debug};

use aster_frame::sync::SpinLock;
use component::{init_component, ComponentInitError};
use spin::Once;

static COMPONENT: Once<Component> = Once::new();

#[init_component]
fn component_init() -> Result<(), ComponentInitError> {
    let a = Component::init()?;
    COMPONENT.call_once(|| a);
    pci::init();
    Ok(())
}

#[derive(Debug)]
struct Component {
    device_table: SpinLock<BTreeMap<String, Arc<dyn IvSharedMemoryDevice>>>,
}

impl Component {
    pub fn init() -> Result<Self, ComponentInitError> {
        Ok(Self {
            device_table: SpinLock::new(BTreeMap::new()),
        })
    }
}

pub trait IvSharedMemoryDevice: Send + Sync + Any + Debug {
    fn read_bytes(&self, offset: usize, data: &mut [u8]) -> Result<(), aster_frame::Error>;

    fn write_bytes(&self, offset: usize, data: &[u8]) -> Result<(), aster_frame::Error>;

    fn size(&self) -> usize;
}

pub fn register_device(name: String, device: Arc<dyn IvSharedMemoryDevice>) {
    COMPONENT
        .get()
        .unwrap()
        .device_table
        .lock()
        .insert(name, device);
}

pub fn get_device(str: &str) -> Option<Arc<dyn IvSharedMemoryDevice>> {
    COMPONENT
        .get()
        .unwrap()
        .device_table
        .lock()
        .get(str)
        .cloned()
}

pub fn all_devices() -> Vec<(String, Arc<dyn IvSharedMemoryDevice>)> {
    let devs = COMPONENT.get().unwrap().device_table.lock();
    devs.iter()
        .map(|(name, device)| (name.clone(), device.clone()))
        .collect()
}
