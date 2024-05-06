use core::{
    fmt,
    fmt::Formatter,
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Atomic non-null pointer (Anp), since rust does not provide one
#[repr(C)]
pub union Anp<T> {
    pub ptr: Option<NonNull<T>>,
    pub raw: usize,
    atomic: ManuallyDrop<AtomicUsize>,
}

impl<T> Anp<T> {
    pub(crate) const fn null() -> Self {
        Self { raw: 0 }
    }

    pub(crate) fn to(target: *mut T) -> Self {
        Self {
            ptr: NonNull::new(target),
        }
    }

    pub(crate) fn addr(address: usize) -> Self {
        Self { raw: address }
    }
    #[inline]
    pub unsafe fn as_ref<'a>(&self) -> &'a T {
        self.ptr.unwrap().as_ref()
    }
    #[inline]
    pub unsafe fn as_mut<'a>(&mut self) -> &'a mut T {
        self.ptr.unwrap().as_mut()
    }
    #[inline]
    pub unsafe fn as_ptr(&self) -> *mut T {
        self.ptr.unwrap().as_ptr()
    }
    #[inline]
    pub unsafe fn compare_exchange(&self, curr: usize, new: usize) -> Result<usize, usize> {
        self.atomic
            .compare_exchange(curr, new, Ordering::Relaxed, Ordering::SeqCst)
    }
    #[inline]
    pub unsafe fn load(&self) -> usize {
        self.atomic.load(Ordering::Relaxed)
    }
}

impl<T> PartialEq for Anp<T> {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.raw == other.raw }
    }
    fn ne(&self, other: &Self) -> bool {
        unsafe { self.raw != other.raw }
    }
}

impl<T> Clone for Anp<T> {
    fn clone(&self) -> Self {
        Self {
            raw: unsafe { self.load() },
        }
    }
}

impl<T> fmt::Debug for Anp<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "AnnPtr({})", self.raw) }
    }
}

impl<T> fmt::Display for Anp<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        unsafe {
            if self.ptr.is_none() {
                write!(f, "AnnPtr[0x{:012x}]", 0)
            } else {
                write!(f, "AnnPtr[0x{:x}]", self.raw)
            }
        }
    }
}
