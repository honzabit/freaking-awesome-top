//! Minimal CoreFoundation FFI: an owning handle and typed readers for the property lists IOKit
//! returns (dictionaries of strings, numbers, booleans, data and arrays).
//!
//! Every reader checks the CFTypeID before touching an object, so a property of an unexpected
//! type reads as None instead of crashing. Readers take borrowed `CFTypeRef`s ("Get" rule);
//! [`Cf`] owns objects obtained by a Create/Copy call and releases them on drop.
#![allow(non_upper_case_globals)]

use std::ffi::{c_char, c_void};

pub type CFTypeRef = *const c_void;
type CFIndex = isize;
type CFTypeID = usize;

const kCFStringEncodingUTF8: u32 = 0x0800_0100;
const kCFNumberSInt64Type: CFIndex = 4;
const kCFNumberFloat64Type: CFIndex = 6;

#[cfg(test)]
#[repr(C)]
pub struct CFDictionaryKeyCallBacks {
    _version: CFIndex,
    _retain: *const c_void,
    _release: *const c_void,
    _copy_description: *const c_void,
    _equal: *const c_void,
    _hash: *const c_void,
}

#[cfg(test)]
#[repr(C)]
pub struct CFDictionaryValueCallBacks {
    _version: CFIndex,
    _retain: *const c_void,
    _release: *const c_void,
    _copy_description: *const c_void,
    _equal: *const c_void,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFNumberGetTypeID() -> CFTypeID;
    fn CFBooleanGetTypeID() -> CFTypeID;
    fn CFDictionaryGetTypeID() -> CFTypeID;
    fn CFArrayGetTypeID() -> CFTypeID;
    fn CFDataGetTypeID() -> CFTypeID;
    fn CFStringCreateWithBytes(alloc: CFTypeRef, bytes: *const u8, len: CFIndex, enc: u32, external: u8) -> CFTypeRef;
    fn CFStringGetLength(s: CFTypeRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(len: CFIndex, enc: u32) -> CFIndex;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: CFIndex, enc: u32) -> u8;
    fn CFNumberGetValue(n: CFTypeRef, ty: CFIndex, out: *mut c_void) -> u8;
    fn CFBooleanGetValue(b: CFTypeRef) -> u8;
    fn CFDictionaryGetValue(d: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFArrayGetCount(a: CFTypeRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(a: CFTypeRef, i: CFIndex) -> CFTypeRef;
    fn CFDataGetLength(d: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(d: CFTypeRef) -> *const u8;
}

// Constructors used only to build fixtures in tests.
#[cfg(test)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
    static kCFTypeArrayCallBacks: c_void;
    fn CFNumberCreate(alloc: CFTypeRef, ty: CFIndex, val: *const c_void) -> CFTypeRef;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        n: CFIndex,
        kcb: *const CFDictionaryKeyCallBacks,
        vcb: *const CFDictionaryValueCallBacks,
    ) -> CFTypeRef;
    fn CFArrayCreate(alloc: CFTypeRef, values: *const CFTypeRef, n: CFIndex, cb: *const c_void) -> CFTypeRef;
}

/// An owned CF object (from a Create/Copy function), released on drop.
pub struct Cf(CFTypeRef);

impl Cf {
    /// Take ownership of `p`; None when it is NULL.
    ///
    /// # Safety
    /// `p` must be NULL or a CF object the caller owns (+1 retain count).
    pub unsafe fn owned(p: CFTypeRef) -> Option<Cf> {
        // Not `then_some(Cf(p))`: that builds (and drops, i.e. CFReleases) the handle eagerly.
        if p.is_null() { None } else { Some(Cf(p)) }
    }

    pub fn as_ptr(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: we own one reference (see `owned`).
        unsafe { CFRelease(self.0) }
    }
}

/// A new CFString with the contents of `s`.
pub fn string(s: &str) -> Option<Cf> {
    // SAFETY: bytes/len describe a valid UTF-8 buffer; the result is owned (Create rule).
    unsafe {
        Cf::owned(CFStringCreateWithBytes(std::ptr::null(), s.as_ptr(), s.len() as CFIndex, kCFStringEncodingUTF8, 0))
    }
}

/// # Safety
/// `v` must be NULL or a valid CF object (borrowed is fine).
unsafe fn is(v: CFTypeRef, ty: CFTypeID) -> bool {
    // SAFETY: caller guarantees v is a CF object when non-NULL.
    !v.is_null() && unsafe { CFGetTypeID(v) } == ty
}

/// # Safety
/// `v` must be NULL or a valid CF object.
pub unsafe fn to_string(v: CFTypeRef) -> Option<String> {
    // SAFETY: type checked first; the buffer is sized by CFStringGetMaximumSizeForEncoding + NUL.
    unsafe {
        if !is(v, CFStringGetTypeID()) {
            return None;
        }
        let cap = CFStringGetMaximumSizeForEncoding(CFStringGetLength(v), kCFStringEncodingUTF8) + 1;
        let mut buf = vec![0u8; cap.max(1) as usize];
        if CFStringGetCString(v, buf.as_mut_ptr() as *mut c_char, cap, kCFStringEncodingUTF8) == 0 {
            return None;
        }
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        buf.truncate(n);
        String::from_utf8(buf).ok()
    }
}

/// A CFNumber as i64 (floats are truncated by CF), or a CFBoolean as 0/1.
///
/// # Safety
/// `v` must be NULL or a valid CF object.
pub unsafe fn to_i64(v: CFTypeRef) -> Option<i64> {
    // SAFETY: type checked before each typed accessor; `n` is a valid i64 out-param.
    unsafe {
        if is(v, CFNumberGetTypeID()) {
            let mut n: i64 = 0;
            // CFNumberGetValue returns false when the conversion is lossy but still stores a value.
            CFNumberGetValue(v, kCFNumberSInt64Type, &mut n as *mut i64 as *mut c_void);
            return Some(n);
        }
        if is(v, CFBooleanGetTypeID()) {
            return Some(CFBooleanGetValue(v) as i64);
        }
        None
    }
}

/// # Safety
/// `v` must be NULL or a valid CF object.
#[allow(dead_code)]
pub unsafe fn to_f64(v: CFTypeRef) -> Option<f64> {
    // SAFETY: type checked; `n` is a valid f64 out-param.
    unsafe {
        if !is(v, CFNumberGetTypeID()) {
            return None;
        }
        let mut n: f64 = 0.0;
        CFNumberGetValue(v, kCFNumberFloat64Type, &mut n as *mut f64 as *mut c_void);
        Some(n)
    }
}

/// A CFString, or CFData holding a (NUL-terminated) UTF-8 string, as found in IORegistry
/// properties such as a GPU's "model".
///
/// # Safety
/// `v` must be NULL or a valid CF object.
pub unsafe fn to_text(v: CFTypeRef) -> Option<String> {
    // SAFETY: type checked; CFData's byte pointer is valid for CFDataGetLength bytes.
    unsafe {
        if let Some(s) = to_string(v) {
            return Some(s);
        }
        if !is(v, CFDataGetTypeID()) {
            return None;
        }
        let len = CFDataGetLength(v).max(0) as usize;
        let p = CFDataGetBytePtr(v);
        if p.is_null() {
            return None;
        }
        let b = std::slice::from_raw_parts(p, len);
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        std::str::from_utf8(&b[..end]).ok().map(str::to_string)
    }
}

/// `d[key]`, borrowed (valid while `d` is). NULL when `d` is not a dictionary or lacks `key`.
///
/// # Safety
/// `d` must be NULL or a valid CF object.
pub unsafe fn dict_get(d: CFTypeRef, key: &str) -> CFTypeRef {
    // SAFETY: d is type-checked as a dictionary; the key string lives across the lookup.
    unsafe {
        if !is(d, CFDictionaryGetTypeID()) {
            return std::ptr::null();
        }
        let Some(k) = string(key) else { return std::ptr::null() };
        CFDictionaryGetValue(d, k.as_ptr())
    }
}

/// # Safety
/// `d` must be NULL or a valid CF object.
pub unsafe fn dict_i64(d: CFTypeRef, key: &str) -> Option<i64> {
    // SAFETY: forwarded contract.
    unsafe { to_i64(dict_get(d, key)) }
}

/// # Safety
/// `d` must be NULL or a valid CF object.
pub unsafe fn dict_string(d: CFTypeRef, key: &str) -> Option<String> {
    // SAFETY: forwarded contract.
    unsafe { to_string(dict_get(d, key)) }
}

/// Borrowed elements of a CFArray (empty when `a` is not an array).
///
/// # Safety
/// `a` must be NULL or a valid CF object; the elements are valid while `a` is.
pub unsafe fn array_items(a: CFTypeRef) -> Vec<CFTypeRef> {
    // SAFETY: type-checked; indices are within CFArrayGetCount.
    unsafe {
        if !is(a, CFArrayGetTypeID()) {
            return Vec::new();
        }
        (0..CFArrayGetCount(a)).map(|i| CFArrayGetValueAtIndex(a, i)).collect()
    }
}

/// Build a CFDictionary (tests and fixtures). Values are retained by the dictionary.
#[cfg(test)]
pub fn dictionary(pairs: &[(&str, CFTypeRef)]) -> Option<Cf> {
    let keys: Vec<Cf> = pairs.iter().filter_map(|(k, _)| string(k)).collect();
    let kp: Vec<CFTypeRef> = keys.iter().map(Cf::as_ptr).collect();
    let vp: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
    // SAFETY: parallel key/value arrays of equal length; the standard CFType callbacks retain both.
    unsafe {
        Cf::owned(CFDictionaryCreate(
            std::ptr::null(),
            kp.as_ptr(),
            vp.as_ptr(),
            kp.len() as CFIndex,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        ))
    }
}

#[cfg(test)]
pub fn number(n: i64) -> Option<Cf> {
    // SAFETY: n is a valid i64 for kCFNumberSInt64Type; result owned.
    unsafe { Cf::owned(CFNumberCreate(std::ptr::null(), kCFNumberSInt64Type, &n as *const i64 as *const c_void)) }
}

#[cfg(test)]
pub fn array(items: &[CFTypeRef]) -> Option<Cf> {
    // SAFETY: items are valid CF objects, retained by the array via the CFType callbacks.
    unsafe {
        Cf::owned(CFArrayCreate(
            std::ptr::null(),
            items.as_ptr(),
            items.len() as CFIndex,
            &raw const kCFTypeArrayCallBacks,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_struct_sizes() {
        assert_eq!(std::mem::size_of::<CFDictionaryKeyCallBacks>(), 48);
        assert_eq!(std::mem::size_of::<CFDictionaryValueCallBacks>(), 40);
    }

    #[test]
    fn dictionary_round_trip() {
        let s = string("Apple M3 Max — GPU").unwrap();
        let n = number(1_596_080_128).unwrap();
        let inner = dictionary(&[("Device Utilization %", number(37).unwrap().as_ptr())]).unwrap();
        let d = dictionary(&[
            ("model", s.as_ptr()),
            ("In use system memory", n.as_ptr()),
            ("PerformanceStatistics", inner.as_ptr()),
        ])
        .unwrap();
        unsafe {
            assert_eq!(dict_string(d.as_ptr(), "model").as_deref(), Some("Apple M3 Max — GPU"));
            assert_eq!(dict_i64(d.as_ptr(), "In use system memory"), Some(1_596_080_128));
            // Exact key match only.
            assert_eq!(dict_i64(d.as_ptr(), "In use system memory (driver)"), None);
            let perf = dict_get(d.as_ptr(), "PerformanceStatistics");
            assert_eq!(dict_i64(perf, "Device Utilization %"), Some(37));
            // Type mismatches read as None, never crash.
            assert_eq!(dict_i64(d.as_ptr(), "model"), None);
            assert_eq!(dict_string(d.as_ptr(), "In use system memory"), None);
            assert_eq!(dict_i64(s.as_ptr(), "anything"), None, "not a dictionary");
            assert_eq!(dict_i64(std::ptr::null(), "x"), None);
            assert_eq!(to_text(s.as_ptr()).as_deref(), Some("Apple M3 Max — GPU"));
            assert_eq!(to_f64(n.as_ptr()), Some(1_596_080_128.0));
            let arr = array(&[s.as_ptr(), n.as_ptr()]).unwrap();
            let items = array_items(arr.as_ptr());
            assert_eq!(items.len(), 2);
            assert_eq!(to_i64(items[1]), Some(1_596_080_128));
            assert!(array_items(d.as_ptr()).is_empty());
        }
    }
}
