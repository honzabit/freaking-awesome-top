//! IOKit: disk I/O counters (IOBlockStorageDriver "Statistics"), GPU utilization
//! (IOAccelerator "PerformanceStatistics") and power sources (IOPowerSources). Read-only
//! registry lookups; none needs root.
#![allow(non_upper_case_globals)]

use super::cf::{self, CFTypeRef, Cf};
use crate::model::Gpu;
use std::collections::HashMap;
use std::ffi::{CString, c_char};

type KernReturn = i32;
type IoObject = u32;

const KERN_SUCCESS: KernReturn = 0;
/// kIOMainPortDefault / kIOMasterPortDefault: MACH_PORT_NULL selects the default main port.
const kIOMainPortDefault: u32 = 0;
const kIORegistryIterateRecursively: u32 = 1;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> CFTypeRef;
    fn IOServiceGetMatchingServices(main: u32, matching: CFTypeRef, it: *mut IoObject) -> KernReturn;
    fn IOIteratorNext(it: IoObject) -> IoObject;
    fn IOObjectRelease(o: IoObject) -> KernReturn;
    fn IOObjectGetClass(o: IoObject, name: *mut c_char) -> KernReturn;
    fn IORegistryEntryCreateCFProperty(entry: IoObject, key: CFTypeRef, alloc: CFTypeRef, options: u32) -> CFTypeRef;
    fn IORegistryEntryGetRegistryEntryID(entry: IoObject, id: *mut u64) -> KernReturn;
    fn IORegistryEntryCreateIterator(
        entry: IoObject,
        plane: *const c_char,
        options: u32,
        it: *mut IoObject,
    ) -> KernReturn;
    fn IOPSCopyPowerSourcesInfo() -> CFTypeRef;
    fn IOPSCopyPowerSourcesList(blob: CFTypeRef) -> CFTypeRef;
    fn IOPSGetPowerSourceDescription(blob: CFTypeRef, ps: CFTypeRef) -> CFTypeRef;
    fn IOPSGetProvidingPowerSourceType(blob: CFTypeRef) -> CFTypeRef;
}

/// An io_object_t we own, released on drop.
struct Obj(IoObject);

impl Drop for Obj {
    fn drop(&mut self) {
        // SAFETY: we hold one reference to a valid io object.
        unsafe { IOObjectRelease(self.0) };
    }
}

/// An io_iterator_t; yields owned objects.
struct Iter(Obj);

impl Iterator for Iter {
    type Item = Obj;
    fn next(&mut self) -> Option<Obj> {
        // SAFETY: valid iterator; IOIteratorNext returns a +1 object or 0 at the end.
        let o = unsafe { IOIteratorNext((self.0).0) };
        if o == 0 { None } else { Some(Obj(o)) }
    }
}

/// Registry entries whose class is (or derives from) `class`. None when IOKit refuses.
fn services(class: &str) -> Option<Iter> {
    let c = CString::new(class).ok()?;
    // SAFETY: IOServiceMatching returns a +1 dictionary that IOServiceGetMatchingServices
    // consumes (releases) whatever it returns; `it` is a valid out-param.
    unsafe {
        let m = IOServiceMatching(c.as_ptr());
        if m.is_null() {
            return None;
        }
        let mut it: IoObject = 0;
        (IOServiceGetMatchingServices(kIOMainPortDefault, m, &mut it) == KERN_SUCCESS && it != 0).then(|| Iter(Obj(it)))
    }
}

/// Every descendant of `o` in the IOService plane.
fn descendants(o: &Obj) -> Option<Iter> {
    let plane = c"IOService";
    let mut it: IoObject = 0;
    // SAFETY: valid entry and plane name; `it` is a valid out-param.
    let kr = unsafe { IORegistryEntryCreateIterator(o.0, plane.as_ptr(), kIORegistryIterateRecursively, &mut it) };
    (kr == KERN_SUCCESS && it != 0).then(|| Iter(Obj(it)))
}

/// A copy of property `key` of `o` (None when absent).
fn property(o: &Obj, key: &str) -> Option<Cf> {
    let k = cf::string(key)?;
    // SAFETY: valid entry and CFString key; the result follows the Create rule.
    unsafe { Cf::owned(IORegistryEntryCreateCFProperty(o.0, k.as_ptr(), std::ptr::null(), 0)) }
}

fn entry_id(o: &Obj) -> Option<u64> {
    let mut id = 0u64;
    // SAFETY: valid entry, valid out-param.
    (unsafe { IORegistryEntryGetRegistryEntryID(o.0, &mut id) } == KERN_SUCCESS).then_some(id)
}

fn class_name(o: &Obj) -> Option<String> {
    let mut buf = [0 as c_char; 128]; // io_name_t
    // SAFETY: io_name_t is char[128]; IOObjectGetClass writes a NUL-terminated name into it.
    if unsafe { IOObjectGetClass(o.0, buf.as_mut_ptr()) } != KERN_SUCCESS {
        return None;
    }
    // SAFETY: NUL-terminated within the buffer.
    Some(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
}

/// Same spelling as `ioreg`'s "id 0x100000a59", so the native and fallback paths share maps.
pub fn id_string(id: u64) -> String {
    format!("{id:#x}")
}

/// Every IOBlockStorageDriver: (registry id, bytes read, bytes written). None when IOKit fails.
pub fn block_storage_stats() -> Option<Vec<(String, u64, u64)>> {
    let mut out = Vec::new();
    for drv in services("IOBlockStorageDriver")? {
        let Some(id) = entry_id(&drv) else { continue };
        let Some(stats) = property(&drv, "Statistics") else { continue };
        // SAFETY: `stats` is a live CF object; readers type-check.
        let (r, w) =
            unsafe { (cf::dict_i64(stats.as_ptr(), "Bytes (Read)"), cf::dict_i64(stats.as_ptr(), "Bytes (Write)")) };
        out.push((id_string(id), r.unwrap_or(0).max(0) as u64, w.unwrap_or(0).max(0) as u64));
    }
    Some(out)
}

/// BSD name -> (driver id, whole-disk name) for every BSD node below each IOBlockStorageDriver
/// (the physical disk, its partitions, and APFS containers / volumes / snapshots on them).
pub fn block_storage_bsd_map() -> Option<HashMap<String, (String, String)>> {
    let mut m = HashMap::new();
    for drv in services("IOBlockStorageDriver")? {
        let Some(id) = entry_id(&drv).map(id_string) else { continue };
        let Some(kids) = descendants(&drv) else { continue };
        let mut whole: Option<String> = None;
        for kid in kids {
            let Some(name) = property(&kid, "BSD Name") else { continue };
            // SAFETY: live CF object.
            let Some(name) = (unsafe { cf::to_string(name.as_ptr()) }) else { continue };
            let w = whole.get_or_insert_with(|| name.clone()).clone();
            m.insert(name, (id.clone(), w));
        }
    }
    Some(m)
}

/// GPUs from IOAccelerator: name ("model", else the class), "Device Utilization %", and
/// "In use system memory" bytes. None when IOKit fails; empty when there is no accelerator.
pub fn gpus() -> Option<Vec<Gpu>> {
    let mut out = Vec::new();
    for acc in services("IOAccelerator")? {
        // SAFETY: CF objects below are live for the duration of each read.
        let name = property(&acc, "model")
            .and_then(|m| unsafe { cf::to_text(m.as_ptr()) })
            .filter(|s| !s.is_empty())
            .or_else(|| class_name(&acc))
            .unwrap_or_else(|| "GPU".into());
        let mut g = Gpu { name, ..Default::default() };
        if let Some(perf) = property(&acc, "PerformanceStatistics") {
            // SAFETY: live CF object; readers type-check.
            unsafe {
                if let Some(u) = cf::dict_i64(perf.as_ptr(), "Device Utilization %") {
                    g.util = u.clamp(0, 100) as f32;
                }
                if let Some(mem) = cf::dict_i64(perf.as_ptr(), "In use system memory") {
                    g.mem_used = mem.max(0) as u64;
                }
            }
        }
        out.push(g);
    }
    Some(out)
}

/// (battery percent, on battery) from IOPowerSources, with the same meaning as `pmset -g batt`:
/// percent of the internal battery (None on a desktop); "on battery" only when a battery exists.
/// None when the power-source snapshot cannot be taken.
pub fn battery() -> Option<(Option<f32>, Option<bool>)> {
    // SAFETY: the snapshot and list are Copy-rule objects we own; descriptions are borrowed
    // from the snapshot and only used while it lives. Readers type-check every value.
    unsafe {
        let blob = Cf::owned(IOPSCopyPowerSourcesInfo())?;
        let list = Cf::owned(IOPSCopyPowerSourcesList(blob.as_ptr()))?;
        let mut pct = None;
        let mut state = None;
        for ps in cf::array_items(list.as_ptr()) {
            let d = IOPSGetPowerSourceDescription(blob.as_ptr(), ps);
            if cf::dict_string(d, "Type").as_deref() != Some("InternalBattery")
                || cf::dict_i64(d, "Is Present") == Some(0)
            {
                continue;
            }
            pct = battery_percent(cf::dict_i64(d, "Current Capacity"), cf::dict_i64(d, "Max Capacity"));
            state = cf::dict_string(d, "Power Source State");
            break;
        }
        let providing = cf::to_string(IOPSGetProvidingPowerSourceType(blob.as_ptr())).or(state);
        let on_batt = match providing.as_deref() {
            Some("Battery Power") => Some(true),
            Some("AC Power") | Some("UPS Power") => Some(false),
            _ => None,
        };
        Some((pct, if pct.is_some() { on_batt } else { None }))
    }
}

/// IOPS reports "Current Capacity" in percent of "Max Capacity" (normally 100).
pub fn battery_percent(cur: Option<i64>, max: Option<i64>) -> Option<f32> {
    let cur = cur?;
    let pct = match max {
        Some(m) if m > 0 => (cur as f64 * 100.0 / m as f64).round(),
        _ => cur as f64,
    };
    (0.0..=100.0).contains(&pct).then_some(pct as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent() {
        assert_eq!(battery_percent(Some(87), Some(100)), Some(87.0));
        assert_eq!(battery_percent(Some(4000), Some(5000)), Some(80.0));
        assert_eq!(battery_percent(Some(55), None), Some(55.0));
        assert_eq!(battery_percent(None, Some(100)), None);
        assert_eq!(battery_percent(Some(500), Some(0)), None, "out of range");
    }

    #[test]
    fn id_format_matches_ioreg() {
        assert_eq!(id_string(0x1_0000_0a59), "0x100000a59");
    }

    /// Live registry: whatever this machine has must be readable and consistent.
    #[test]
    fn live_registry() {
        let stats = block_storage_stats().expect("IOKit matching works");
        let map = block_storage_bsd_map().unwrap();
        for (bsd, (id, whole)) in &map {
            assert!(bsd.starts_with("disk"), "{bsd}");
            assert!(
                whole.starts_with("disk") && bsd.starts_with(whole.as_str()) || bsd.starts_with("disk"),
                "{bsd} {whole}"
            );
            assert!(stats.iter().any(|s| &s.0 == id), "map id {id} has stats");
        }
        let g = gpus().unwrap();
        for x in &g {
            assert!(!x.name.is_empty() && (0.0..=100.0).contains(&x.util), "{x:?}");
        }
        let _ = battery().expect("power source snapshot");
    }
}
