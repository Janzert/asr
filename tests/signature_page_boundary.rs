//! Scans are done a page at a time, with the tail of the last page carried in
//! front of the next one so a signature lying across the boundary is still
//! found. Two things about that carry are easy to get wrong, and both are
//! invisible in the common case where every page is a full 4 KiB.
//!
//! The runtime side of a read is stubbed: memory is zero everywhere except one
//! planted needle.

use std::{
    panic, ptr, slice,
    sync::{Mutex, MutexGuard},
};

/// The needle, planted at `NEEDLE_AT`.
const NEEDLE: [u8; 3] = [0x48, 0x8B, 0x0D];
/// An address no scan here covers, for the tests that plant nothing.
const NOWHERE: u64 = 1 << 40;
static mut NEEDLE_AT: u64 = NOWHERE;

const PAGE: u64 = 0x1000;

#[no_mangle]
pub extern "C" fn process_attach_by_pid(_pid: u64) -> u64 {
    1
}

#[no_mangle]
pub extern "C" fn process_detach(_process: u64) {}

/// # Safety
///
/// `buf_ptr` must be writable for `buf_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn process_read(
    _process: u64,
    address: u64,
    buf_ptr: *mut u8,
    buf_len: usize,
) -> bool {
    let buf = slice::from_raw_parts_mut(buf_ptr, buf_len);
    buf.fill(0);
    for (i, byte) in NEEDLE.iter().enumerate() {
        let at = NEEDLE_AT + i as u64;
        if at >= address && at < address + buf_len as u64 {
            buf[(at - address) as usize] = *byte;
        }
    }
    true
}

/// Serialises the tests, which share the planted needle. Cargo runs them in
/// parallel otherwise, and they then read each other's.
static PLANTED: Mutex<()> = Mutex::new(());

fn scan(start: u64, len: u64, needle_at: u64) -> Option<u64> {
    let _guard: MutexGuard<'_, ()> = PLANTED.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: the lock above is held for as long as the scan runs, and nothing
    // touches the needle without it.
    unsafe { ptr::addr_of_mut!(NEEDLE_AT).write(needle_at) };
    let process = asr::Process::attach_by_pid(asr::ProcessId(1)).expect("attaching");
    let signature: asr::signature::Signature<3> = asr::signature::Signature::new("48 8B 0D");
    signature
        .scan_process_range(&process, (asr::Address::new(start), len))
        .map(|address| address.value())
}

/// A range that ends part way into a page, which is most of them: a module is
/// not a whole number of pages long.
///
/// The tail carried in front of a page used to be taken at the offset a *full*
/// previous page would have ended at, so the last, short page of a multi-page
/// range asked for more bytes than were there and panicked.
#[test]
fn a_range_can_end_part_way_into_a_page() {
    for (name, start, len) in [
        ("two pages, ending on the boundary", PAGE, 2 * PAGE),
        ("two pages, ending part way in", PAGE, 2 * PAGE + 0x800),
        (
            "starting and ending part way in",
            PAGE + 0x234,
            2 * PAGE + 0x800,
        ),
        ("three pages, ending after one byte", PAGE, 3 * PAGE + 1),
        // The shape `mono::Module::attach` scans with: a short range that lands
        // wherever a symbol happens to be, sometimes across a boundary.
        ("a short range across a boundary", 2 * PAGE - 0x80, 0x100),
    ] {
        let result = panic::catch_unwind(|| scan(start, len, NOWHERE));
        assert!(
            result.is_ok(),
            "{name}: scanning {len:#x} bytes from {start:#x} panicked"
        );
    }
}

/// The carry has to come from where the previous page actually ended.
///
/// It used to be read from the offset a full page would have ended at, so a
/// signature across the first boundary of a range that starts part way into a
/// page was compared against bytes that were never read -- and silently missed.
#[test]
fn a_signature_across_a_page_boundary_is_found() {
    // One byte before the boundary, so the needle spans it.
    let across = 2 * PAGE - 1;

    assert_eq!(
        scan(PAGE, 2 * PAGE, across),
        Some(across),
        "not found from a page-aligned start"
    );
    assert_eq!(
        scan(2 * PAGE - 0x100, PAGE, across),
        Some(across),
        "not found when the first page of the range is a short one"
    );
}
