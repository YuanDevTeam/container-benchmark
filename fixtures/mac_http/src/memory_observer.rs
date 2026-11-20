//! Core worker kernel lifetime readings at the hello and exit boundaries.
use serde_json::{Value, json};
use std::{mem, ptr};

const TASK_VM_INFO: libc::task_flavor_t = 22;

// Public task_info.h revision-3 prefix, including all preceding ABI fields.
// Address fields exist only for ABI layout and are never serialized or read.
#[repr(C)]
#[derive(Default)]
struct TaskVmInfoRev3 {
    virtual_size: libc::mach_vm_size_t,
    region_count: libc::integer_t,
    page_size: libc::integer_t,
    resident_size: libc::mach_vm_size_t,
    resident_size_peak: libc::mach_vm_size_t,
    device: libc::mach_vm_size_t,
    device_peak: libc::mach_vm_size_t,
    internal: libc::mach_vm_size_t,
    internal_peak: libc::mach_vm_size_t,
    external: libc::mach_vm_size_t,
    external_peak: libc::mach_vm_size_t,
    reusable: libc::mach_vm_size_t,
    reusable_peak: libc::mach_vm_size_t,
    purgeable_volatile_pmap: libc::mach_vm_size_t,
    purgeable_volatile_resident: libc::mach_vm_size_t,
    purgeable_volatile_virtual: libc::mach_vm_size_t,
    compressed: libc::mach_vm_size_t,
    compressed_peak: libc::mach_vm_size_t,
    compressed_lifetime: libc::mach_vm_size_t,
    phys_footprint: libc::mach_vm_size_t,
    min_address: libc::mach_vm_address_t,
    max_address: libc::mach_vm_address_t,
    ledger_phys_footprint_peak: i64,
    remaining_rev3_ledgers: [i64; 20],
}

const _: () = {
    assert!(mem::size_of::<TaskVmInfoRev3>() == 336);
    assert!(mem::offset_of!(TaskVmInfoRev3, phys_footprint) == 144);
    assert!(mem::offset_of!(TaskVmInfoRev3, ledger_phys_footprint_peak) == 168);
};

struct TaskVmCapture {
    info: TaskVmInfoRev3,
    returned_words: libc::mach_msg_type_number_t,
    status: libc::kern_return_t,
}

#[allow(deprecated)] // libc's public thin mach_task_self accessor.
fn task_vm_capture() -> TaskVmCapture {
    let mut info = TaskVmInfoRev3::default();
    let mut returned_words =
        (mem::size_of::<TaskVmInfoRev3>() / mem::size_of::<libc::natural_t>()) as u32;
    // SAFETY: exact documented complete revision-3 prefix, in natural_t words.
    let status = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            TASK_VM_INFO,
            ptr::from_mut(&mut info).cast(),
            &mut returned_words,
        )
    };
    TaskVmCapture {
        info,
        returned_words,
        status,
    }
}

fn process_memory_json(capture: TaskVmCapture, process_id: u32, final_observation: bool) -> Value {
    let TaskVmCapture {
        info,
        returned_words,
        status,
    } = capture;
    let bytes = returned_words as usize * mem::size_of::<libc::natural_t>();
    let current_available = status == libc::KERN_SUCCESS
        && bytes >= mem::offset_of!(TaskVmInfoRev3, phys_footprint) + mem::size_of::<u64>()
        && info.phys_footprint > 0;
    let peak_available = current_available
        && bytes >= mem::size_of::<TaskVmInfoRev3>()
        && info.ledger_phys_footprint_peak > 0
        && info.ledger_phys_footprint_peak as u64 >= info.phys_footprint;
    json!({
        "schemaVersion":1,"metric":"physical_footprint","unit":"bytes",
        "processID":process_id,"available":current_available && peak_available,
        "currentAvailable":current_available,"peakAvailable":peak_available,
        "currentBytes":current_available.then_some(info.phys_footprint),
        "lifetimePeakBytes":peak_available.then_some(info.ledger_phys_footprint_peak as u64),
        "machStatus":status,"returnedWords":returned_words,
        "finalObservation":final_observation,
        "observationPoint":if final_observation {"after-core-stop-destroy-and-observer-join-before-exit-reply"} else {"worker-hello"},
        "scope":"exact Core worker kernel lifetime through this self observation; excludes parent client/origin; final observation follows Core stop/destroy, but excludes exit-reply serialization and process-exit tail",
        "sampling":"existing hello/exit boundary only; no observer thread or periodic sampling",
        "fullExecToReapObserved":false
    })
}

/// Kernel lifetime high-water mark from the exact worker.
/// The final reading includes Core cleanup; subsequent reply encoding and the
/// process-exit tail cannot be covered by a self observation and remain explicit.
pub fn process_memory(final_observation: bool) -> Value {
    process_memory_json(task_vm_capture(), std::process::id(), final_observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_process_memory(
        status: libc::kern_return_t,
        returned_words: u32,
        current: u64,
        peak: i64,
    ) -> Value {
        process_memory_json(
            TaskVmCapture {
                info: TaskVmInfoRev3 {
                    phys_footprint: current,
                    ledger_phys_footprint_peak: peak,
                    resident_size: 2 * 1024 * 1024 * 1024,
                    resident_size_peak: 3 * 1024 * 1024 * 1024,
                    ..TaskVmInfoRev3::default()
                },
                returned_words,
                status,
            },
            321,
            true,
        )
    }

    #[test]
    fn formal_footprint_uses_kernel_ledger_peak_and_exact_worker_identity() {
        let memory = fake_process_memory(libc::KERN_SUCCESS, 84, 1024, 8 * 1024);
        assert_eq!(memory["schemaVersion"], 1);
        assert_eq!(memory["metric"], "physical_footprint");
        assert_eq!(memory["unit"], "bytes");
        assert_eq!(memory["processID"], 321);
        assert_eq!(memory["available"], true);
        assert_eq!(memory["currentAvailable"], true);
        assert_eq!(memory["peakAvailable"], true);
        assert_eq!(memory["currentBytes"], 1024);
        assert_eq!(memory["lifetimePeakBytes"], 8 * 1024);
        assert_eq!(memory["machStatus"], libc::KERN_SUCCESS);
        assert_eq!(memory["returnedWords"], 84);
        assert_eq!(memory["finalObservation"], true);
        assert_eq!(memory["fullExecToReapObserved"], false);
        assert!(memory.get("maxRSSBytes").is_none());
        assert!(
            memory["scope"]
                .as_str()
                .unwrap()
                .contains("process-exit tail")
        );
    }

    #[test]
    fn failed_or_short_mach_reply_cannot_become_a_zero_or_rss_peak() {
        for (status, words) in [(libc::KERN_INVALID_ARGUMENT, 84), (libc::KERN_SUCCESS, 37)] {
            let memory = fake_process_memory(status, words, 1024, 8 * 1024);
            assert_eq!(memory["available"], false);
            assert_eq!(memory["currentAvailable"], false);
            assert_eq!(memory["peakAvailable"], false);
            assert!(memory["currentBytes"].is_null());
            assert!(memory["lifetimePeakBytes"].is_null());
            assert_eq!(memory["machStatus"], status);
            assert_eq!(memory["returnedWords"], words);
        }
    }

    #[test]
    fn complete_revision_is_required_for_the_kernel_lifetime_peak() {
        for words in [38, 42, 83] {
            let memory = fake_process_memory(libc::KERN_SUCCESS, words, 1024, 8 * 1024);
            assert_eq!(memory["available"], false);
            assert_eq!(memory["currentAvailable"], true);
            assert_eq!(memory["currentBytes"], 1024);
            assert_eq!(memory["peakAvailable"], false);
            assert!(memory["lifetimePeakBytes"].is_null());
        }
    }

    #[test]
    fn zero_negative_or_inconsistent_kernel_peak_is_unavailable() {
        for peak in [0, -1, 512] {
            let memory = fake_process_memory(libc::KERN_SUCCESS, 84, 1024, peak);
            assert_eq!(memory["available"], false);
            assert_eq!(memory["currentAvailable"], true);
            assert_eq!(memory["peakAvailable"], false);
            assert!(memory["lifetimePeakBytes"].is_null());
        }
        let memory = fake_process_memory(libc::KERN_SUCCESS, 84, 0, 8 * 1024);
        assert_eq!(memory["available"], false);
        assert!(memory["currentBytes"].is_null());
        assert!(memory["lifetimePeakBytes"].is_null());
    }
}
