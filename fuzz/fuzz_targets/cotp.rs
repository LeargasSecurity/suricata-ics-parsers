#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    suricata_ics::fuzz_api::cotp(data);
});
