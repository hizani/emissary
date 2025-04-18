#![no_main]

use emissary_core::i2np::tunnel::build::short::TunnelBuildRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: Vec<u8>| {
    let _ = TunnelBuildRecord::parse(&buffer);
});
