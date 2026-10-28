// Entry points for cargo-fuzz targets (built only with --cfg fuzzing).
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::cotp::{parse_tpkt_cotp, probe_iso102, tpkt_frame, CotpReassembler};

/// TPKT/COTP framing, reassembly and TCP/102 protocol detection.
pub fn cotp(data: &[u8]) {
    let _ = probe_iso102(data);
    let _ = tpkt_frame(data, 65535);
    let mut r = CotpReassembler::default();
    let mut input = data;
    while let Ok((rest, pdu)) = parse_tpkt_cotp(input) {
        let _ = r.push(pdu.payload, pdu.eot, 4096);
        if rest.len() >= input.len() {
            break;
        }
        input = rest;
    }
}

/// Session/presentation/ACSE/MMS decoding of one TSDU.
pub fn mms_message(data: &[u8]) {
    let _ = crate::mms::parser::parse_iso_message(data);
}

/// The MMS state machine: framing, reassembly, decoding, pairing, limits.
pub fn mms_state(data: &[u8]) {
    crate::mms::state::fuzz_feed(data);
}

pub fn s7comm(data: &[u8]) {
    let _ = crate::parser::parse_s7comm_pdu(data);
    crate::s7comm::fuzz_feed(data);
}

pub fn iec104(data: &[u8]) {
    let _ = crate::iec104::parser::parse_apdu(data);
    let _ = crate::iec104::parser::probe_iec104(data);
    crate::iec104::state::fuzz_feed(data);
}
