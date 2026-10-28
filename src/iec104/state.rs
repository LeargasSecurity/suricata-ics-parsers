// IEC 60870-5-104 Suricata app-layer state, transactions and registration
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use super::consts::*;
use super::parser::*;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata::applayer::{
    state_get_tx_iterator, AppLayerEvent, AppLayerFrameType, AppLayerRegisterParser,
    AppLayerRegisterProtocolDetection, AppLayerResult, AppLayerStateData, AppLayerTxData,
    RustParser, State, StreamSlice, Transaction, APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use suricata::conf::conf_get;
use suricata::core::{ALPROTO_UNKNOWN, IPPROTO_TCP};
use suricata::direction::Direction;
use suricata::frames::Frame;
use suricata::{
    build_slice, cast_pointer, export_state_data_get, export_tx_data_get, SCLogError, SCLogNotice,
};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, Flow, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(crate) static mut ALPROTO_IEC104: AppProto = ALPROTO_UNKNOWN;

/// Maximum number of live transactions before we force an error (DoS guard).
static mut IEC104_MAX_TX: usize = 1024;

#[repr(u8)]
pub(crate) enum Iec104FrameType {
    /// The entire APDU (APCI + ASDU).
    Pdu = 0,
    /// The ASDU portion of an I-format APDU.
    Asdu = 1,
}

impl AppLayerFrameType for Iec104FrameType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Pdu),
            1 => Some(Self::Asdu),
            _ => None,
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Pdu => 0,
            Self::Asdu => 1,
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "pdu" => Some(Self::Pdu),
            "asdu" => Some(Self::Asdu),
            _ => None,
        }
    }

    fn to_cstring(&self) -> *const c_char {
        match self {
            Self::Pdu => b"pdu\0".as_ptr() as *const c_char,
            Self::Asdu => b"asdu\0".as_ptr() as *const c_char,
        }
    }
}

#[derive(AppLayerEvent)]
pub(crate) enum Iec104Event {
    MalformedApdu,
    InvalidStartByte,
    InvalidLength,
    UnknownUFunction,
    UnknownTypeId,
    InvalidCot,
    AsduLengthMismatch,
    SequenceMismatch,
    NegativeConfirmation,
    UnknownAddress,
    Command,
    Interrogation,
    ClockSync,
    ResetProcess,
    ParameterChange,
    FileTransfer,
    StopDataTransfer,
    TooManyTransactions,
}

pub(crate) struct Iec104Transaction {
    pub tx_id: u64,
    pub to_server: bool,
    /// Value of the APDU length byte.
    pub length: u8,
    /// None when the APDU could not be parsed.
    pub apdu: Option<Apdu>,
    pub is_dangerous: bool,
    pub attack_technique: Option<&'static str>,
    /// Raw APDU for sticky-buffer matching.
    pub buffer: Vec<u8>,
    tx_data: AppLayerTxData,
}

impl Iec104Transaction {
    fn new(tx_id: u64, to_server: bool) -> Self {
        let direction = if to_server {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        Self {
            tx_id,
            to_server,
            length: 0,
            apdu: None,
            is_dangerous: false,
            attack_technique: None,
            buffer: Vec::new(),
            tx_data: AppLayerTxData::for_direction(direction),
        }
    }

    pub fn asdu(&self) -> Option<&Asdu> {
        self.apdu.as_ref().and_then(|a| a.asdu.as_ref())
    }

    fn set_event(&mut self, event: Iec104Event) {
        self.tx_data.set_event(event as u8);
    }

    /// Raise events and ATT&CK mapping for a successfully parsed APDU.
    fn classify(&mut self) {
        let apdu = match self.apdu {
            Some(ref a) => a,
            None => return,
        };
        let mut events: Vec<Iec104Event> = Vec::new();

        if let Some(u) = apdu.u_function {
            if u_function_name(u).is_none() {
                events.push(Iec104Event::UnknownUFunction);
            }
            if u == U_STOPDT_ACT {
                events.push(Iec104Event::StopDataTransfer);
                self.attack_technique = Some("T0815 Denial of View");
            }
        }

        if let Some(ref a) = apdu.asdu {
            let cot = a.cot;
            let activation = cot == COT_ACTIVATION || cot == COT_DEACTIVATION;
            let category = type_category(a.type_id);

            if category.is_none() {
                events.push(Iec104Event::UnknownTypeId);
            }
            // 0 is undefined; 14..=19 and 42..=43 are reserved. 48..=63 is private use.
            if cot == 0 || (cot < 48 && cot_name(cot).is_none()) {
                events.push(Iec104Event::InvalidCot);
            }
            if (44..=47).contains(&cot) {
                events.push(Iec104Event::UnknownAddress);
            }
            if a.negative {
                events.push(Iec104Event::NegativeConfirmation);
            }
            if a.length_mismatch {
                events.push(Iec104Event::AsduLengthMismatch);
            }

            match category {
                Some(TypeCategory::Command) if activation => {
                    self.is_dangerous = true;
                    self.attack_technique = Some(command_attack_technique(a.type_id));
                    events.push(Iec104Event::Command);
                }
                Some(TypeCategory::SystemCommand) if cot == COT_ACTIVATION => match a.type_id {
                    C_IC_NA_1 | C_CI_NA_1 => {
                        self.attack_technique = Some("T0861 Point & Tag Identification");
                        events.push(Iec104Event::Interrogation);
                    }
                    C_CS_NA_1 => {
                        events.push(Iec104Event::ClockSync);
                    }
                    C_RP_NA_1 => {
                        self.is_dangerous = true;
                        self.attack_technique = Some("T0816 Device Restart/Shutdown");
                        events.push(Iec104Event::ResetProcess);
                    }
                    _ => {}
                },
                Some(TypeCategory::Parameter) if activation => {
                    self.is_dangerous = true;
                    self.attack_technique = Some("T0836 Modify Parameter");
                    events.push(Iec104Event::ParameterChange);
                }
                Some(TypeCategory::FileTransfer) => {
                    events.push(Iec104Event::FileTransfer);
                }
                _ => {}
            }
        }

        for e in events {
            self.set_event(e);
        }
    }
}

impl Transaction for Iec104Transaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub(crate) struct Iec104State {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<Iec104Transaction>,
    /// Next expected I-format send sequence number per direction.
    next_send_seq_ts: Option<u16>,
    next_send_seq_tc: Option<u16>,
}

impl State<Iec104Transaction> for Iec104State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&Iec104Transaction> {
        self.transactions.get(index)
    }
}

impl Iec104State {
    pub fn new() -> Self {
        Default::default()
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1)
        {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&self, tx_id: u64) -> Option<&Iec104Transaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self, to_server: bool) -> &mut Iec104Transaction {
        self.tx_id += 1;
        self.transactions
            .push_back(Iec104Transaction::new(self.tx_id, to_server));
        self.transactions.back_mut().unwrap()
    }

    /// Sequence continuity can't be verified across a gap.
    fn on_gap(&mut self, to_server: bool) {
        if to_server {
            self.next_send_seq_ts = None;
        } else {
            self.next_send_seq_tc = None;
        }
    }

    fn parse(
        &mut self,
        flow: *const Flow,
        stream_slice: &StreamSlice,
        to_server: bool,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        let mut start = input;
        while !start.is_empty() {
            if start.len() < 2 {
                let consumed = input.len() - start.len();
                return AppLayerResult::incomplete(consumed as u32, (2 - start.len()) as u32);
            }
            // No resynchronisation marker exists in 104, so a bad start byte ends parsing.
            if start[0] != IEC104_START_BYTE {
                let tx = self.new_tx(to_server);
                tx.set_event(Iec104Event::InvalidStartByte);
                return AppLayerResult::err();
            }
            let apdu_len = start[1] as usize + 2;
            if start.len() < apdu_len {
                let consumed = input.len() - start.len();
                return AppLayerResult::incomplete(
                    consumed as u32,
                    (apdu_len - start.len()) as u32,
                );
            }

            let frame = &start[..apdu_len];
            Self::emit_frames(flow, stream_slice, frame);
            self.handle_apdu(frame, to_server);
            start = &start[apdu_len..];

            if self.transactions.len() >= unsafe { IEC104_MAX_TX } {
                if let Some(tx) = self.transactions.back_mut() {
                    tx.set_event(Iec104Event::TooManyTransactions);
                }
                return AppLayerResult::err();
            }
        }
        AppLayerResult::ok()
    }

    fn emit_frames(flow: *const Flow, stream_slice: &StreamSlice, frame: &[u8]) {
        let _ = Frame::new(
            flow,
            stream_slice,
            frame,
            frame.len() as i64,
            Iec104FrameType::Pdu as u8,
            None,
        );
        // I-format with an ASDU after the 6-byte APCI.
        if frame.len() > 6 && frame[2] & 0x01 == 0 {
            let _ = Frame::new(
                flow,
                stream_slice,
                &frame[6..],
                (frame.len() - 6) as i64,
                Iec104FrameType::Asdu as u8,
                None,
            );
        }
    }

    fn handle_apdu(&mut self, frame: &[u8], to_server: bool) {
        let result = parse_apdu(frame);

        let mut seq_mismatch = false;
        if let Ok(Apdu {
            send_seq: Some(ns), ..
        }) = result
        {
            let next = if to_server {
                &mut self.next_send_seq_ts
            } else {
                &mut self.next_send_seq_tc
            };
            if let Some(expected) = *next {
                seq_mismatch = expected != ns;
            }
            *next = Some((ns + 1) & 0x7fff);
        }

        let tx = self.new_tx(to_server);
        tx.length = frame[1];
        tx.buffer = frame.to_vec();
        match result {
            Ok(apdu) => {
                tx.apdu = Some(apdu);
                tx.classify();
                if seq_mismatch {
                    tx.set_event(Iec104Event::SequenceMismatch);
                }
            }
            Err(ApduError::InvalidLength) => tx.set_event(Iec104Event::InvalidLength),
            Err(ApduError::InvalidStart) => tx.set_event(Iec104Event::InvalidStartByte),
            Err(ApduError::Malformed) => tx.set_event(Iec104Event::MalformedApdu),
        }
    }
}

// C FFI exports

unsafe extern "C" fn iec104_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    if input_len >= 6 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe_iec104(slice) {
            return ALPROTO_IEC104;
        }
    }
    ALPROTO_UNKNOWN
}

extern "C" fn iec104_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = Iec104State::new();
    Box::into_raw(Box::new(state)) as *mut c_void
}

unsafe extern "C" fn iec104_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut Iec104State));
}

unsafe extern "C" fn iec104_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, Iec104State);
    state.free_tx(tx_id);
}

unsafe extern "C" fn iec104_parse_ts(
    flow: *mut Flow,
    state: *mut c_void,
    _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, Iec104State);
    if stream_slice.is_gap() {
        state.on_gap(true);
        return AppLayerResult::ok();
    }
    state.parse(flow, &stream_slice, true)
}

unsafe extern "C" fn iec104_parse_tc(
    flow: *mut Flow,
    state: *mut c_void,
    _pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, Iec104State);
    if stream_slice.is_gap() {
        state.on_gap(false);
        return AppLayerResult::ok();
    }
    state.parse(flow, &stream_slice, false)
}

unsafe extern "C" fn iec104_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, Iec104State);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn iec104_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, Iec104State);
    state.tx_id
}

unsafe extern "C" fn iec104_tx_get_alstate_progress(_tx: *mut c_void, _direction: u8) -> c_int {
    // Every APDU is a complete, unidirectional transaction.
    1
}

export_tx_data_get!(iec104_get_tx_data, Iec104Transaction);
export_state_data_get!(iec104_get_state_data, Iec104State);

const PARSER_NAME: &[u8] = b"iec104\0";

pub(crate) unsafe extern "C" fn iec104_register_parser() {
    let default_port = CString::new("[2404]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(iec104_probing_parser),
        probe_tc: Some(iec104_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: iec104_state_new,
        state_free: iec104_state_free,
        tx_free: iec104_state_tx_free,
        parse_ts: iec104_parse_ts,
        parse_tc: iec104_parse_tc,
        get_tx_count: iec104_state_get_tx_count,
        get_tx: iec104_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: iec104_tx_get_alstate_progress,
        get_eventinfo: Some(Iec104Event::get_event_info),
        get_eventinfo_byid: Some(Iec104Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<Iec104State, Iec104Transaction>),
        get_tx_data: iec104_get_tx_data,
        get_state_data: iec104_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(Iec104FrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(Iec104FrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_IEC104 = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        // Optional config: app-layer.protocols.iec104.max-tx
        if let Some(val) = conf_get("app-layer.protocols.iec104.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                IEC104_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for iec104.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC104);
        SCLogNotice!("IEC 60870-5-104 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for iec104.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(state: &mut Iec104State, frames: &[&[u8]], to_server: bool) {
        for f in frames {
            state.handle_apdu(f, to_server);
        }
    }

    #[test]
    fn test_command_is_dangerous() {
        let mut state = Iec104State::new();
        feed(
            &mut state,
            &[&[
                0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x01, 0x06, 0x00, 0x01, 0x00, 0x88, 0x13,
                0x00, 0x01,
            ]],
            true,
        );
        let tx = state.transactions.back().unwrap();
        assert!(tx.is_dangerous);
        assert!(tx.attack_technique.unwrap().starts_with("T0855"));
    }

    #[test]
    fn test_confirmation_not_dangerous() {
        let mut state = Iec104State::new();
        // Same command with COT=7 (activation confirmation) from the outstation.
        feed(
            &mut state,
            &[&[
                0x68, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x2d, 0x01, 0x07, 0x00, 0x01, 0x00, 0x88, 0x13,
                0x00, 0x01,
            ]],
            false,
        );
        assert!(!state.transactions.back().unwrap().is_dangerous);
    }

    #[test]
    fn test_sequence_tracking() {
        let mut state = Iec104State::new();
        // N(S)=0, then N(S)=1 (ok), then N(S)=5 (mismatch)
        let mk = |ns: u16| -> Vec<u8> {
            let cf = (ns << 1).to_le_bytes();
            vec![
                0x68, 0x0e, cf[0], cf[1], 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x14,
            ]
        };
        state.handle_apdu(&mk(0), true);
        state.handle_apdu(&mk(1), true);
        assert_eq!(state.next_send_seq_ts, Some(2));
        state.handle_apdu(&mk(5), true);
        assert_eq!(state.next_send_seq_ts, Some(6));
        // The other direction is tracked independently.
        assert_eq!(state.next_send_seq_tc, None);
        state.on_gap(true);
        assert_eq!(state.next_send_seq_ts, None);
    }

    #[test]
    fn test_tx_free() {
        let mut state = Iec104State::new();
        feed(&mut state, &[&[0x68, 0x04, 0x07, 0x00, 0x00, 0x00]], true);
        feed(&mut state, &[&[0x68, 0x04, 0x0b, 0x00, 0x00, 0x00]], false);
        assert_eq!(state.transactions.len(), 2);
        assert!(state.get_tx(0).unwrap().to_server);
        assert!(!state.get_tx(1).unwrap().to_server);
        state.free_tx(0);
        assert_eq!(state.transactions.len(), 1);
        assert!(state.get_tx(0).is_none());
    }
}

/// Fuzzing harness: split the input into APDUs like `parse()` and feed them,
/// alternating direction on the low bit of each APDU's length byte.
#[cfg(fuzzing)]
pub(crate) fn fuzz_feed(data: &[u8]) {
    let mut s = Iec104State::new();
    let mut start = data;
    while start.len() >= 2 {
        if start[0] != IEC104_START_BYTE {
            break;
        }
        let len = start[1] as usize + 2;
        if start.len() < len {
            break;
        }
        let to_server = start[1] & 1 == 0;
        s.handle_apdu(&start[..len], to_server);
        start = &start[len..];
        if s.transactions.len() > 256 {
            s.transactions.clear();
        }
    }
}
