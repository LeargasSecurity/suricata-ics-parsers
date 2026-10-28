// S7comm Suricata app-layer parser plugin
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::consts::*;
use crate::cotp::*;
use crate::parser::*;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata::applayer::{
    state_get_tx_iterator, AppLayerEvent, AppLayerFrameType, AppLayerRegisterParser,
    AppLayerRegisterProtocolDetection, AppLayerResult, AppLayerStateData, AppLayerTxData,
    RustParser, State, StreamSlice, Transaction, APP_LAYER_PARSER_EOF_TC, APP_LAYER_PARSER_EOF_TS,
    APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use suricata::conf::conf_get;
use suricata::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP};
use suricata::frames::Frame;
use suricata::{
    build_slice, cast_pointer, export_state_data_get, export_tx_data_get, SCLogError, SCLogNotice,
};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, Flow, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(crate) static mut ALPROTO_S7COMM: AppProto = ALPROTO_UNKNOWN;

/// Maximum number of live transactions before we force an error (DoS guard).
static mut S7COMM_MAX_TX: usize = 1024;

/// Maximum size (bytes) of a single S7comm PDU we will accept before erroring.
/// A TPKT length field is 16-bit, so 65535 is the protocol maximum; the default
/// bounds pathological reassembly requests.
static mut S7COMM_MAX_BUFFER: usize = 131072;

/// Frame types exposed to the Suricata detection engine.
#[repr(u8)]
pub(crate) enum S7commFrameType {
    /// The entire TPKT/COTP/S7comm PDU.
    Pdu = 0,
    /// The S7comm portion only (after TPKT + COTP).
    S7comm = 1,
}

impl AppLayerFrameType for S7commFrameType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Pdu),
            1 => Some(Self::S7comm),
            _ => None,
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Pdu => 0,
            Self::S7comm => 1,
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "pdu" => Some(Self::Pdu),
            "s7comm" => Some(Self::S7comm),
            _ => None,
        }
    }

    fn to_cstring(&self) -> *const c_char {
        match self {
            Self::Pdu => b"pdu\0".as_ptr() as *const c_char,
            Self::S7comm => b"s7comm\0".as_ptr() as *const c_char,
        }
    }
}

#[derive(AppLayerEvent)]
pub(crate) enum S7commEvent {
    MalformedPdu,
    InvalidProtocolId,
    PlcStop,
    PlcModeChange,
    ProgramDownload,
    ProgramUpload,
    WriteVariable,
    ReadSzl,
    PasswordAccess,
    S7CommPlusUsage,
    TooManyTransactions,
}

pub(crate) struct S7commTransaction {
    pub tx_id: u64,
    pub pdu_reference: u16,

    pub request_rosctr: u8,
    pub request_function_code: u8,
    pub request_function_name: Option<&'static str>,
    pub request_userdata_group: u8,
    pub request_userdata_group_name: Option<&'static str>,
    pub request_userdata_subfunction: u8,

    pub response_rosctr: u8,
    pub response_error_class: u8,
    pub response_error_code: u8,

    // Data item (Read/Write Variable)
    pub has_data_item: bool,
    pub item_count: u8,
    pub item_area: u8,
    pub item_area_name: Option<&'static str>,
    pub item_db_number: u16,
    pub item_address: u32,
    pub item_length: u16,

    // COTP connection info (rack/slot addressing)
    pub src_tsap: u16,
    pub dst_tsap: u16,
    pub rack: u8,
    pub slot: u8,
    pub has_tsap: bool,

    // PLC control
    pub plc_control_service: Option<&'static str>,

    // S7comm-plus
    pub is_s7comm_plus: bool,
    pub s7plus_version: u8,
    pub s7plus_opcode: u8,
    pub s7plus_opcode_name: Option<&'static str>,
    pub s7plus_function: u16,
    pub s7plus_function_name: Option<&'static str>,
    pub s7plus_has_function: bool,
    pub s7plus_seqnum: u16,

    pub is_dangerous: bool,
    pub attack_technique: Option<&'static str>,

    pub complete: bool,

    /// Raw request/response payload for sticky-buffer matching
    pub request_buffer: Vec<u8>,
    pub response_buffer: Vec<u8>,

    tx_data: AppLayerTxData,
}

impl Default for S7commTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl S7commTransaction {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            pdu_reference: 0,
            request_rosctr: 0,
            request_function_code: 0,
            request_function_name: None,
            request_userdata_group: 0,
            request_userdata_group_name: None,
            request_userdata_subfunction: 0,
            response_rosctr: 0,
            response_error_class: 0,
            response_error_code: 0,
            has_data_item: false,
            item_count: 0,
            item_area: 0,
            item_area_name: None,
            item_db_number: 0,
            item_address: 0,
            item_length: 0,
            src_tsap: 0,
            dst_tsap: 0,
            rack: 0,
            slot: 0,
            has_tsap: false,
            plc_control_service: None,
            is_s7comm_plus: false,
            s7plus_version: 0,
            s7plus_opcode: 0,
            s7plus_opcode_name: None,
            s7plus_function: 0,
            s7plus_function_name: None,
            s7plus_has_function: false,
            s7plus_seqnum: 0,
            is_dangerous: false,
            attack_technique: None,
            complete: false,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for S7commTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub(crate) struct S7commState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<S7commTransaction>,
    // Connection-level TSAP info learned from COTP CR/CC
    conn_src_tsap: u16,
    conn_dst_tsap: u16,
    conn_rack: u8,
    conn_slot: u8,
    conn_has_tsap: bool,
    cotp_connected: bool,
}

impl State<S7commTransaction> for S7commState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&S7commTransaction> {
        self.transactions.get(index)
    }
}

impl S7commState {
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

    pub fn get_tx(&self, tx_id: u64) -> Option<&S7commTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> &mut S7commTransaction {
        self.tx_id += 1;
        let mut tx = S7commTransaction::new();
        tx.tx_id = self.tx_id;
        // Inherit learned connection addressing
        if self.conn_has_tsap {
            tx.src_tsap = self.conn_src_tsap;
            tx.dst_tsap = self.conn_dst_tsap;
            tx.rack = self.conn_rack;
            tx.slot = self.conn_slot;
            tx.has_tsap = true;
        }
        self.transactions.push_back(tx);
        self.transactions.back_mut().unwrap()
    }

    fn find_tx_by_pdu_ref(&mut self, pdu_ref: u16) -> Option<&mut S7commTransaction> {
        self.transactions
            .iter_mut()
            .rev()
            .find(|tx| tx.pdu_reference == pdu_ref && !tx.complete)
    }

    fn parse_request(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            let tpkt_len = match tpkt_frame(start, unsafe { S7COMM_MAX_BUFFER }) {
                TpktFrame::Complete(len) => len,
                TpktFrame::Incomplete(needed) => {
                    let consumed = input.len() - start.len();
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                TpktFrame::Invalid => return AppLayerResult::err(),
            };

            let pdu_data = &start[..tpkt_len];
            self.emit_frames(flow, stream_slice, pdu_data);

            match parse_s7comm_pdu(pdu_data) {
                Ok((_, pdu)) => {
                    self.process_request_pdu(&pdu, pdu_data);
                }
                Err(_) => {
                    let tx = self.new_tx();
                    tx.tx_data.set_event(S7commEvent::MalformedPdu as u8);
                    tx.complete = true;
                    return AppLayerResult::err();
                }
            }

            start = &start[tpkt_len..];

            if self.transactions.len() >= unsafe { S7COMM_MAX_TX } {
                if let Some(tx) = self.transactions.back_mut() {
                    tx.tx_data.set_event(S7commEvent::TooManyTransactions as u8);
                }
                return AppLayerResult::err();
            }
        }

        AppLayerResult::ok()
    }

    fn parse_response(&mut self, flow: *const Flow, stream_slice: &StreamSlice) -> AppLayerResult {
        let input = stream_slice.as_slice();
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            let tpkt_len = match tpkt_frame(start, unsafe { S7COMM_MAX_BUFFER }) {
                TpktFrame::Complete(len) => len,
                TpktFrame::Incomplete(needed) => {
                    let consumed = input.len() - start.len();
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                TpktFrame::Invalid => return AppLayerResult::err(),
            };

            let pdu_data = &start[..tpkt_len];
            self.emit_frames(flow, stream_slice, pdu_data);

            match parse_s7comm_pdu(pdu_data) {
                Ok((_, pdu)) => {
                    self.process_response_pdu(&pdu, pdu_data);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }

            start = &start[tpkt_len..];
        }

        AppLayerResult::ok()
    }

    /// Emit protocol frames for a complete PDU that lies within `stream_slice`.
    fn emit_frames(&self, flow: *const Flow, stream_slice: &StreamSlice, pdu_data: &[u8]) {
        // Whole TPKT/COTP/S7comm PDU frame.
        let _ = Frame::new(
            flow,
            stream_slice,
            pdu_data,
            pdu_data.len() as i64,
            S7commFrameType::Pdu as u8,
            None,
        );
        // S7comm-portion frame (after TPKT[4] + COTP length byte + COTP body).
        if pdu_data.len() >= 6 {
            let cotp_len = pdu_data[4] as usize;
            let s7_offset = 5 + cotp_len;
            if s7_offset < pdu_data.len() {
                let proto = pdu_data[s7_offset];
                if proto == S7COMM_PROTOCOL_ID || proto == S7COMM_PLUS_PROTOCOL_ID {
                    let _ = Frame::new(
                        flow,
                        stream_slice,
                        &pdu_data[s7_offset..],
                        (pdu_data.len() - s7_offset) as i64,
                        S7commFrameType::S7comm as u8,
                        None,
                    );
                }
            }
        }
    }

    fn process_request_pdu(&mut self, pdu: &S7commPdu, raw: &[u8]) {
        // COTP connection request: learn TSAP/rack/slot
        if pdu.cotp_type == COTP_CR {
            self.cotp_connected = false;
            if let Some(ref conn) = pdu.cotp_connect {
                self.learn_tsap(conn);
            }
            return;
        }

        if pdu.is_s7comm_plus {
            let tx = self.new_tx();
            tx.is_s7comm_plus = true;
            tx.request_buffer = raw.to_vec();
            if let Some(ref sp) = pdu.s7_plus {
                tx.s7plus_version = sp.version;
                tx.s7plus_opcode = sp.opcode;
                tx.s7plus_opcode_name = S7PlusOpcode::from_u8(sp.opcode).map(|o| o.as_str());
                tx.s7plus_has_function = sp.has_function;
                if sp.has_function {
                    tx.s7plus_function = sp.function;
                    tx.s7plus_function_name = Some(s7plus_function_name(sp.function));
                    tx.s7plus_seqnum = sp.sequence_number;
                }
            }
            tx.tx_data.set_event(S7commEvent::S7CommPlusUsage as u8);
            tx.complete = true;
            return;
        }

        if let Some(ref header) = pdu.s7_header {
            match header.rosctr {
                0x01 => {
                    let tx = self.new_tx();
                    tx.pdu_reference = header.pdu_reference;
                    tx.request_rosctr = header.rosctr;
                    tx.request_buffer = raw.to_vec();

                    // Data item (Read/Write Variable)
                    if let Some(ref item) = pdu.data_item {
                        tx.has_data_item = true;
                        tx.item_count = pdu.item_count;
                        tx.item_area = item.area;
                        tx.item_area_name = S7Area::from_u8(item.area).map(|a| a.as_str());
                        tx.item_db_number = item.db_number;
                        tx.item_address = item.byte_address;
                        tx.item_length = item.length;
                    }

                    // PLC control service string
                    tx.plc_control_service = pdu.plc_control_service;

                    if let Some(ref param) = pdu.s7_parameter {
                        tx.request_function_code = param.function_code;
                        if let Some(fc) = S7Function::from_u8(param.function_code) {
                            tx.request_function_name = Some(fc.as_str());
                            tx.is_dangerous = fc.is_dangerous();
                            let technique = fc.attack_technique();
                            if !technique.is_empty() {
                                tx.attack_technique = Some(technique);
                            }

                            match fc {
                                S7Function::PlcStop => {
                                    tx.tx_data.set_event(S7commEvent::PlcStop as u8);
                                }
                                S7Function::PlcControl => {
                                    tx.tx_data.set_event(S7commEvent::PlcModeChange as u8);
                                }
                                S7Function::RequestDownload
                                | S7Function::DownloadBlock
                                | S7Function::DownloadEnded => {
                                    tx.tx_data.set_event(S7commEvent::ProgramDownload as u8);
                                }
                                S7Function::StartUpload
                                | S7Function::Upload
                                | S7Function::EndUpload => {
                                    tx.tx_data.set_event(S7commEvent::ProgramUpload as u8);
                                }
                                S7Function::WriteVar => {
                                    tx.tx_data.set_event(S7commEvent::WriteVariable as u8);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                0x07 => {
                    let tx = self.new_tx();
                    tx.pdu_reference = header.pdu_reference;
                    tx.request_rosctr = header.rosctr;
                    tx.request_buffer = raw.to_vec();

                    if let Some(ref ud) = pdu.s7_userdata {
                        let group = ud.function_type & 0x0F;
                        tx.request_userdata_group = group;
                        tx.request_userdata_group_name =
                            S7UserdataGroup::from_u8(group).map(|g| g.as_str());
                        tx.request_userdata_subfunction = ud.subfunction;

                        // Security group access (password functions)
                        if group == S7UserdataGroup::Security as u8 {
                            tx.is_dangerous = true;
                            tx.attack_technique =
                                Some("T0859 Valid Accounts / T0812 Default Credentials");
                            tx.tx_data.set_event(S7commEvent::PasswordAccess as u8);
                        }

                        // Read SZL (CPU functions group 4, subfunc 1) = reconnaissance
                        if group == S7UserdataGroup::CpuFunctions as u8
                            && ud.subfunction == S7_CPU_READ_SZL
                        {
                            tx.attack_technique = Some("T0888 Remote System Information Discovery");
                            tx.tx_data.set_event(S7commEvent::ReadSzl as u8);
                        }
                    }
                    tx.complete = true;
                }
                _ => {
                    // Unknown/invalid ROSCTR value — record as an anomaly.
                    if pdu.invalid_rosctr {
                        let tx = self.new_tx();
                        tx.pdu_reference = header.pdu_reference;
                        tx.request_rosctr = header.rosctr;
                        tx.request_buffer = raw.to_vec();
                        tx.tx_data.set_event(S7commEvent::InvalidProtocolId as u8);
                        tx.complete = true;
                    }
                }
            }
        }
    }

    fn process_response_pdu(&mut self, pdu: &S7commPdu, raw: &[u8]) {
        if pdu.cotp_type == COTP_CC {
            self.cotp_connected = true;
            if let Some(ref conn) = pdu.cotp_connect {
                self.learn_tsap(conn);
            }
            return;
        }

        if let Some(ref header) = pdu.s7_header {
            if header.rosctr == 0x02 || header.rosctr == 0x03 {
                if let Some(tx) = self.find_tx_by_pdu_ref(header.pdu_reference) {
                    tx.response_rosctr = header.rosctr;
                    tx.response_error_class = header.error_class.unwrap_or(0);
                    tx.response_error_code = header.error_code.unwrap_or(0);
                    tx.response_buffer = raw.to_vec();
                    tx.complete = true;
                    tx.tx_data.updated_tc = true;
                }
            }
        }
    }

    fn learn_tsap(&mut self, conn: &CotpConnectInfo) {
        if let Some(src) = conn.src_tsap {
            self.conn_src_tsap = src;
        }
        if let Some(dst) = conn.dst_tsap {
            self.conn_dst_tsap = dst;
        }
        if let Some(rack) = conn.rack {
            self.conn_rack = rack;
        }
        if let Some(slot) = conn.slot {
            self.conn_slot = slot;
        }
        if conn.src_tsap.is_some() || conn.dst_tsap.is_some() {
            self.conn_has_tsap = true;
        }
    }
}

// C FFI exports

unsafe extern "C" fn s7comm_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    if input.is_null() || input_len == 0 {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, input_len as usize);
    match probe_iso102(slice) {
        Iso102Probe::Detected(Iso102Payload::S7comm | Iso102Payload::S7commPlus) => ALPROTO_S7COMM,
        Iso102Probe::NeedMore => ALPROTO_UNKNOWN,
        _ => ALPROTO_FAILED,
    }
}

extern "C" fn s7comm_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = S7commState::new();
    Box::into_raw(Box::new(state)) as *mut c_void
}

unsafe extern "C" fn s7comm_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut S7commState));
}

unsafe extern "C" fn s7comm_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, S7commState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn s7comm_parse_request(
    flow: *mut Flow,
    state: *mut c_void,
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, S7commState);
    if stream_slice.is_gap() {
        return AppLayerResult::ok();
    }
    state.parse_request(flow, &stream_slice)
}

unsafe extern "C" fn s7comm_parse_response(
    flow: *mut Flow,
    state: *mut c_void,
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, S7commState);
    if stream_slice.is_gap() {
        return AppLayerResult::ok();
    }
    state.parse_response(flow, &stream_slice)
}

unsafe extern "C" fn s7comm_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, S7commState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn s7comm_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, S7commState);
    state.tx_id
}

unsafe extern "C" fn s7comm_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    if tx.complete {
        return 1;
    }
    0
}

export_tx_data_get!(s7comm_get_tx_data, S7commTransaction);
export_state_data_get!(s7comm_get_state_data, S7commState);

const PARSER_NAME: &[u8] = b"s7comm\0";

pub(crate) unsafe extern "C" fn s7comm_register_parser() {
    let default_port = CString::new("[102]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(s7comm_probing_parser),
        probe_tc: Some(s7comm_probing_parser),
        min_depth: 0,
        // Room for a full COTP CR (<= 259 bytes) plus the first DT header and payload byte.
        max_depth: 512,
        state_new: s7comm_state_new,
        state_free: s7comm_state_free,
        tx_free: s7comm_state_tx_free,
        parse_ts: s7comm_parse_request,
        parse_tc: s7comm_parse_response,
        get_tx_count: s7comm_state_get_tx_count,
        get_tx: s7comm_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: s7comm_tx_get_alstate_progress,
        get_eventinfo: Some(S7commEvent::get_event_info),
        get_eventinfo_byid: Some(S7commEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<S7commState, S7commTransaction>),
        get_tx_data: s7comm_get_tx_data,
        get_state_data: s7comm_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(S7commFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(S7commFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_S7COMM = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        // Optional config: app-layer.protocols.s7comm.max-tx
        if let Some(val) = conf_get("app-layer.protocols.s7comm.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                S7COMM_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for s7comm.max-tx");
            }
        }
        // Optional config: app-layer.protocols.s7comm.max-request-size
        if let Some(val) = conf_get("app-layer.protocols.s7comm.max-request-size") {
            if let Ok(v) = val.parse::<usize>() {
                S7COMM_MAX_BUFFER = v;
            } else {
                SCLogError!("Invalid value for s7comm.max-request-size");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_S7COMM);
        SCLogNotice!("S7comm parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for s7comm.");
    }
}

/// Fuzzing harness: TPKT-frame the input like the parse loops and run each
/// PDU through the request or response path (low bit of the TPKT reserved
/// byte picks the direction).
#[cfg(fuzzing)]
pub(crate) fn fuzz_feed(data: &[u8]) {
    let mut s = S7commState::new();
    let mut start = data;
    while !start.is_empty() {
        let len = match tpkt_frame(start, unsafe { S7COMM_MAX_BUFFER }) {
            TpktFrame::Complete(len) => len,
            _ => break,
        };
        let pdu_data = &start[..len];
        let to_server = start[1] & 1 == 0;
        if let Ok((_, pdu)) = parse_s7comm_pdu(pdu_data) {
            if to_server {
                s.process_request_pdu(&pdu, pdu_data);
            } else {
                s.process_response_pdu(&pdu, pdu_data);
            }
        }
        start = &start[len..];
        if s.transactions.len() > 256 {
            s.transactions.clear();
        }
    }
}
