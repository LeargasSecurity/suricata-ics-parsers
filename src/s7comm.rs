// S7comm Suricata app-layer parser plugin
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::consts::*;
use crate::parser::*;
use nom7 as nom;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata::applayer::{
    state_get_tx_iterator, AppLayerEvent, AppLayerRegisterParser,
    AppLayerRegisterProtocolDetection, AppLayerResult, AppLayerStateData, AppLayerTxData,
    RustParser, State, StreamSlice, Transaction, APP_LAYER_PARSER_EOF_TC, APP_LAYER_PARSER_EOF_TS,
    APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use suricata::core::{ALPROTO_UNKNOWN, IPPROTO_TCP};
use suricata::{
    build_slice, cast_pointer, export_state_data_get, export_tx_data_get, SCLogNotice,
};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, Flow, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(crate) static mut ALPROTO_S7COMM: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
pub(crate) enum S7commEvent {
    MalformedPdu,
    PlcStop,
    PlcModeChange,
    ProgramDownload,
    ProgramUpload,
    WriteVariable,
}

pub(crate) struct S7commTransaction {
    pub tx_id: u64,
    pub pdu_reference: u16,

    pub request_rosctr: u8,
    pub request_function_code: u8,
    pub request_function_name: Option<&'static str>,
    pub request_userdata_group: u8,
    pub request_userdata_subfunction: u8,

    pub response_rosctr: u8,
    pub response_error_class: u8,
    pub response_error_code: u8,

    pub is_dangerous: bool,
    pub attack_technique: Option<&'static str>,
    pub is_s7comm_plus: bool,

    pub complete: bool,

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
            request_userdata_subfunction: 0,
            response_rosctr: 0,
            response_error_class: 0,
            response_error_code: 0,
            is_dangerous: false,
            attack_technique: None,
            is_s7comm_plus: false,
            complete: false,
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
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
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
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            if self.transactions[i].tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
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
        self.transactions.push_back(tx);
        self.transactions.back_mut().unwrap()
    }

    fn find_tx_by_pdu_ref(&mut self, pdu_ref: u16) -> Option<&mut S7commTransaction> {
        self.transactions
            .iter_mut()
            .rev()
            .find(|tx| tx.pdu_reference == pdu_ref && !tx.complete)
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        self.request_buffer.extend_from_slice(input);

        loop {
            if self.request_buffer.len() < 4 {
                return AppLayerResult::ok();
            }

            let tpkt_len =
                u16::from_be_bytes([self.request_buffer[2], self.request_buffer[3]]) as usize;
            if tpkt_len < 7 {
                self.request_buffer.clear();
                return AppLayerResult::err();
            }
            if self.request_buffer.len() < tpkt_len {
                return AppLayerResult::ok();
            }

            let pdu_data: Vec<u8> = self.request_buffer.drain(..tpkt_len).collect();

            match parse_s7comm_pdu(&pdu_data) {
                Ok((_, pdu)) => {
                    self.process_request_pdu(&pdu);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        self.response_buffer.extend_from_slice(input);

        loop {
            if self.response_buffer.len() < 4 {
                return AppLayerResult::ok();
            }

            let tpkt_len =
                u16::from_be_bytes([self.response_buffer[2], self.response_buffer[3]]) as usize;
            if tpkt_len < 7 {
                self.response_buffer.clear();
                return AppLayerResult::err();
            }
            if self.response_buffer.len() < tpkt_len {
                return AppLayerResult::ok();
            }

            let pdu_data: Vec<u8> = self.response_buffer.drain(..tpkt_len).collect();

            match parse_s7comm_pdu(&pdu_data) {
                Ok((_, pdu)) => {
                    self.process_response_pdu(&pdu);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }
    }

    fn process_request_pdu(&mut self, pdu: &S7commPdu) {
        if pdu.cotp_type == COTP_CR {
            self.cotp_connected = false;
            return;
        }

        if pdu.is_s7comm_plus {
            let tx = self.new_tx();
            tx.is_s7comm_plus = true;
            tx.complete = true;
            return;
        }

        if let Some(ref header) = pdu.s7_header {
            match header.rosctr {
                0x01 => {
                    let tx = self.new_tx();
                    tx.pdu_reference = header.pdu_reference;
                    tx.request_rosctr = header.rosctr;

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

                    if let Some(ref ud) = pdu.s7_userdata {
                        let group = ud.function_type & 0x0F;
                        tx.request_userdata_group = group;
                        tx.request_userdata_subfunction = ud.subfunction;
                    }
                    tx.complete = true;
                }
                _ => {}
            }
        }
    }

    fn process_response_pdu(&mut self, pdu: &S7commPdu) {
        if pdu.cotp_type == COTP_CC {
            self.cotp_connected = true;
            return;
        }

        if let Some(ref header) = pdu.s7_header {
            if header.rosctr == 0x02 || header.rosctr == 0x03 {
                if let Some(tx) = self.find_tx_by_pdu_ref(header.pdu_reference) {
                    tx.response_rosctr = header.rosctr;
                    tx.response_error_class = header.error_class.unwrap_or(0);
                    tx.response_error_code = header.error_code.unwrap_or(0);
                    tx.complete = true;
                    tx.tx_data.updated_tc = true;
                }
            }
        }
    }
}

// C FFI exports

unsafe extern "C" fn s7comm_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len > 6 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe_s7comm(slice) {
            return ALPROTO_S7COMM;
        }
    }
    return ALPROTO_UNKNOWN;
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
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if eof {
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, S7commState);
    if stream_slice.is_gap() {
        return AppLayerResult::ok();
    }
    let buf = stream_slice.as_slice();
    state.parse_request(buf)
}

unsafe extern "C" fn s7comm_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, S7commState);
    if stream_slice.is_gap() {
        return AppLayerResult::ok();
    }
    let buf = stream_slice.as_slice();
    state.parse_response(buf)
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
        max_depth: 16,
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
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
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
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_S7COMM);
        SCLogNotice!("S7comm parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for s7comm.");
    }
}
