// S7comm application-layer state machine
// Copyright (C) 2026 Critical Path Security
// License: GPL-2.0

use crate::s7comm::consts::*;
use crate::s7comm::parser::*;

/// Represents a single S7comm transaction (request/response pair)
#[derive(Debug, Clone)]
pub struct S7commTransaction {
    pub id: u64,
    pub pdu_reference: u16,

    // Request fields
    pub request_rosctr: Option<u8>,
    pub request_function_code: Option<u8>,
    pub request_function_name: Option<&'static str>,
    pub request_userdata_group: Option<u8>,
    pub request_userdata_subfunction: Option<u8>,

    // Response fields
    pub response_rosctr: Option<u8>,
    pub response_error_class: Option<u8>,
    pub response_error_code: Option<u8>,

    // Metadata
    pub is_dangerous: bool,
    pub attack_technique: Option<&'static str>,
    pub is_s7comm_plus: bool,

    // Transaction state
    pub complete: bool,
    pub logged: bool,
}

impl S7commTransaction {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            pdu_reference: 0,
            request_rosctr: None,
            request_function_code: None,
            request_function_name: None,
            request_userdata_group: None,
            request_userdata_subfunction: None,
            response_rosctr: None,
            response_error_class: None,
            response_error_code: None,
            is_dangerous: false,
            attack_technique: None,
            is_s7comm_plus: false,
            complete: false,
            logged: false,
        }
    }
}

/// Events that the S7comm parser can generate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S7commEvent {
    MalformedPdu,
    InvalidProtocolId,
    PlcStop,
    PlcModeChange,
    ProgramDownload,
    ProgramUpload,
    WriteVariable,
    UnauthorizedCommand,
}

impl S7commEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MalformedPdu => "malformed_pdu",
            Self::InvalidProtocolId => "invalid_protocol_id",
            Self::PlcStop => "plc_stop",
            Self::PlcModeChange => "plc_mode_change",
            Self::ProgramDownload => "program_download",
            Self::ProgramUpload => "program_upload",
            Self::WriteVariable => "write_variable",
            Self::UnauthorizedCommand => "unauthorized_command",
        }
    }
}

/// Main S7comm application-layer state
#[derive(Debug)]
pub struct S7commState {
    pub tx_id: u64,
    pub transactions: Vec<S7commTransaction>,
    pub events: Vec<S7commEvent>,

    // TCP reassembly buffer
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,

    // Connection state
    pub cotp_connected: bool,
}

impl Default for S7commState {
    fn default() -> Self {
        Self::new()
    }
}

impl S7commState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
            events: Vec::new(),
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            cotp_connected: false,
        }
    }

    fn new_tx(&mut self) -> &mut S7commTransaction {
        self.tx_id += 1;
        let tx = S7commTransaction::new(self.tx_id);
        self.transactions.push(tx);
        self.transactions.last_mut().unwrap()
    }

    fn find_tx_by_pdu_ref(&mut self, pdu_ref: u16) -> Option<&mut S7commTransaction> {
        self.transactions
            .iter_mut()
            .rev()
            .find(|tx| tx.pdu_reference == pdu_ref && !tx.complete)
    }

    /// Parse data from client (request direction)
    pub fn parse_request(&mut self, input: &[u8]) -> bool {
        self.request_buffer.extend_from_slice(input);

        loop {
            if self.request_buffer.len() < 4 {
                return true;
            }

            // Check TPKT length
            let tpkt_len =
                u16::from_be_bytes([self.request_buffer[2], self.request_buffer[3]]) as usize;
            if self.request_buffer.len() < tpkt_len {
                return true; // Need more data
            }

            // Extract one complete PDU
            let pdu_data: Vec<u8> = self.request_buffer.drain(..tpkt_len).collect();

            match parse_s7comm_pdu(&pdu_data) {
                Ok((_, pdu)) => {
                    self.process_request_pdu(&pdu);
                }
                Err(_) => {
                    self.events.push(S7commEvent::MalformedPdu);
                    return false;
                }
            }
        }
    }

    /// Parse data from server (response direction)
    pub fn parse_response(&mut self, input: &[u8]) -> bool {
        self.response_buffer.extend_from_slice(input);

        loop {
            if self.response_buffer.len() < 4 {
                return true;
            }

            let tpkt_len =
                u16::from_be_bytes([self.response_buffer[2], self.response_buffer[3]]) as usize;
            if self.response_buffer.len() < tpkt_len {
                return true;
            }

            let pdu_data: Vec<u8> = self.response_buffer.drain(..tpkt_len).collect();

            match parse_s7comm_pdu(&pdu_data) {
                Ok((_, pdu)) => {
                    self.process_response_pdu(&pdu);
                }
                Err(_) => {
                    self.events.push(S7commEvent::MalformedPdu);
                    return false;
                }
            }
        }
    }

    fn process_request_pdu(&mut self, pdu: &S7commPdu) {
        // Handle COTP connection
        if pdu.cotp_type == COTP_CR {
            self.cotp_connected = false;
            return;
        }

        // S7comm-plus detection
        if pdu.is_s7comm_plus {
            let tx = self.new_tx();
            tx.is_s7comm_plus = true;
            tx.complete = true;
            return;
        }

        if let Some(ref header) = pdu.s7_header {
            match header.rosctr {
                0x01 => {
                    // Job (request)
                    let tx = self.new_tx();
                    tx.pdu_reference = header.pdu_reference;
                    tx.request_rosctr = Some(header.rosctr);

                    if let Some(ref param) = pdu.s7_parameter {
                        tx.request_function_code = Some(param.function_code);
                        if let Some(fc) = S7Function::from_u8(param.function_code) {
                            tx.request_function_name = Some(fc.as_str());
                            tx.is_dangerous = fc.is_dangerous();
                            let technique = fc.attack_technique();
                            if !technique.is_empty() {
                                tx.attack_technique = Some(technique);
                            }

                            // Generate events for dangerous operations
                            match fc {
                                S7Function::PlcStop => {
                                    self.events.push(S7commEvent::PlcStop);
                                }
                                S7Function::PlcControl => {
                                    self.events.push(S7commEvent::PlcModeChange);
                                }
                                S7Function::RequestDownload
                                | S7Function::DownloadBlock
                                | S7Function::DownloadEnded => {
                                    self.events.push(S7commEvent::ProgramDownload);
                                }
                                S7Function::StartUpload
                                | S7Function::Upload
                                | S7Function::EndUpload => {
                                    self.events.push(S7commEvent::ProgramUpload);
                                }
                                S7Function::WriteVar => {
                                    self.events.push(S7commEvent::WriteVariable);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                0x07 => {
                    // Userdata
                    let tx = self.new_tx();
                    tx.pdu_reference = header.pdu_reference;
                    tx.request_rosctr = Some(header.rosctr);

                    if let Some(ref ud) = pdu.s7_userdata {
                        let group = ud.function_type & 0x0F;
                        tx.request_userdata_group = Some(group);
                        tx.request_userdata_subfunction = Some(ud.subfunction);
                    }
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
                // Ack or AckData — find matching request
                if let Some(tx) = self.find_tx_by_pdu_ref(header.pdu_reference) {
                    tx.response_rosctr = Some(header.rosctr);
                    tx.response_error_class = header.error_class;
                    tx.response_error_code = header.error_code;
                    tx.complete = true;
                }
            }
        }
    }

    /// Get transactions ready for logging
    pub fn get_tx_for_logging(&mut self) -> Vec<&S7commTransaction> {
        self.transactions
            .iter()
            .filter(|tx| tx.complete && !tx.logged)
            .collect()
    }

    /// Mark a transaction as logged
    pub fn mark_logged(&mut self, tx_id: u64) {
        if let Some(tx) = self.transactions.iter_mut().find(|t| t.id == tx_id) {
            tx.logged = true;
        }
    }

    /// Garbage collect completed + logged transactions
    pub fn gc(&mut self) {
        self.transactions.retain(|tx| !tx.logged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_parse_request() {
        let mut state = S7commState::new();

        // PLC Stop request (TPKT length = 0x13 = 19 bytes total)
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x13, // TPKT: length 19
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, // S7: Job
            0x00, 0x01, 0x00, 0x02, // pdu_ref=1, param_len=2
            0x00, 0x00, // data_len=0
            0x29, 0x00, // PLC Stop
        ];

        assert!(state.parse_request(data));
        assert_eq!(state.transactions.len(), 1);

        let tx = &state.transactions[0];
        assert_eq!(tx.request_function_code, Some(0x29));
        assert!(tx.is_dangerous);
        assert!(state.events.contains(&S7commEvent::PlcStop));
    }

    #[test]
    fn test_state_request_response_pair() {
        let mut state = S7commState::new();

        // Setup Communication request
        let request: &[u8] = &[
            0x03, 0x00, 0x00, 0x19, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, // S7: Job
            0x00, 0x01, 0x00, 0x08, // pdu_ref=1, param_len=8
            0x00, 0x00, // data_len=0
            0xF0, 0x00, 0x00, 0x01, // Setup Comm
            0x00, 0x01, 0x00, 0xF0,
        ];

        // Setup Communication response
        let response: &[u8] = &[
            0x03, 0x00, 0x00, 0x1B, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x03, 0x00, 0x00, // S7: AckData
            0x00, 0x01, 0x00, 0x08, // pdu_ref=1, param_len=8
            0x00, 0x00, // data_len=0
            0x00, 0x00, // error_class=0, error_code=0
            0xF0, 0x00, 0x00, 0x01, // Setup Comm response
            0x00, 0x01, 0x00, 0xF0,
        ];

        assert!(state.parse_request(request));
        assert!(state.parse_response(response));

        assert_eq!(state.transactions.len(), 1);
        let tx = &state.transactions[0];
        assert!(tx.complete);
        assert_eq!(tx.response_error_class, Some(0));
    }
}
