// S7comm protocol parser using nom
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use nom7::bytes::complete::take;
use nom7::number::complete::{be_u16, be_u8};
use nom7::IResult;

use crate::consts::*;

/// S7comm Header
#[derive(Debug, Clone)]
pub struct S7commHeader {
    pub protocol_id: u8,
    pub rosctr: u8,
    pub redundancy_id: u16,
    pub pdu_reference: u16,
    pub parameter_length: u16,
    pub data_length: u16,
    pub error_class: Option<u8>,
    pub error_code: Option<u8>,
}

/// S7comm Parameter
#[derive(Debug, Clone)]
pub struct S7commParameter {
    pub function_code: u8,
    pub data: Vec<u8>,
}

/// S7comm Userdata parameter
#[derive(Debug, Clone)]
pub struct S7commUserdataParam {
    pub param_head: [u8; 3],
    pub param_length: u8,
    pub method: u8,
    pub function_type: u8,
    pub subfunction: u8,
    pub sequence_number: u8,
}

/// Complete parsed S7comm PDU
#[derive(Debug, Clone)]
pub struct S7commPdu {
    pub cotp_type: u8,
    pub s7_header: Option<S7commHeader>,
    pub s7_parameter: Option<S7commParameter>,
    pub s7_userdata: Option<S7commUserdataParam>,
    pub is_s7comm_plus: bool,
}

/// Parse S7comm header (10 or 12 bytes depending on ROSCTR)
fn parse_s7comm_header(input: &[u8]) -> IResult<&[u8], S7commHeader> {
    let (input, protocol_id) = be_u8(input)?;
    let (input, rosctr) = be_u8(input)?;
    let (input, redundancy_id) = be_u16(input)?;
    let (input, pdu_reference) = be_u16(input)?;
    let (input, parameter_length) = be_u16(input)?;
    let (input, data_length) = be_u16(input)?;

    let (input, error_class, error_code) = if rosctr == 0x02 || rosctr == 0x03 {
        let (input, ec) = be_u8(input)?;
        let (input, code) = be_u8(input)?;
        (input, Some(ec), Some(code))
    } else {
        (input, None, None)
    };

    Ok((
        input,
        S7commHeader {
            protocol_id,
            rosctr,
            redundancy_id,
            pdu_reference,
            parameter_length,
            data_length,
            error_class,
            error_code,
        },
    ))
}

/// Parse S7comm parameter (function code + raw data)
fn parse_s7comm_parameter(input: &[u8], length: u16) -> IResult<&[u8], S7commParameter> {
    if length == 0 {
        return Ok((input, S7commParameter { function_code: 0, data: vec![] }));
    }
    let (input, function_code) = be_u8(input)?;
    let remaining = (length as usize).saturating_sub(1);
    let (input, data) = take(remaining)(input)?;
    Ok((
        input,
        S7commParameter {
            function_code,
            data: data.to_vec(),
        },
    ))
}

/// Parse S7comm Userdata parameter header
fn parse_s7comm_userdata_param(input: &[u8]) -> IResult<&[u8], S7commUserdataParam> {
    let (input, h0) = be_u8(input)?;
    let (input, h1) = be_u8(input)?;
    let (input, h2) = be_u8(input)?;
    let (input, param_length) = be_u8(input)?;
    let (input, method) = be_u8(input)?;
    let (input, function_type) = be_u8(input)?;
    let (input, subfunction) = be_u8(input)?;
    let (input, sequence_number) = be_u8(input)?;
    Ok((
        input,
        S7commUserdataParam {
            param_head: [h0, h1, h2],
            param_length,
            method,
            function_type,
            subfunction,
            sequence_number,
        },
    ))
}

/// Parse a complete S7comm PDU (TPKT + COTP + S7comm)
pub(crate) fn parse_s7comm_pdu(input: &[u8]) -> IResult<&[u8], S7commPdu> {
    // Parse TPKT header
    let (input, _version) = be_u8(input)?;
    let (input, _reserved) = be_u8(input)?;
    let (input, _tpkt_length) = be_u16(input)?;

    // Parse COTP
    let (input, cotp_length) = be_u8(input)?;
    let (input, cotp_type_raw) = be_u8(input)?;
    let cotp_type = cotp_type_raw & 0xF0;

    let cotp_remaining = cotp_length.saturating_sub(1);
    let (input, _) = take(cotp_remaining as usize)(input)?;

    // If not a DT PDU, return without S7 payload
    if cotp_type != COTP_DT {
        return Ok((
            input,
            S7commPdu {
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: false,
            },
        ));
    }

    if input.is_empty() {
        return Ok((
            input,
            S7commPdu {
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: false,
            },
        ));
    }

    let protocol_id = input[0];
    let is_s7comm_plus = protocol_id == S7COMM_PLUS_PROTOCOL_ID;

    if protocol_id != S7COMM_PROTOCOL_ID && !is_s7comm_plus {
        return Ok((
            input,
            S7commPdu {
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: false,
            },
        ));
    }

    if is_s7comm_plus {
        return Ok((
            &[],
            S7commPdu {
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: true,
            },
        ));
    }

    let (input, s7_header) = parse_s7comm_header(input)?;

    let (input, s7_parameter, s7_userdata) = if s7_header.rosctr == 0x07 {
        if s7_header.parameter_length >= 8 {
            let (input, ud) = parse_s7comm_userdata_param(input)?;
            let skip = (s7_header.parameter_length as usize).saturating_sub(8);
            let (input, _) = take(skip)(input)?;
            (input, None, Some(ud))
        } else {
            let (input, _) = take(s7_header.parameter_length as usize)(input)?;
            (input, None, None)
        }
    } else if s7_header.parameter_length > 0 {
        let (input, param) = parse_s7comm_parameter(input, s7_header.parameter_length)?;
        (input, Some(param), None)
    } else {
        (input, None, None)
    };

    let (input, _) = take(s7_header.data_length as usize)(input)?;

    Ok((
        input,
        S7commPdu {
            cotp_type,
            s7_header: Some(s7_header),
            s7_parameter,
            s7_userdata,
            is_s7comm_plus,
        },
    ))
}

/// Probe function: check if traffic looks like S7comm (TPKT on port 102)
pub(crate) fn probe_s7comm(input: &[u8]) -> bool {
    if input.len() < 7 {
        return false;
    }
    if input[0] != TPKT_VERSION {
        return false;
    }
    let tpkt_len = u16::from_be_bytes([input[2], input[3]]);
    if tpkt_len < 7 || tpkt_len as usize > input.len() + 100 {
        return false;
    }
    let cotp_len = input[4] as usize;
    let s7_offset = 5 + cotp_len;
    if s7_offset < input.len() {
        let proto = input[s7_offset];
        return proto == S7COMM_PROTOCOL_ID || proto == S7COMM_PLUS_PROTOCOL_ID;
    }
    let cotp_type = input[5] & 0xF0;
    cotp_type == COTP_CR || cotp_type == COTP_CC
}
