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

/// A single data item address specification (Read/Write Variable, S7ANY addressing)
#[derive(Debug, Clone, Default)]
pub struct S7DataItem {
    pub transport_size: u8,
    pub length: u16,
    pub db_number: u16,
    pub area: u8,
    /// Byte address (already shifted from bit address)
    pub byte_address: u32,
    pub bit_address: u8,
}

/// COTP connection info (from CR/CC parameters)
#[derive(Debug, Clone, Default)]
pub struct CotpConnectInfo {
    pub src_tsap: Option<u16>,
    pub dst_tsap: Option<u16>,
    /// Derived from destination TSAP low byte
    pub rack: Option<u8>,
    pub slot: Option<u8>,
}

/// S7comm-plus (v3) info
#[derive(Debug, Clone, Default)]
pub struct S7PlusInfo {
    pub version: u8,
    pub opcode: u8,
    pub function: u16,
}

/// Complete parsed S7comm PDU
#[derive(Debug, Clone)]
pub struct S7commPdu {
    pub cotp_type: u8,
    pub cotp_connect: Option<CotpConnectInfo>,
    pub s7_header: Option<S7commHeader>,
    pub s7_parameter: Option<S7commParameter>,
    pub s7_userdata: Option<S7commUserdataParam>,
    /// First data item from Read/Write Var requests
    pub data_item: Option<S7DataItem>,
    /// PLC control PI-service string (function 0x28)
    pub plc_control_service: Option<&'static str>,
    /// Userdata data payload return code (after userdata parameter)
    pub userdata_return_code: Option<u8>,
    pub is_s7comm_plus: bool,
    pub s7_plus: Option<S7PlusInfo>,
}

impl Default for S7commPdu {
    fn default() -> Self {
        Self {
            cotp_type: 0,
            cotp_connect: None,
            s7_header: None,
            s7_parameter: None,
            s7_userdata: None,
            data_item: None,
            plc_control_service: None,
            userdata_return_code: None,
            is_s7comm_plus: false,
            s7_plus: None,
        }
    }
}

/// Parse COTP CR/CC parameters to extract TSAPs (rack/slot).
/// `input` is the bytes after the COTP fixed header (dst_ref, src_ref, class).
fn parse_cotp_params(mut input: &[u8]) -> CotpConnectInfo {
    let mut info = CotpConnectInfo::default();
    // Parameters are TLV: param_code(1), param_len(1), value(param_len)
    while input.len() >= 2 {
        let code = input[0];
        let len = input[1] as usize;
        if input.len() < 2 + len {
            break;
        }
        let value = &input[2..2 + len];
        match code {
            COTP_PARAM_SRC_TSAP => {
                if len == 2 {
                    info.src_tsap = Some(u16::from_be_bytes([value[0], value[1]]));
                }
            }
            COTP_PARAM_DST_TSAP => {
                if len == 2 {
                    let tsap = u16::from_be_bytes([value[0], value[1]]);
                    info.dst_tsap = Some(tsap);
                    // Low byte encodes rack (high 3 bits) and slot (low 5 bits)
                    let low = (tsap & 0xff) as u8;
                    info.rack = Some(low >> 5);
                    info.slot = Some(low & 0x1f);
                }
            }
            _ => {}
        }
        input = &input[2 + len..];
    }
    info
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

/// Parse the first S7ANY data item from a Read/Write Var parameter body.
/// `data` is the parameter bytes after the function code (starts with item count).
fn parse_first_data_item(data: &[u8]) -> Option<S7DataItem> {
    if data.len() < 2 {
        return None;
    }
    let item_count = data[0];
    if item_count == 0 {
        return None;
    }
    let item = &data[1..];
    // S7ANY item: 0x12, len(0x0a), 0x10(syntax S7ANY), transport(1), length(2),
    // db(2), area(1), address(3)
    if item.len() < 12 {
        return None;
    }
    if item[0] != 0x12 || item[2] != 0x10 {
        // Not S7ANY addressing (could be symbolic/other); skip detailed parse
        return None;
    }
    let transport_size = item[3];
    let length = u16::from_be_bytes([item[4], item[5]]);
    let db_number = u16::from_be_bytes([item[6], item[7]]);
    let area = item[8];
    let addr_raw = ((item[9] as u32) << 16) | ((item[10] as u32) << 8) | (item[11] as u32);
    let byte_address = addr_raw >> 3;
    let bit_address = (addr_raw & 0x07) as u8;
    Some(S7DataItem {
        transport_size,
        length,
        db_number,
        area,
        byte_address,
        bit_address,
    })
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

/// Parse the S7comm-plus (v3) header for opcode and function.
/// `input` starts at the protocol id byte (0x72).
fn parse_s7plus(input: &[u8]) -> Option<S7PlusInfo> {
    // 0x72, version(1), datalen(2), then opcode(1), reserved(2), function(2)...
    if input.len() < 10 {
        return None;
    }
    let version = input[1];
    // data starts at offset 4
    let opcode = input[4];
    // function is at offset 7..9 (after opcode(1) + reserved(2))
    let function = u16::from_be_bytes([input[7], input[8]]);
    Some(S7PlusInfo {
        version,
        opcode,
        function,
    })
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

    // For CR/CC, extract TSAP params. COTP CR/CC fixed part after type:
    // dst_ref(2), src_ref(2), class(1) = 5 bytes, then variable params.
    if cotp_type == COTP_CR || cotp_type == COTP_CC {
        let hdr_remaining = cotp_length.saturating_sub(1) as usize;
        let (input, cotp_body) = take(hdr_remaining)(input)?;
        let mut pdu = S7commPdu {
            cotp_type,
            ..Default::default()
        };
        // Skip dst_ref(2) + src_ref(2) + class(1) = 5 bytes to reach params
        if cotp_body.len() > 5 {
            pdu.cotp_connect = Some(parse_cotp_params(&cotp_body[5..]));
        }
        return Ok((input, pdu));
    }

    let cotp_remaining = cotp_length.saturating_sub(1);
    let (input, _) = take(cotp_remaining as usize)(input)?;

    // If not a DT PDU, return without S7 payload
    if cotp_type != COTP_DT {
        return Ok((
            input,
            S7commPdu {
                cotp_type,
                ..Default::default()
            },
        ));
    }

    if input.is_empty() {
        return Ok((
            input,
            S7commPdu {
                cotp_type,
                ..Default::default()
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
                ..Default::default()
            },
        ));
    }

    if is_s7comm_plus {
        let s7_plus = parse_s7plus(input);
        return Ok((
            &[],
            S7commPdu {
                cotp_type,
                is_s7comm_plus: true,
                s7_plus,
                ..Default::default()
            },
        ));
    }

    let (input, s7_header) = parse_s7comm_header(input)?;

    let mut data_item = None;
    let mut plc_ctrl_service = None;

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
        // Extract data item for Read/Write Var requests (Job)
        if s7_header.rosctr == 0x01
            && (param.function_code == 0x04 || param.function_code == 0x05)
        {
            data_item = parse_first_data_item(&param.data);
        }
        // Extract PLC control service string for function 0x28
        if param.function_code == 0x28 {
            plc_ctrl_service = Some(plc_control_service(&param.data));
        }
        (input, Some(param), None)
    } else {
        (input, None, None)
    };

    // Read userdata return code (first byte of data section for userdata)
    let mut userdata_return_code = None;
    if s7_userdata.is_some() && !input.is_empty() {
        userdata_return_code = Some(input[0]);
    }

    let (input, _) = take(s7_header.data_length as usize)(input)?;

    Ok((
        input,
        S7commPdu {
            cotp_type,
            cotp_connect: None,
            s7_header: Some(s7_header),
            s7_parameter,
            s7_userdata,
            data_item,
            plc_control_service: plc_ctrl_service,
            userdata_return_code,
            is_s7comm_plus,
            s7_plus: None,
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
