// S7comm protocol parser using nom
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use nom7::bytes::complete::take;
use nom7::number::complete::{be_u16, be_u8};
use nom7::IResult;

use crate::consts::*;
use crate::cotp::*;

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

/// S7comm-plus (v3) info
#[derive(Debug, Clone, Default)]
pub struct S7PlusInfo {
    pub version: u8,
    pub data_length: u16,
    pub opcode: u8,
    pub function: u16,
    pub sequence_number: u16,
    pub has_function: bool,
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
    /// Total number of data items declared in a Read/Write Var request
    pub item_count: u8,
    /// PLC control PI-service string (function 0x28)
    pub plc_control_service: Option<&'static str>,
    /// Userdata data payload return code (after userdata parameter)
    pub userdata_return_code: Option<u8>,
    /// ROSCTR value was outside the known set (1,2,3,7)
    pub invalid_rosctr: bool,
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
            item_count: 0,
            plc_control_service: None,
            userdata_return_code: None,
            invalid_rosctr: false,
            is_s7comm_plus: false,
            s7_plus: None,
        }
    }
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

/// Parse S7ANY data items from a Read/Write Var parameter body.
/// `data` is the parameter bytes after the function code (starts with item count).
/// Returns (declared_item_count, first_parsed_item).
fn parse_data_items(data: &[u8]) -> (u8, Option<S7DataItem>) {
    if data.is_empty() {
        return (0, None);
    }
    let item_count = data[0];
    if item_count == 0 || data.len() < 2 {
        return (item_count, None);
    }

    let mut first: Option<S7DataItem> = None;
    let mut cursor = &data[1..];

    // Iterate through up to item_count items, capturing the first S7ANY item.
    for _ in 0..item_count {
        if cursor.len() < 2 {
            break;
        }
        // Every item begins with spec type (0x12) + spec length byte.
        if cursor[0] != 0x12 {
            break;
        }
        let spec_len = cursor[1] as usize;
        // Full item = 0x12 + len byte + spec_len bytes of spec.
        let item_total = 2 + spec_len;
        if cursor.len() < item_total {
            break;
        }
        let item = &cursor[..item_total];
        // S7ANY addressing: syntax id (item[2]) == 0x10 and spec_len == 0x0a
        if spec_len >= 10 && item[2] == 0x10 && item.len() >= 12 {
            let transport_size = item[3];
            let length = u16::from_be_bytes([item[4], item[5]]);
            let db_number = u16::from_be_bytes([item[6], item[7]]);
            let area = item[8];
            let addr_raw =
                ((item[9] as u32) << 16) | ((item[10] as u32) << 8) | (item[11] as u32);
            let byte_address = addr_raw >> 3;
            let bit_address = (addr_raw & 0x07) as u8;
            if first.is_none() {
                first = Some(S7DataItem {
                    transport_size,
                    length,
                    db_number,
                    area,
                    byte_address,
                    bit_address,
                });
                // We only need the first item for detection; stop early.
                break;
            }
        }
        cursor = &cursor[item_total..];
    }
    (item_count, first)
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
    // Layout: 0x72, version(1), data_length(2), then a data area whose shape
    // depends on the opcode:
    //   opcode(1), reserved(2), function(2), reserved(2), seqnum(2), ...
    if input.len() < 5 {
        return None;
    }
    let version = input[1];
    let data_length = u16::from_be_bytes([input[2], input[3]]);
    let opcode = input[4];

    let mut info = S7PlusInfo {
        version,
        data_length,
        opcode,
        function: 0,
        sequence_number: 0,
        has_function: false,
    };

    // Request (0x31) and Response (0x32) carry a function code + sequence number.
    // Notification (0x33) has a different layout, so only decode the known ones.
    if (opcode == 0x31 || opcode == 0x32) && input.len() >= 13 {
        info.function = u16::from_be_bytes([input[7], input[8]]);
        info.sequence_number = u16::from_be_bytes([input[11], input[12]]);
        info.has_function = true;
    }

    Some(info)
}

/// Parse a complete S7comm PDU (TPKT + COTP + S7comm)
pub(crate) fn parse_s7comm_pdu(input: &[u8]) -> IResult<&[u8], S7commPdu> {
    let (rem, cotp) = parse_tpkt_cotp(input)?;
    let cotp_type = cotp.pdu_type;

    if cotp_type == COTP_CR || cotp_type == COTP_CC {
        return Ok((
            rem,
            S7commPdu {
                cotp_type,
                cotp_connect: cotp.connect,
                ..Default::default()
            },
        ));
    }

    let input = cotp.payload;
    let payload_kind = if cotp_type == COTP_DT {
        classify_payload(input)
    } else {
        Iso102Payload::Unknown
    };

    match payload_kind {
        Iso102Payload::S7comm => {}
        Iso102Payload::S7commPlus => {
            return Ok((
                rem,
                S7commPdu {
                    cotp_type,
                    is_s7comm_plus: true,
                    s7_plus: parse_s7plus(input),
                    ..Default::default()
                },
            ));
        }
        _ => {
            return Ok((
                rem,
                S7commPdu {
                    cotp_type,
                    ..Default::default()
                },
            ));
        }
    }

    let (input, s7_header) = parse_s7comm_header(input)?;

    // Flag ROSCTR values outside the known set (Job/Ack/AckData/Userdata).
    let invalid_rosctr = !matches!(s7_header.rosctr, 0x01 | 0x02 | 0x03 | 0x07);

    let mut data_item = None;
    let mut item_count = 0u8;
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
        // Extract data items for Read/Write Var requests (Job)
        if s7_header.rosctr == 0x01
            && (param.function_code == 0x04 || param.function_code == 0x05)
        {
            let (count, first) = parse_data_items(&param.data);
            item_count = count;
            data_item = first;
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
            item_count,
            plc_control_service: plc_ctrl_service,
            userdata_return_code,
            invalid_rosctr,
            is_s7comm_plus: false,
            s7_plus: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plc_stop() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x13, // TPKT len 19
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, // S7 Job header
            0x29, 0x00, // PLC Stop
        ];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        let hdr = pdu.s7_header.expect("header");
        assert_eq!(hdr.rosctr, 0x01);
        assert_eq!(pdu.s7_parameter.unwrap().function_code, 0x29);
        assert!(!pdu.invalid_rosctr);
    }

    #[test]
    fn test_parse_read_var_item() {
        // Read Var, one S7ANY item: DB1, byte area 0x84, length 64
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x1f, // TPKT len 31
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x00, // S7 Job, param_len 14
            0x04, 0x01, // function Read Var, item count 1
            0x12, 0x0a, 0x10, 0x02, 0x00, 0x40, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00, // item
        ];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        assert_eq!(pdu.item_count, 1);
        let item = pdu.data_item.expect("data item");
        assert_eq!(item.area, 0x84);
        assert_eq!(item.db_number, 1);
        assert_eq!(item.length, 64);
        assert_eq!(item.byte_address, 0);
    }

    #[test]
    fn test_parse_write_var_two_items() {
        // Write Var with two S7ANY items; first is Flags(M) length 4
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x2b, // TPKT len 43
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1a, 0x00, 0x00, // param_len 26
            0x05, 0x02, // Write Var, item count 2
            0x12, 0x0a, 0x10, 0x02, 0x00, 0x04, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00, // item 1 (M)
            0x12, 0x0a, 0x10, 0x02, 0x00, 0x02, 0x00, 0x01, 0x84, 0x00, 0x00, 0x08, // item 2 (DB1)
        ];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        assert_eq!(pdu.item_count, 2);
        let item = pdu.data_item.expect("first item");
        assert_eq!(item.area, 0x83);
        assert_eq!(item.length, 4);
    }

    #[test]
    fn test_parse_cotp_cr_tsap() {
        // COTP Connection Request with src/dst TSAP params (rack 0, slot 2)
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x16, // TPKT len 22
            0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, // COTP CR fixed part
            0xc0, 0x01, 0x0a, // tpdu size param
            0xc1, 0x02, 0x01, 0x00, // src tsap 0x0100
            0xc2, 0x02, 0x01, 0x02, // dst tsap 0x0102
        ];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        assert_eq!(pdu.cotp_type, COTP_CR);
        let conn = pdu.cotp_connect.expect("cotp connect");
        assert_eq!(conn.src_tsap, Some(0x0100));
        assert_eq!(conn.dst_tsap, Some(0x0102));
        assert_eq!(conn.rack, Some(0));
        assert_eq!(conn.slot, Some(2));
    }

    #[test]
    fn test_parse_s7comm_plus() {
        // S7comm-plus request, SetVariable (0x04f2), seqnum 5
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x14, // TPKT len 20
            0x02, 0xF0, 0x80, // COTP DT
            0x72, 0x01, 0x00, 0x1a, 0x31, 0x00, 0x00, 0x04, 0xf2, 0x00, 0x00, 0x00,
            0x05, // s7comm-plus (13 bytes)
        ];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        assert!(pdu.is_s7comm_plus);
        let sp = pdu.s7_plus.expect("s7 plus info");
        assert_eq!(sp.opcode, 0x31);
        assert!(sp.has_function);
        assert_eq!(sp.function, 0x04f2);
        assert_eq!(sp.sequence_number, 5);
    }

    #[test]
    fn test_non_s7_dt_payload_ignored() {
        // COTP DT carrying an ISO session CONNECT SPDU (MMS), not S7
        let data: &[u8] = &[0x03, 0x00, 0x00, 0x0c, 0x02, 0xF0, 0x80, 0x0d, 0xb2, 0x05, 0x06, 0x13];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        assert_eq!(pdu.cotp_type, COTP_DT);
        assert!(pdu.s7_header.is_none());
        assert!(!pdu.is_s7comm_plus);
    }

    #[test]
    fn test_invalid_rosctr_flag() {
        // ROSCTR 0x99 is not a known value
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x11, 0x02, 0xF0, 0x80, 0x32, 0x99, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
        ];
        let (_, pdu) = parse_s7comm_pdu(data).unwrap();
        assert!(pdu.invalid_rosctr);
    }

    #[test]
    fn test_malformed_does_not_panic() {
        // Truncated / random inputs must never panic, only Err or Ok.
        let cases: &[&[u8]] = &[
            &[],
            &[0x03],
            &[0x03, 0x00, 0x00, 0xff, 0x02, 0xF0, 0x80],
            &[0x03, 0x00, 0x00, 0x0a, 0x02, 0xF0, 0x80, 0x32, 0x01],
            &[0xff; 32],
        ];
        for c in cases {
            let _ = parse_s7comm_pdu(c);
        }
    }

    #[test]
    fn test_data_items_empty() {
        assert_eq!(parse_data_items(&[]).0, 0);
        assert!(parse_data_items(&[]).1.is_none());
        assert_eq!(parse_data_items(&[0x00]).0, 0);
    }
}

