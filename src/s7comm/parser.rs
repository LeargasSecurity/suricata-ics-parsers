// S7comm protocol parser using nom
// Copyright (C) 2026 Critical Path Security
// License: GPL-2.0

use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

use crate::s7comm::consts::*;

/// TPKT Header (RFC 1006) - 4 bytes
#[derive(Debug, Clone)]
pub struct TpktHeader {
    pub version: u8,
    pub reserved: u8,
    pub length: u16,
}

/// COTP Header (ISO 8073)
#[derive(Debug, Clone)]
pub struct CotpHeader {
    pub length: u8,
    pub pdu_type: u8,
    pub destination_ref: u16,
    pub source_ref: u16,
    pub class_option: u8,
}

/// COTP Data Transfer header (minimal for DT PDUs)
#[derive(Debug, Clone)]
pub struct CotpDataHeader {
    pub length: u8,
    pub pdu_type: u8,
    pub tpdu_number: u8, // includes EOT bit
}

/// S7comm Header
#[derive(Debug, Clone)]
pub struct S7commHeader {
    pub protocol_id: u8,
    pub rosctr: u8,
    pub redundancy_id: u16,
    pub pdu_reference: u16,
    pub parameter_length: u16,
    pub data_length: u16,
    /// Only present in Ack/AckData
    pub error_class: Option<u8>,
    pub error_code: Option<u8>,
}

/// S7comm Parameter (for Job/AckData with function code)
#[derive(Debug, Clone)]
pub struct S7commParameter {
    pub function_code: u8,
    /// Raw parameter data after function code
    pub data: Vec<u8>,
}

/// S7comm Userdata parameter
#[derive(Debug, Clone)]
pub struct S7commUserdataParam {
    pub param_head: [u8; 3], // always 0x00 0x01 0x12
    pub param_length: u8,
    pub method: u8,           // 0x11 = request, 0x12 = response
    pub function_type: u8,    // upper nibble = type, lower nibble = function group
    pub subfunction: u8,
    pub sequence_number: u8,
}

/// Complete parsed S7comm PDU
#[derive(Debug, Clone)]
pub struct S7commPdu {
    pub tpkt: TpktHeader,
    pub cotp_type: u8,
    pub s7_header: Option<S7commHeader>,
    pub s7_parameter: Option<S7commParameter>,
    pub s7_userdata: Option<S7commUserdataParam>,
    pub is_s7comm_plus: bool,
}

/// Parse TPKT header (4 bytes)
pub fn parse_tpkt(input: &[u8]) -> IResult<&[u8], TpktHeader> {
    let (input, version) = be_u8(input)?;
    let (input, reserved) = be_u8(input)?;
    let (input, length) = be_u16(input)?;
    Ok((
        input,
        TpktHeader {
            version,
            reserved,
            length,
        },
    ))
}

/// Parse COTP Connection Request/Confirm (variable length)
pub fn parse_cotp_cr_cc(input: &[u8]) -> IResult<&[u8], CotpHeader> {
    let (input, length) = be_u8(input)?;
    let (input, pdu_type) = be_u8(input)?;
    let (input, destination_ref) = be_u16(input)?;
    let (input, source_ref) = be_u16(input)?;
    let (input, class_option) = be_u8(input)?;
    // Skip remaining COTP parameters
    let remaining_len = length.saturating_sub(6);
    let (input, _) = take(remaining_len as usize)(input)?;
    Ok((
        input,
        CotpHeader {
            length,
            pdu_type,
            destination_ref,
            source_ref,
            class_option,
        },
    ))
}

/// Parse COTP Data Transfer header (3 bytes: length=0x02, type=0xF0, tpdu_nr)
pub fn parse_cotp_dt(input: &[u8]) -> IResult<&[u8], CotpDataHeader> {
    let (input, length) = be_u8(input)?;
    let (input, pdu_type) = be_u8(input)?;
    let (input, tpdu_number) = be_u8(input)?;
    Ok((
        input,
        CotpDataHeader {
            length,
            pdu_type,
            tpdu_number,
        },
    ))
}

/// Parse S7comm header (10 or 12 bytes depending on ROSCTR)
pub fn parse_s7comm_header(input: &[u8]) -> IResult<&[u8], S7commHeader> {
    let (input, protocol_id) = be_u8(input)?;
    let (input, rosctr) = be_u8(input)?;
    let (input, redundancy_id) = be_u16(input)?;
    let (input, pdu_reference) = be_u16(input)?;
    let (input, parameter_length) = be_u16(input)?;
    let (input, data_length) = be_u16(input)?;

    // Ack and AckData have 2 extra bytes: error_class + error_code
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
pub fn parse_s7comm_parameter(input: &[u8], length: u16) -> IResult<&[u8], S7commParameter> {
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
pub fn parse_s7comm_userdata_param(input: &[u8]) -> IResult<&[u8], S7commUserdataParam> {
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
pub fn parse_s7comm_pdu(input: &[u8]) -> IResult<&[u8], S7commPdu> {
    let (input, tpkt) = parse_tpkt(input)?;

    // Validate TPKT
    if tpkt.version != TPKT_VERSION {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    // Parse COTP
    let (input, cotp_length) = be_u8(input)?;
    let (input, cotp_type_raw) = be_u8(input)?;
    let cotp_type = cotp_type_raw & 0xF0;

    // Skip remaining COTP bytes
    let cotp_remaining = cotp_length.saturating_sub(1);
    let (input, _) = take(cotp_remaining as usize)(input)?;

    // If not a DT PDU, return without S7 payload
    if cotp_type != COTP_DT {
        return Ok((
            input,
            S7commPdu {
                tpkt,
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: false,
            },
        ));
    }

    // Check if we have S7comm payload
    if input.is_empty() {
        return Ok((
            input,
            S7commPdu {
                tpkt,
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: false,
            },
        ));
    }

    // Check protocol ID
    let protocol_id = input[0];
    let is_s7comm_plus = protocol_id == S7COMM_PLUS_PROTOCOL_ID;

    if protocol_id != S7COMM_PROTOCOL_ID && !is_s7comm_plus {
        return Ok((
            input,
            S7commPdu {
                tpkt,
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: false,
            },
        ));
    }

    // S7comm-plus: just flag it, don't deep-parse (proprietary)
    if is_s7comm_plus {
        return Ok((
            &[],
            S7commPdu {
                tpkt,
                cotp_type,
                s7_header: None,
                s7_parameter: None,
                s7_userdata: None,
                is_s7comm_plus: true,
            },
        ));
    }

    // Parse S7comm header
    let (input, s7_header) = parse_s7comm_header(input)?;

    // Parse parameter based on ROSCTR
    let (input, s7_parameter, s7_userdata) = if s7_header.rosctr == 0x07 {
        // Userdata
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

    // Skip data section
    let (input, _) = take(s7_header.data_length as usize)(input)?;

    Ok((
        input,
        S7commPdu {
            tpkt,
            cotp_type,
            s7_header: Some(s7_header),
            s7_parameter,
            s7_userdata,
            is_s7comm_plus,
        },
    ))
}

/// Probe function: check if traffic looks like S7comm (TPKT on port 102)
pub fn probe_s7comm(input: &[u8]) -> bool {
    if input.len() < 7 {
        return false;
    }
    // TPKT version 3
    if input[0] != TPKT_VERSION {
        return false;
    }
    // TPKT length should be reasonable
    let tpkt_len = u16::from_be_bytes([input[2], input[3]]);
    if tpkt_len < 7 || tpkt_len as usize > input.len() + 100 {
        return false;
    }
    // After COTP header, check for S7comm protocol ID
    let cotp_len = input[4] as usize;
    let s7_offset = 5 + cotp_len;
    if s7_offset < input.len() {
        let proto = input[s7_offset];
        return proto == S7COMM_PROTOCOL_ID || proto == S7COMM_PLUS_PROTOCOL_ID;
    }
    // Could be a COTP CR/CC without S7 payload — still valid
    let cotp_type = input[5] & 0xF0;
    cotp_type == COTP_CR || cotp_type == COTP_CC || cotp_type == COTP_DT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_s7comm() {
        // TPKT + COTP DT + S7comm Setup Communication
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x19, // TPKT: version 3, length 25
            0x02, 0xF0, 0x80, // COTP: DT, EOT
            0x32, 0x01, 0x00, 0x00, // S7: protocol_id=0x32, rosctr=Job
            0x00, 0x00, 0x00, 0x08, // pdu_ref=0, param_len=8
            0x00, 0x00, // data_len=0
            0xF0, 0x00, 0x00, 0x01, // param: Setup Comm, reserved, max_amq_calling=1
            0x00, 0x01, 0x00, 0xF0, // max_amq_called=1, pdu_length=240
        ];
        assert!(probe_s7comm(data));
    }

    #[test]
    fn test_parse_setup_communication() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x19, // TPKT
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, // S7comm header start
            0x00, 0x00, 0x00, 0x08, // pdu_ref, param_len=8
            0x00, 0x00, // data_len=0
            0xF0, 0x00, 0x00, 0x01, // Setup Comm
            0x00, 0x01, 0x00, 0xF0, // params
        ];
        let result = parse_s7comm_pdu(data);
        assert!(result.is_ok());
        let (_, pdu) = result.unwrap();
        assert_eq!(pdu.cotp_type, COTP_DT);
        assert!(!pdu.is_s7comm_plus);
        let hdr = pdu.s7_header.unwrap();
        assert_eq!(hdr.protocol_id, S7COMM_PROTOCOL_ID);
        assert_eq!(hdr.rosctr, 0x01); // Job
        let param = pdu.s7_parameter.unwrap();
        assert_eq!(param.function_code, 0xF0); // Setup Communication
    }

    #[test]
    fn test_parse_plc_stop() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x15, // TPKT: length 21
            0x02, 0xF0, 0x80, // COTP DT
            0x32, 0x01, 0x00, 0x00, // S7: Job
            0x00, 0x01, 0x00, 0x02, // pdu_ref=1, param_len=2
            0x00, 0x00, // data_len=0
            0x29, 0x00, // PLC Stop
        ];
        let result = parse_s7comm_pdu(data);
        assert!(result.is_ok());
        let (_, pdu) = result.unwrap();
        let param = pdu.s7_parameter.unwrap();
        assert_eq!(param.function_code, 0x29);
        let fc = S7Function::from_u8(param.function_code).unwrap();
        assert!(fc.is_dangerous());
        assert_eq!(fc.as_str(), "PLC Stop");
    }

    #[test]
    fn test_probe_non_s7comm() {
        let http = b"GET / HTTP/1.1\r\n";
        assert!(!probe_s7comm(http));
    }
}
