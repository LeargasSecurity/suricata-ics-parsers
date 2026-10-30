// ISO transport (RFC 1006 TPKT + ISO 8073 COTP) shared by the TCP/102 protocols
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use nom7::bytes::complete::take;
use nom7::number::complete::{be_u16, be_u8};
use nom7::IResult;

use crate::consts::{S7COMM_PLUS_PROTOCOL_ID, S7COMM_PROTOCOL_ID};

pub const TPKT_VERSION: u8 = 0x03;
pub const TPKT_HEADER_LEN: usize = 4;
/// TPKT header + COTP length indicator + PDU type + at least one more byte.
pub const TPKT_MIN_LEN: usize = 7;

/// COTP PDU types (high nibble of the type byte)
pub const COTP_CR: u8 = 0xE0; // Connection Request
pub const COTP_CC: u8 = 0xD0; // Connection Confirm
pub const COTP_DR: u8 = 0x80; // Disconnect Request
pub const COTP_DC: u8 = 0xC0; // Disconnect Confirm
pub const COTP_DT: u8 = 0xF0; // Data Transfer
pub const COTP_ED: u8 = 0x10; // Expedited Data
pub const COTP_AK: u8 = 0x60; // Data Acknowledgement
pub const COTP_EA: u8 = 0x20; // Expedited Data Acknowledgement
pub const COTP_RJ: u8 = 0x50; // Reject
pub const COTP_ER: u8 = 0x70; // TPDU Error

/// COTP parameter codes (in CR/CC PDUs)
pub const COTP_PARAM_SRC_TSAP: u8 = 0xC1;
pub const COTP_PARAM_DST_TSAP: u8 = 0xC2;

fn is_cotp_type(t: u8) -> bool {
    matches!(
        t,
        COTP_CR
            | COTP_CC
            | COTP_DR
            | COTP_DC
            | COTP_DT
            | COTP_ED
            | COTP_AK
            | COTP_EA
            | COTP_RJ
            | COTP_ER
    )
}

/// COTP connection info (from CR/CC parameters)
#[derive(Debug, Clone, Default)]
pub struct CotpConnectInfo {
    pub src_tsap: Option<u16>,
    pub dst_tsap: Option<u16>,
    /// S7 addressing, derived from the destination TSAP low byte
    pub rack: Option<u8>,
    pub slot: Option<u8>,
}

/// One TPKT frame decoded down to the COTP user data.
#[derive(Debug)]
pub struct CotpPdu<'a> {
    pub pdu_type: u8,
    pub connect: Option<CotpConnectInfo>,
    /// DT only: end-of-TSDU flag. False means the message continues in the next DT.
    pub eot: bool,
    pub payload: &'a [u8],
}

/// Result of feeding one COTP DT to a [`CotpReassembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum DtAssembly {
    /// A complete TSDU (one upper-layer message).
    Complete(Vec<u8>),
    /// More DTs are needed.
    Partial,
    /// The message exceeded the size limit and is being discarded up to its last DT.
    Overflow,
}

/// Joins COTP DT segments into complete TSDUs, for one direction of a connection.
#[derive(Debug, Default)]
pub struct CotpReassembler {
    buf: Vec<u8>,
    discarding: bool,
}

impl CotpReassembler {
    /// Add one DT payload. `max_len` bounds the reassembled message size.
    pub fn push(&mut self, data: &[u8], eot: bool, max_len: usize) -> DtAssembly {
        if self.discarding {
            if eot {
                self.discarding = false;
            }
            return DtAssembly::Partial;
        }
        if self.buf.len() + data.len() > max_len {
            self.buf = Vec::new();
            self.discarding = !eot;
            return DtAssembly::Overflow;
        }
        if eot {
            if self.buf.is_empty() {
                return DtAssembly::Complete(data.to_vec());
            }
            self.buf.extend_from_slice(data);
            return DtAssembly::Complete(std::mem::take(&mut self.buf));
        }
        self.buf.extend_from_slice(data);
        DtAssembly::Partial
    }

    /// Drop any partial message (e.g. after a stream gap).
    pub fn reset(&mut self) {
        self.buf = Vec::new();
        self.discarding = false;
    }
}

/// Upper-layer protocol carried in a COTP DT on TCP/102.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iso102Payload {
    S7comm,
    S7commPlus,
    /// ISO 8327 session SPDU (MMS / IEC 61850 / ICCP with the full OSI stack)
    IsoSession,
    /// MMS PDU directly on COTP, without the session/presentation/ACSE layers
    /// (used by some MMS tools and scanners).
    MmsDirect,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iso102Probe {
    Detected(Iso102Payload),
    NeedMore,
    NotIso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpktFrame {
    Complete(usize),
    /// Total bytes needed from the start of the input (AppLayerResult "needed").
    Incomplete(usize),
    Invalid,
}

/// Size the next TPKT frame at the start of `input`.
pub fn tpkt_frame(input: &[u8], max_len: usize) -> TpktFrame {
    if input.len() < TPKT_HEADER_LEN {
        return TpktFrame::Incomplete(TPKT_HEADER_LEN);
    }
    if input[0] != TPKT_VERSION {
        return TpktFrame::Invalid;
    }
    let len = u16::from_be_bytes([input[2], input[3]]) as usize;
    if len < TPKT_MIN_LEN || len > max_len {
        return TpktFrame::Invalid;
    }
    if input.len() < len {
        return TpktFrame::Incomplete(len);
    }
    TpktFrame::Complete(len)
}

/// Parse COTP CR/CC variable parameters (TLV) following the fixed header.
fn parse_cotp_params(mut input: &[u8]) -> CotpConnectInfo {
    let mut info = CotpConnectInfo::default();
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

/// Parse one TPKT frame + COTP header. Returns bytes following the TPKT frame.
pub fn parse_tpkt_cotp(input: &[u8]) -> IResult<&[u8], CotpPdu<'_>> {
    let (input, _version) = be_u8(input)?;
    let (input, _reserved) = be_u8(input)?;
    let (input, tpkt_len) = be_u16(input)?;
    let (rem, frame) = take((tpkt_len as usize).saturating_sub(TPKT_HEADER_LEN))(input)?;

    let (frame, li) = be_u8(frame)?;
    let (payload, header) = take(li as usize)(frame)?;
    let (fixed, type_raw) = be_u8(header)?;
    let pdu_type = type_raw & 0xF0;

    // CR/CC fixed part: dst_ref(2) src_ref(2) class(1), then parameters.
    let connect = if (pdu_type == COTP_CR || pdu_type == COTP_CC) && fixed.len() > 5 {
        Some(parse_cotp_params(&fixed[5..]))
    } else {
        None
    };
    // DT fixed part: TPDU-NR with the EOT flag in the top bit (class 0/1).
    let eot = pdu_type != COTP_DT || fixed.first().map_or(true, |nr| nr & 0x80 != 0);

    Ok((
        rem,
        CotpPdu {
            pdu_type,
            connect,
            eot,
            payload,
        },
    ))
}

/// Identify the upper layer from the first bytes of a COTP DT payload.
pub fn classify_payload(payload: &[u8]) -> Iso102Payload {
    match payload.first() {
        Some(&S7COMM_PROTOCOL_ID) => Iso102Payload::S7comm,
        Some(&S7COMM_PLUS_PROTOCOL_ID) => Iso102Payload::S7commPlus,
        // ISO 8327 SPDU ids: GT/DT, NF, FN, DN, RF, CN, AC, AB, AA
        Some(&(0x01 | 0x08 | 0x09 | 0x0A | 0x0C | 0x0D | 0x0E | 0x19 | 0x1A)) => {
            Iso102Payload::IsoSession
        }
        // Reduced stack: a BER MMSpdu CHOICE tag ([0]..[13], context-specific;
        // primitive for cancel and conclude) directly on COTP.
        Some(&tag) if matches!(tag, 0xA0..=0xAD | 0x85 | 0x86 | 0x8B | 0x8C) => {
            Iso102Payload::MmsDirect
        }
        _ => Iso102Payload::Unknown,
    }
}

/// Walk TPKT frames past CR/CC to the first DT with data and classify it.
/// CR/CC alone is not enough: S7, MMS and ICCP all open with the same COTP handshake.
pub fn probe_iso102(mut input: &[u8]) -> Iso102Probe {
    loop {
        if input.is_empty() {
            return Iso102Probe::NeedMore;
        }
        if input[0] != TPKT_VERSION || (input.len() > 1 && input[1] != 0) {
            return Iso102Probe::NotIso;
        }
        if input.len() < TPKT_HEADER_LEN + 2 {
            return Iso102Probe::NeedMore;
        }
        let tpkt_len = u16::from_be_bytes([input[2], input[3]]) as usize;
        let li = input[4] as usize;
        let pdu_type = input[5] & 0xF0;
        let data_start = TPKT_HEADER_LEN + 1 + li;
        if tpkt_len < TPKT_MIN_LEN || li == 0 || data_start > tpkt_len || !is_cotp_type(pdu_type) {
            return Iso102Probe::NotIso;
        }

        if pdu_type == COTP_DT && data_start < tpkt_len {
            let end = tpkt_len.min(input.len());
            if data_start >= end {
                return Iso102Probe::NeedMore;
            }
            return Iso102Probe::Detected(classify_payload(&input[data_start..end]));
        }

        if input.len() < tpkt_len {
            return Iso102Probe::NeedMore;
        }
        input = &input[tpkt_len..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S7_CR: &[u8] = &[
        0x03, 0x00, 0x00, 0x16, // TPKT len 22
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, // COTP CR fixed part
        0xc0, 0x01, 0x0a, // tpdu size
        0xc1, 0x02, 0x01, 0x00, // src tsap 0x0100
        0xc2, 0x02, 0x01, 0x02, // dst tsap 0x0102
    ];

    const MMS_CR: &[u8] = &[
        0x03, 0x00, 0x00, 0x16, // TPKT len 22
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, // COTP CR fixed part
        0xc0, 0x01, 0x0d, // tpdu size
        0xc1, 0x02, 0x00, 0x01, // src tsap 0x0001
        0xc2, 0x02, 0x00, 0x01, // dst tsap 0x0001
    ];

    const S7_SETUP_DT: &[u8] = &[
        0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80, // TPKT + COTP DT
        0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, // S7 Job header
        0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0, // Setup Communication
    ];

    // DT carrying the start of an ISO session CONNECT SPDU
    const SESSION_CN_DT: &[u8] = &[
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xF0, 0x80, 0x0d, 0xb2, 0x05, 0x06, 0x13,
    ];

    fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut v = a.to_vec();
        v.extend_from_slice(b);
        v
    }

    #[test]
    fn test_tpkt_frame() {
        assert_eq!(tpkt_frame(&[0x03, 0x00], 1024), TpktFrame::Incomplete(4));
        assert_eq!(tpkt_frame(&S7_CR[..10], 1024), TpktFrame::Incomplete(22));
        assert_eq!(tpkt_frame(S7_CR, 1024), TpktFrame::Complete(22));
        assert_eq!(tpkt_frame(S7_CR, 16), TpktFrame::Invalid);
        assert_eq!(
            tpkt_frame(&[0x04, 0x00, 0x00, 0x16], 1024),
            TpktFrame::Invalid
        );
        assert_eq!(
            tpkt_frame(&[0x03, 0x00, 0x00, 0x05], 1024),
            TpktFrame::Invalid
        );
    }

    #[test]
    fn test_parse_cr_tsap() {
        let (rem, pdu) = parse_tpkt_cotp(S7_CR).unwrap();
        assert!(rem.is_empty());
        assert_eq!(pdu.pdu_type, COTP_CR);
        let conn = pdu.connect.expect("connect info");
        assert_eq!(conn.src_tsap, Some(0x0100));
        assert_eq!(conn.dst_tsap, Some(0x0102));
        assert_eq!(conn.rack, Some(0));
        assert_eq!(conn.slot, Some(2));
    }

    #[test]
    fn test_parse_dt_payload() {
        let (_, pdu) = parse_tpkt_cotp(S7_SETUP_DT).unwrap();
        assert_eq!(pdu.pdu_type, COTP_DT);
        assert!(pdu.connect.is_none());
        assert!(pdu.eot);
        assert_eq!(pdu.payload.len(), 18);
        assert_eq!(pdu.payload[0], S7COMM_PROTOCOL_ID);
    }

    #[test]
    fn test_parse_dt_eot_clear() {
        // DT with TPDU-NR 0 and EOT=0: the TSDU continues in the next DT.
        let dt = [0x03, 0x00, 0x00, 0x09, 0x02, 0xF0, 0x00, 0xAA, 0xBB];
        let (_, pdu) = parse_tpkt_cotp(&dt).unwrap();
        assert!(!pdu.eot);
        assert_eq!(pdu.payload, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_reassemble_segments() {
        let mut r = CotpReassembler::default();
        assert_eq!(r.push(&[1], true, 16), DtAssembly::Complete(vec![1]));
        assert_eq!(r.push(&[1, 2], false, 16), DtAssembly::Partial);
        assert_eq!(r.push(&[3], false, 16), DtAssembly::Partial);
        assert_eq!(
            r.push(&[4], true, 16),
            DtAssembly::Complete(vec![1, 2, 3, 4])
        );
        // Buffer is empty again afterwards.
        assert_eq!(r.push(&[9], true, 16), DtAssembly::Complete(vec![9]));
    }

    #[test]
    fn test_reassemble_overflow_discards_rest_of_message() {
        let mut r = CotpReassembler::default();
        assert_eq!(r.push(&[0; 8], false, 10), DtAssembly::Partial);
        assert_eq!(r.push(&[0; 8], false, 10), DtAssembly::Overflow);
        // Remaining segments of the oversized message are dropped, not parsed.
        assert_eq!(r.push(&[0; 8], false, 10), DtAssembly::Partial);
        assert_eq!(r.push(&[0; 2], true, 10), DtAssembly::Partial);
        // The next message is reassembled normally.
        assert_eq!(r.push(&[7], true, 10), DtAssembly::Complete(vec![7]));
    }

    #[test]
    fn test_reassemble_reset() {
        let mut r = CotpReassembler::default();
        assert_eq!(r.push(&[1, 2], false, 16), DtAssembly::Partial);
        r.reset();
        assert_eq!(r.push(&[3], true, 16), DtAssembly::Complete(vec![3]));
    }

    #[test]
    fn test_parse_bounded_by_tpkt_len() {
        let data = concat(S7_SETUP_DT, SESSION_CN_DT);
        let (rem, pdu) = parse_tpkt_cotp(&data).unwrap();
        assert_eq!(pdu.payload.len(), 18);
        assert_eq!(rem, SESSION_CN_DT);
    }

    #[test]
    fn test_probe_dt_only() {
        assert_eq!(
            probe_iso102(S7_SETUP_DT),
            Iso102Probe::Detected(Iso102Payload::S7comm)
        );
        assert_eq!(
            probe_iso102(SESSION_CN_DT),
            Iso102Probe::Detected(Iso102Payload::IsoSession)
        );
    }

    #[test]
    fn test_probe_cr_needs_dt() {
        assert_eq!(probe_iso102(S7_CR), Iso102Probe::NeedMore);
        assert_eq!(probe_iso102(MMS_CR), Iso102Probe::NeedMore);
        assert_eq!(probe_iso102(&S7_CR[..9]), Iso102Probe::NeedMore);
    }

    #[test]
    fn test_probe_cr_then_dt() {
        let s7 = concat(S7_CR, S7_SETUP_DT);
        assert_eq!(
            probe_iso102(&s7),
            Iso102Probe::Detected(Iso102Payload::S7comm)
        );
        let mms = concat(MMS_CR, SESSION_CN_DT);
        assert_eq!(
            probe_iso102(&mms),
            Iso102Probe::Detected(Iso102Payload::IsoSession)
        );
        // DT header present but no payload byte yet
        assert_eq!(probe_iso102(&s7[..S7_CR.len() + 7]), Iso102Probe::NeedMore);
    }

    #[test]
    fn test_probe_s7plus() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x0b, 0x02, 0xF0, 0x80, 0x72, 0x01, 0x00, 0x1a,
        ];
        assert_eq!(
            probe_iso102(data),
            Iso102Probe::Detected(Iso102Payload::S7commPlus)
        );
    }

    #[test]
    fn test_probe_not_iso() {
        assert_eq!(probe_iso102(&[0x04, 0x00, 0x00, 0x13]), Iso102Probe::NotIso);
        assert_eq!(probe_iso102(&[0x03, 0x01, 0x00, 0x13]), Iso102Probe::NotIso);
        // unknown COTP type nibble
        assert_eq!(
            probe_iso102(&[0x03, 0x00, 0x00, 0x13, 0x02, 0x30, 0x80]),
            Iso102Probe::NotIso
        );
        // LI runs past the TPKT frame
        assert_eq!(
            probe_iso102(&[0x03, 0x00, 0x00, 0x07, 0x09, 0xF0, 0x80]),
            Iso102Probe::NotIso
        );
        assert_eq!(
            probe_iso102(&[0x03, 0x00, 0x00, 0x0b, 0x02, 0xF0, 0x80, 0x99, 0x01, 0x00, 0x00]),
            Iso102Probe::Detected(Iso102Payload::Unknown)
        );
    }

    #[test]
    fn test_malformed_does_not_panic() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x03],
            &[0x03, 0x00, 0x00, 0xff, 0x02, 0xF0, 0x80],
            &[0x03, 0x00, 0x00, 0x07, 0x00, 0xF0, 0x80],
            &[0xff; 32],
        ];
        for c in cases {
            let _ = parse_tpkt_cotp(c);
            let _ = probe_iso102(c);
            let _ = tpkt_frame(c, 65535);
        }
    }
}
