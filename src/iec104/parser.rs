// IEC 60870-5-104 APDU parser
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use super::consts::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// First byte is not 0x68.
    InvalidStart,
    /// Length byte outside 4..=253.
    InvalidLength,
    /// Structurally invalid APCI/ASDU.
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommandValue {
    /// SCS / DCS / RCS state bits.
    State(u8),
    /// Normalized setpoint (raw NVA).
    Normalized(i16),
    /// Scaled setpoint (SVA).
    Scaled(i16),
    /// Short floating point setpoint.
    Float(f32),
    /// 32-bit bitstring.
    Bitstring(u32),
}

/// First command object of a control-direction ASDU.
#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    /// S/E bit: true = select, false = execute. None for bitstring commands.
    pub select: Option<bool>,
    /// QU (SCO/DCO/RCO) or QL (QOS) qualifier.
    pub qualifier: Option<u8>,
    pub value: CommandValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Asdu {
    pub type_id: u8,
    pub sq: bool,
    pub num_objects: u8,
    pub test: bool,
    pub negative: bool,
    pub cot: u8,
    pub originator: u8,
    pub common_address: u16,
    /// Information object addresses that could be located in the ASDU.
    pub ioas: Vec<u32>,
    /// Declared object count does not match the ASDU length.
    pub length_mismatch: bool,
    pub command: Option<Command>,
    /// QOI / QCC / QRP / QPA of system and parameter-activation commands.
    pub qualifier: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Apdu {
    pub format: ApciFormat,
    pub send_seq: Option<u16>,
    pub recv_seq: Option<u16>,
    pub u_function: Option<u8>,
    pub asdu: Option<Asdu>,
}

fn read_ioa(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

fn parse_command(type_id: u8, elem: &[u8]) -> Option<Command> {
    // Time-tagged variants (58..=64) share the layout of 45..=51 plus CP56Time2a.
    let base = if (58..=64).contains(&type_id) { type_id - 13 } else { type_id };
    match base {
        C_SC_NA_1 => {
            let q = *elem.first()?;
            Some(Command {
                select: Some(q & 0x80 != 0),
                qualifier: Some((q >> 2) & 0x1f),
                value: CommandValue::State(q & 0x01),
            })
        }
        C_DC_NA_1 | C_RC_NA_1 => {
            let q = *elem.first()?;
            Some(Command {
                select: Some(q & 0x80 != 0),
                qualifier: Some((q >> 2) & 0x1f),
                value: CommandValue::State(q & 0x03),
            })
        }
        C_SE_NA_1 | C_SE_NB_1 => {
            if elem.len() < 3 {
                return None;
            }
            let v = i16::from_le_bytes([elem[0], elem[1]]);
            let q = elem[2];
            Some(Command {
                select: Some(q & 0x80 != 0),
                qualifier: Some(q & 0x7f),
                value: if base == C_SE_NA_1 {
                    CommandValue::Normalized(v)
                } else {
                    CommandValue::Scaled(v)
                },
            })
        }
        C_SE_NC_1 => {
            if elem.len() < 5 {
                return None;
            }
            let v = f32::from_le_bytes([elem[0], elem[1], elem[2], elem[3]]);
            let q = elem[4];
            Some(Command {
                select: Some(q & 0x80 != 0),
                qualifier: Some(q & 0x7f),
                value: CommandValue::Float(v),
            })
        }
        C_BO_NA_1 => {
            if elem.len() < 4 {
                return None;
            }
            Some(Command {
                select: None,
                qualifier: None,
                value: CommandValue::Bitstring(u32::from_le_bytes([
                    elem[0], elem[1], elem[2], elem[3],
                ])),
            })
        }
        _ => None,
    }
}

fn parse_asdu(data: &[u8]) -> Result<Asdu, ApduError> {
    if data.len() < ASDU_HEADER_LEN {
        return Err(ApduError::Malformed);
    }
    let type_id = data[0];
    let vsq = data[1];
    let sq = vsq & 0x80 != 0;
    let num_objects = vsq & 0x7f;
    let n = num_objects as usize;
    let objects = &data[ASDU_HEADER_LEN..];

    let mut asdu = Asdu {
        type_id,
        sq,
        num_objects,
        test: data[2] & 0x80 != 0,
        negative: data[2] & 0x40 != 0,
        cot: data[2] & 0x3f,
        originator: data[3],
        common_address: u16::from_le_bytes([data[4], data[5]]),
        ioas: Vec::new(),
        length_mismatch: false,
        command: None,
        qualifier: None,
    };

    match element_size(type_id) {
        Some(size) => {
            let expected = match (n, sq) {
                (0, _) => 0,
                (_, true) => IOA_LEN + n * size,
                (_, false) => n * (IOA_LEN + size),
            };
            asdu.length_mismatch = objects.len() != expected;
            if sq {
                if n > 0 && objects.len() >= IOA_LEN {
                    let base = read_ioa(objects);
                    let fit = if size == 0 { n } else { (objects.len() - IOA_LEN) / size };
                    for i in 0..n.min(fit) {
                        asdu.ioas.push(base.wrapping_add(i as u32) & 0x00ff_ffff);
                    }
                }
            } else {
                let mut off = 0;
                for _ in 0..n {
                    if off + IOA_LEN + size > objects.len() {
                        break;
                    }
                    asdu.ioas.push(read_ioa(&objects[off..]));
                    off += IOA_LEN + size;
                }
            }
        }
        None => {
            // Unknown or variable-length type: only the first IOA is locatable.
            if n > 0 && objects.len() >= IOA_LEN {
                asdu.ioas.push(read_ioa(objects));
            }
        }
    }

    if n > 0 && objects.len() >= IOA_LEN {
        let elem = &objects[IOA_LEN..];
        asdu.command = parse_command(type_id, elem);
        if matches!(type_id, C_IC_NA_1 | C_CI_NA_1 | C_RP_NA_1 | P_AC_NA_1) {
            asdu.qualifier = elem.first().copied();
        }
    }

    Ok(asdu)
}

/// Parse one complete APDU. `input` must be exactly `length + 2` bytes.
pub(crate) fn parse_apdu(input: &[u8]) -> Result<Apdu, ApduError> {
    if input.len() < 2 || input[0] != IEC104_START_BYTE {
        return Err(ApduError::InvalidStart);
    }
    let length = input[1];
    if !(APCI_CONTROL_LEN..=APDU_MAX_LENGTH).contains(&length) {
        return Err(ApduError::InvalidLength);
    }
    if input.len() != length as usize + 2 {
        return Err(ApduError::Malformed);
    }
    let cf = &input[2..6];
    let body = &input[6..];

    if cf[0] & 0x01 == 0 {
        let send_seq = u16::from_le_bytes([cf[0], cf[1]]) >> 1;
        let recv_seq = u16::from_le_bytes([cf[2], cf[3]]) >> 1;
        let asdu = parse_asdu(body)?;
        Ok(Apdu {
            format: ApciFormat::I,
            send_seq: Some(send_seq),
            recv_seq: Some(recv_seq),
            u_function: None,
            asdu: Some(asdu),
        })
    } else if cf[0] & 0x03 == 0x01 {
        if !body.is_empty() {
            return Err(ApduError::Malformed);
        }
        Ok(Apdu {
            format: ApciFormat::S,
            send_seq: None,
            recv_seq: Some(u16::from_le_bytes([cf[2], cf[3]]) >> 1),
            u_function: None,
            asdu: None,
        })
    } else {
        if !body.is_empty() {
            return Err(ApduError::Malformed);
        }
        Ok(Apdu {
            format: ApciFormat::U,
            send_seq: None,
            recv_seq: None,
            u_function: Some(cf[0]),
            asdu: None,
        })
    }
}

/// Probe: does `input` start with a plausible IEC 60870-5-104 APDU?
pub(crate) fn probe_iec104(input: &[u8]) -> bool {
    if input.len() < 6 || input[0] != IEC104_START_BYTE {
        return false;
    }
    let length = input[1];
    if !(APCI_CONTROL_LEN..=APDU_MAX_LENGTH).contains(&length) {
        return false;
    }
    let cf1 = input[2];
    if cf1 & 0x01 == 0 {
        if (length as usize) < APCI_CONTROL_LEN as usize + ASDU_HEADER_LEN || input[4] & 0x01 != 0 {
            return false;
        }
        // Require a known type identifier when it is available.
        return input.len() < 7 || type_id_name(input[6]).is_some();
    }
    if length != APCI_CONTROL_LEN {
        return false;
    }
    if cf1 & 0x03 == 0x01 {
        return input[3] == 0 && input[4] & 0x01 == 0;
    }
    u_function_name(cf1).is_some() && input[3] == 0 && input[4] == 0 && input[5] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const STARTDT_ACT: &[u8] = &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00];

    #[test]
    fn test_probe() {
        assert!(probe_iec104(STARTDT_ACT));
        assert!(probe_iec104(&[0x68, 0x04, 0x0b, 0x00, 0x00, 0x00])); // STARTDT con
        assert!(probe_iec104(&[0x68, 0x04, 0x01, 0x00, 0x0a, 0x00])); // S-frame
        // General interrogation I-frame
        assert!(probe_iec104(&[
            0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14
        ]));
        assert!(!probe_iec104(&[0x67, 0x04, 0x07, 0x00, 0x00, 0x00]));
        assert!(!probe_iec104(&[0x68, 0x04, 0x0f, 0x00, 0x00, 0x00])); // bad U function
        assert!(!probe_iec104(&[0x68, 0x02, 0x07, 0x00, 0x00, 0x00])); // bad length
        assert!(!probe_iec104(&[0x68, 0x04, 0x07])); // too short
        // I-frame with unknown type id
        assert!(!probe_iec104(&[
            0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14
        ]));
    }

    #[test]
    fn test_parse_u_frame() {
        let apdu = parse_apdu(STARTDT_ACT).unwrap();
        assert_eq!(apdu.format, ApciFormat::U);
        assert_eq!(apdu.u_function, Some(U_STARTDT_ACT));
        assert!(apdu.asdu.is_none());
    }

    #[test]
    fn test_parse_s_frame() {
        // N(R) = 5 -> CF3 = 5 << 1
        let apdu = parse_apdu(&[0x68, 0x04, 0x01, 0x00, 0x0a, 0x00]).unwrap();
        assert_eq!(apdu.format, ApciFormat::S);
        assert_eq!(apdu.recv_seq, Some(5));
    }

    #[test]
    fn test_parse_interrogation() {
        // N(S)=2, N(R)=1, C_IC_NA_1, COT=6, CA=1, IOA=0, QOI=20
        let data = &[
            0x68, 0x0e, 0x04, 0x00, 0x02, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ];
        let apdu = parse_apdu(data).unwrap();
        assert_eq!(apdu.format, ApciFormat::I);
        assert_eq!(apdu.send_seq, Some(2));
        assert_eq!(apdu.recv_seq, Some(1));
        let asdu = apdu.asdu.unwrap();
        assert_eq!(asdu.type_id, C_IC_NA_1);
        assert_eq!(asdu.cot, COT_ACTIVATION);
        assert_eq!(asdu.common_address, 1);
        assert_eq!(asdu.ioas, vec![0]);
        assert_eq!(asdu.qualifier, Some(20));
        assert!(!asdu.length_mismatch);
    }

    #[test]
    fn test_parse_single_command_execute() {
        // C_SC_NA_1, COT=6, CA=0x0203, IOA=0x001388 (5000), SCO = execute ON
        let data = &[
            0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x01, 0x06, 0x00, 0x03, 0x02, 0x88, 0x13,
            0x00, 0x01,
        ];
        let asdu = parse_apdu(data).unwrap().asdu.unwrap();
        assert_eq!(asdu.type_id, C_SC_NA_1);
        assert_eq!(asdu.common_address, 0x0203);
        assert_eq!(asdu.ioas, vec![5000]);
        let cmd = asdu.command.unwrap();
        assert_eq!(cmd.select, Some(false));
        assert_eq!(cmd.value, CommandValue::State(1));
    }

    #[test]
    fn test_parse_float_setpoint_select() {
        // C_SE_NC_1, COT=6, CA=1, IOA=100, value=1.5, QOS select
        let v = 1.5f32.to_le_bytes();
        let data = &[
            0x68, 0x12, 0x00, 0x00, 0x00, 0x00, 0x32, 0x01, 0x06, 0x00, 0x01, 0x00, 0x64, 0x00,
            0x00, v[0], v[1], v[2], v[3], 0x80,
        ];
        let asdu = parse_apdu(data).unwrap().asdu.unwrap();
        let cmd = asdu.command.unwrap();
        assert_eq!(cmd.select, Some(true));
        assert_eq!(cmd.value, CommandValue::Float(1.5));
        assert!(!asdu.length_mismatch);
    }

    #[test]
    fn test_parse_sequence_of_measurements() {
        // M_ME_NB_1, SQ=1, 3 objects from IOA 10, COT=3 (spontaneous)
        let data = &[
            0x68, 0x16, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x83, 0x03, 0x00, 0x01, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00,
        ];
        let asdu = parse_apdu(data).unwrap().asdu.unwrap();
        assert!(asdu.sq);
        assert_eq!(asdu.num_objects, 3);
        assert_eq!(asdu.ioas, vec![10, 11, 12]);
        assert!(!asdu.length_mismatch);
        assert!(asdu.command.is_none());
    }

    #[test]
    fn test_length_mismatch() {
        // M_SP_NA_1 claiming 2 objects but carrying only one.
        let data = &[
            0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x01,
        ];
        let asdu = parse_apdu(data).unwrap().asdu.unwrap();
        assert!(asdu.length_mismatch);
        assert_eq!(asdu.ioas, vec![1]);
    }

    #[test]
    fn test_parse_errors() {
        assert_eq!(parse_apdu(&[0x67, 0x04, 0x07, 0, 0, 0]), Err(ApduError::InvalidStart));
        assert_eq!(parse_apdu(&[0x68, 0x02, 0x07, 0]), Err(ApduError::InvalidLength));
        assert_eq!(parse_apdu(&[0x68, 0xff]), Err(ApduError::InvalidLength));
        // I-frame with a truncated ASDU header
        assert_eq!(
            parse_apdu(&[0x68, 0x06, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x01]),
            Err(ApduError::Malformed)
        );
        // U-frame carrying trailing bytes
        assert_eq!(
            parse_apdu(&[0x68, 0x05, 0x07, 0x00, 0x00, 0x00, 0xff]),
            Err(ApduError::Malformed)
        );
    }

    #[test]
    fn test_malformed_does_not_panic() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x68],
            &[0x68, 0x04],
            &[0x68, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x2d, 0xff, 0x06, 0x00, 0x01, 0x00],
            &[0x68, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x7d, 0x81, 0x0d, 0x00, 0x01, 0x00],
            &[0xff; 32],
        ];
        for c in cases {
            let _ = parse_apdu(c);
            let _ = probe_iec104(c);
        }
    }
}
