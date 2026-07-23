// S7comm detection keyword support
// Copyright (C) 2026 Critical Path Security
// License: GPL-2.0
//
// Provides Suricata rule keyword matching for:
//   s7comm.function_code - match on S7comm function code (numeric)
//   s7comm.rosctr        - match on PDU type (1=Job, 2=Ack, 3=AckData, 7=Userdata)
//   s7comm.pdu_type      - alias for rosctr
//   s7comm.dangerous     - boolean: true if function code is dangerous

use crate::s7comm::state::S7commTransaction;

/// Match on function code value
pub fn detect_function_code(tx: &S7commTransaction, target: u8) -> bool {
    tx.request_function_code == Some(target)
}

/// Match on function code range (for rule keyword like: s7comm.function_code:0x1a-0x1f)
pub fn detect_function_code_range(tx: &S7commTransaction, min: u8, max: u8) -> bool {
    if let Some(fc) = tx.request_function_code {
        fc >= min && fc <= max
    } else {
        false
    }
}

/// Match on ROSCTR (PDU type)
pub fn detect_rosctr(tx: &S7commTransaction, target: u8) -> bool {
    tx.request_rosctr == Some(target)
}

/// Match if the transaction involves a dangerous operation
pub fn detect_dangerous(tx: &S7commTransaction) -> bool {
    tx.is_dangerous
}

/// Match on userdata function group
pub fn detect_userdata_group(tx: &S7commTransaction, target: u8) -> bool {
    tx.request_userdata_group == Some(target)
}

/// Match on userdata subfunction
pub fn detect_userdata_subfunction(tx: &S7commTransaction, target: u8) -> bool {
    tx.request_userdata_subfunction == Some(target)
}

/// Match on S7comm-plus protocol
pub fn detect_s7comm_plus(tx: &S7commTransaction) -> bool {
    tx.is_s7comm_plus
}

/// Keyword definitions for Suricata rule engine integration
/// These would be registered via the C FFI layer
pub struct S7commKeywords;

impl S7commKeywords {
    /// Returns keyword documentation for rule writers
    pub fn keyword_docs() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "s7comm.function_code",
                "Match S7comm function code. Values: 0x04 (Read), 0x05 (Write), \
                 0x1a (Request Download), 0x1b (Download Block), 0x1c (Download Ended), \
                 0x1d (Start Upload), 0x1e (Upload), 0x1f (End Upload), \
                 0x28 (PLC Control), 0x29 (PLC Stop), 0xf0 (Setup Comm)",
            ),
            (
                "s7comm.rosctr",
                "Match S7comm ROSCTR/PDU type. Values: 1 (Job/Request), \
                 2 (Ack), 3 (Ack-Data/Response), 7 (Userdata)",
            ),
            (
                "s7comm.dangerous",
                "Boolean keyword. Matches if the S7comm function code is \
                 considered dangerous (writes, downloads, uploads, stop, control)",
            ),
            (
                "s7comm.userdata_group",
                "Match Userdata function group. Values: 1 (Programmer), \
                 2 (Cyclic), 3 (Block), 4 (CPU), 5 (Security), 7 (Time)",
            ),
            (
                "s7comm.subfunction",
                "Match Userdata subfunction code (numeric)",
            ),
            (
                "s7comm.plus",
                "Boolean keyword. Matches S7comm-plus (newer protocol variant)",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s7comm::state::S7commTransaction;

    #[test]
    fn test_detect_function_code() {
        let mut tx = S7commTransaction::new(1);
        tx.request_function_code = Some(0x29); // PLC Stop
        assert!(detect_function_code(&tx, 0x29));
        assert!(!detect_function_code(&tx, 0x04));
    }

    #[test]
    fn test_detect_dangerous() {
        let mut tx = S7commTransaction::new(1);
        tx.is_dangerous = true;
        assert!(detect_dangerous(&tx));

        tx.is_dangerous = false;
        assert!(!detect_dangerous(&tx));
    }

    #[test]
    fn test_detect_function_code_range() {
        let mut tx = S7commTransaction::new(1);
        tx.request_function_code = Some(0x1B); // Download Block
        assert!(detect_function_code_range(&tx, 0x1A, 0x1F));
        assert!(!detect_function_code_range(&tx, 0x28, 0x29));
    }
}
