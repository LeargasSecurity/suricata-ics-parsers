// IEC 60870-5-104 protocol constants
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

/// APDU start byte.
pub const IEC104_START_BYTE: u8 = 0x68;

/// Length of the APCI control field (the minimum APDU length value).
pub const APCI_CONTROL_LEN: u8 = 4;

/// Maximum value of the APDU length byte (IEC 60870-5-104 §5.1).
pub const APDU_MAX_LENGTH: u8 = 253;

/// ASDU data unit identifier: type(1) + VSQ(1) + COT(2) + common address(2).
pub const ASDU_HEADER_LEN: usize = 6;

/// Information object address length in the 104 profile.
pub const IOA_LEN: usize = 3;

/// U-format control function codes (first control octet).
pub const U_STARTDT_ACT: u8 = 0x07;
pub const U_STARTDT_CON: u8 = 0x0B;
pub const U_STOPDT_ACT: u8 = 0x13;
pub const U_STOPDT_CON: u8 = 0x23;
pub const U_TESTFR_ACT: u8 = 0x43;
pub const U_TESTFR_CON: u8 = 0x83;

pub fn u_function_name(cf1: u8) -> Option<&'static str> {
    match cf1 {
        U_STARTDT_ACT => Some("STARTDT_ACT"),
        U_STARTDT_CON => Some("STARTDT_CON"),
        U_STOPDT_ACT => Some("STOPDT_ACT"),
        U_STOPDT_CON => Some("STOPDT_CON"),
        U_TESTFR_ACT => Some("TESTFR_ACT"),
        U_TESTFR_CON => Some("TESTFR_CON"),
        _ => None,
    }
}

/// APCI frame format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApciFormat {
    /// Numbered information transfer (carries an ASDU).
    I,
    /// Numbered supervisory (acknowledgement only).
    S,
    /// Unnumbered control (STARTDT / STOPDT / TESTFR).
    U,
}

impl ApciFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::I => "I",
            Self::S => "S",
            Self::U => "U",
        }
    }
}

// Selected type identifiers referenced by the state machine.
pub const C_SC_NA_1: u8 = 45;
pub const C_DC_NA_1: u8 = 46;
pub const C_RC_NA_1: u8 = 47;
pub const C_SE_NA_1: u8 = 48;
pub const C_SE_NB_1: u8 = 49;
pub const C_SE_NC_1: u8 = 50;
pub const C_BO_NA_1: u8 = 51;
pub const C_IC_NA_1: u8 = 100;
pub const C_CI_NA_1: u8 = 101;
pub const C_CS_NA_1: u8 = 103;
pub const C_RP_NA_1: u8 = 105;
pub const P_AC_NA_1: u8 = 113;

/// Cause of transmission values referenced by the state machine.
pub const COT_ACTIVATION: u8 = 6;
pub const COT_DEACTIVATION: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeCategory {
    /// Process information in monitor direction (M_*).
    Monitor,
    /// Process information in control direction (C_SC .. C_BO).
    Command,
    /// System information in monitor direction (M_EI_NA_1).
    SystemMonitor,
    /// System information in control direction (interrogation, clock sync, reset...).
    SystemCommand,
    /// Parameter in control direction (P_*).
    Parameter,
    /// File transfer (F_*).
    FileTransfer,
}

pub fn type_category(type_id: u8) -> Option<TypeCategory> {
    match type_id {
        1..=21 | 30..=40 => Some(TypeCategory::Monitor),
        45..=51 | 58..=64 => Some(TypeCategory::Command),
        70 => Some(TypeCategory::SystemMonitor),
        100..=107 => Some(TypeCategory::SystemCommand),
        110..=113 => Some(TypeCategory::Parameter),
        120..=127 => Some(TypeCategory::FileTransfer),
        _ => None,
    }
}

pub fn type_id_name(type_id: u8) -> Option<&'static str> {
    let name = match type_id {
        1 => "M_SP_NA_1",
        2 => "M_SP_TA_1",
        3 => "M_DP_NA_1",
        4 => "M_DP_TA_1",
        5 => "M_ST_NA_1",
        6 => "M_ST_TA_1",
        7 => "M_BO_NA_1",
        8 => "M_BO_TA_1",
        9 => "M_ME_NA_1",
        10 => "M_ME_TA_1",
        11 => "M_ME_NB_1",
        12 => "M_ME_TB_1",
        13 => "M_ME_NC_1",
        14 => "M_ME_TC_1",
        15 => "M_IT_NA_1",
        16 => "M_IT_TA_1",
        17 => "M_EP_TA_1",
        18 => "M_EP_TB_1",
        19 => "M_EP_TC_1",
        20 => "M_PS_NA_1",
        21 => "M_ME_ND_1",
        30 => "M_SP_TB_1",
        31 => "M_DP_TB_1",
        32 => "M_ST_TB_1",
        33 => "M_BO_TB_1",
        34 => "M_ME_TD_1",
        35 => "M_ME_TE_1",
        36 => "M_ME_TF_1",
        37 => "M_IT_TB_1",
        38 => "M_EP_TD_1",
        39 => "M_EP_TE_1",
        40 => "M_EP_TF_1",
        45 => "C_SC_NA_1",
        46 => "C_DC_NA_1",
        47 => "C_RC_NA_1",
        48 => "C_SE_NA_1",
        49 => "C_SE_NB_1",
        50 => "C_SE_NC_1",
        51 => "C_BO_NA_1",
        58 => "C_SC_TA_1",
        59 => "C_DC_TA_1",
        60 => "C_RC_TA_1",
        61 => "C_SE_TA_1",
        62 => "C_SE_TB_1",
        63 => "C_SE_TC_1",
        64 => "C_BO_TA_1",
        70 => "M_EI_NA_1",
        100 => "C_IC_NA_1",
        101 => "C_CI_NA_1",
        102 => "C_RD_NA_1",
        103 => "C_CS_NA_1",
        104 => "C_TS_NA_1",
        105 => "C_RP_NA_1",
        106 => "C_CD_NA_1",
        107 => "C_TS_TA_1",
        110 => "P_ME_NA_1",
        111 => "P_ME_NB_1",
        112 => "P_ME_NC_1",
        113 => "P_AC_NA_1",
        120 => "F_FR_NA_1",
        121 => "F_SR_NA_1",
        122 => "F_SC_NA_1",
        123 => "F_LS_NA_1",
        124 => "F_AF_NA_1",
        125 => "F_SG_NA_1",
        126 => "F_DR_TA_1",
        127 => "F_SC_NB_1",
        _ => return None,
    };
    Some(name)
}

/// Size in bytes of one information element (excluding the IOA) for the
/// fixed-size type identifiers. `None` for unknown or variable-length types.
pub fn element_size(type_id: u8) -> Option<usize> {
    let size = match type_id {
        1 | 3 => 1,
        2 | 4 => 4,
        5 => 2,
        6 => 5,
        7 => 5,
        8 => 8,
        9 | 11 => 3,
        10 | 12 => 6,
        13 => 5,
        14 => 8,
        15 => 5,
        16 => 8,
        17 => 6,
        18 | 19 => 7,
        20 => 5,
        21 => 2,
        30 | 31 => 8,
        32 => 9,
        33 => 12,
        34 | 35 => 10,
        36 | 37 => 12,
        38 => 10,
        39 | 40 => 11,
        45..=47 => 1,
        48 | 49 => 3,
        50 => 5,
        51 => 4,
        58..=60 => 8,
        61 | 62 => 10,
        63 => 12,
        64 => 11,
        70 => 1,
        100 | 101 => 1,
        102 => 0,
        103 => 7,
        104 => 2,
        105 => 1,
        106 => 2,
        107 => 9,
        110 | 111 => 3,
        112 => 5,
        113 => 1,
        120 => 6,
        121 => 7,
        122 => 4,
        123 => 5,
        124 => 4,
        126 => 13,
        127 => 16,
        _ => return None,
    };
    Some(size)
}

pub fn cot_name(cot: u8) -> Option<&'static str> {
    let name = match cot {
        1 => "periodic",
        2 => "background_scan",
        3 => "spontaneous",
        4 => "initialized",
        5 => "request",
        6 => "activation",
        7 => "activation_con",
        8 => "deactivation",
        9 => "deactivation_con",
        10 => "activation_term",
        11 => "return_info_remote",
        12 => "return_info_local",
        13 => "file_transfer",
        20 => "interrogated_station",
        21..=36 => "interrogated_group",
        37 => "counter_interrogated_general",
        38..=41 => "counter_interrogated_group",
        44 => "unknown_type_id",
        45 => "unknown_cot",
        46 => "unknown_common_address",
        47 => "unknown_ioa",
        _ => return None,
    };
    Some(name)
}

/// ATT&CK for ICS technique for a control-direction command type.
pub fn command_attack_technique(type_id: u8) -> &'static str {
    match type_id {
        48..=50 | 61..=63 => "T0855 Unauthorized Command Message / T0836 Modify Parameter",
        _ => "T0855 Unauthorized Command Message / T0831 Manipulation of Control",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_mapping() {
        assert_eq!(type_id_name(45), Some("C_SC_NA_1"));
        assert_eq!(type_id_name(100), Some("C_IC_NA_1"));
        assert_eq!(type_id_name(200), None);
        assert_eq!(type_category(46), Some(TypeCategory::Command));
        assert_eq!(type_category(13), Some(TypeCategory::Monitor));
        assert_eq!(type_category(103), Some(TypeCategory::SystemCommand));
        assert_eq!(type_category(0), None);
    }

    #[test]
    fn test_element_sizes() {
        assert_eq!(element_size(1), Some(1));
        assert_eq!(element_size(13), Some(5));
        assert_eq!(element_size(36), Some(12));
        assert_eq!(element_size(58), Some(8));
        assert_eq!(element_size(125), None);
        // Every named type except the variable-length segment has a size.
        for t in 0..=255u8 {
            if type_id_name(t).is_some() && t != 125 {
                assert!(element_size(t).is_some(), "missing size for {}", t);
            }
        }
    }

    #[test]
    fn test_u_and_cot_names() {
        assert_eq!(u_function_name(0x07), Some("STARTDT_ACT"));
        assert_eq!(u_function_name(0x13), Some("STOPDT_ACT"));
        assert_eq!(u_function_name(0x0f), None);
        assert_eq!(cot_name(6), Some("activation"));
        assert_eq!(cot_name(47), Some("unknown_ioa"));
        assert_eq!(cot_name(15), None);
    }
}
