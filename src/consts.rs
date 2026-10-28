// S7comm protocol constants
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

/// S7comm protocol ID
pub const S7COMM_PROTOCOL_ID: u8 = 0x32;

/// S7comm-plus protocol ID
pub const S7COMM_PLUS_PROTOCOL_ID: u8 = 0x72;

/// S7comm memory area codes (used in item address specification)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7Area {
    SystemInfo = 0x03,   // System info of 200 family
    SystemFlags = 0x05,  // System flags of 200 family
    AnalogInputs = 0x06, // Analog inputs of 200 family
    AnalogOutputs = 0x07,
    Counter = 0x1C, // S7 counters
    Timer = 0x1D,   // S7 timers
    Counter200 = 0x1E,
    Timer200 = 0x1F,
    DataRecord = 0x21,    // Direct peripheral access / data blocks (P)
    Inputs = 0x81,        // I - process inputs
    Outputs = 0x82,       // Q - process outputs
    Flags = 0x83,         // M - memory / merkers
    DataBlock = 0x84,     // DB - data blocks
    DataBlockInst = 0x85, // DI - instance data blocks
    LocalData = 0x86,     // L - local data
    PrevLocalData = 0x87,
}

impl S7Area {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x03 => Some(Self::SystemInfo),
            0x05 => Some(Self::SystemFlags),
            0x06 => Some(Self::AnalogInputs),
            0x07 => Some(Self::AnalogOutputs),
            0x1C => Some(Self::Counter),
            0x1D => Some(Self::Timer),
            0x1E => Some(Self::Counter200),
            0x1F => Some(Self::Timer200),
            0x21 => Some(Self::DataRecord),
            0x81 => Some(Self::Inputs),
            0x82 => Some(Self::Outputs),
            0x83 => Some(Self::Flags),
            0x84 => Some(Self::DataBlock),
            0x85 => Some(Self::DataBlockInst),
            0x86 => Some(Self::LocalData),
            0x87 => Some(Self::PrevLocalData),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SystemInfo => "S200 System Info",
            Self::SystemFlags => "S200 System Flags",
            Self::AnalogInputs => "S200 Analog Inputs",
            Self::AnalogOutputs => "S200 Analog Outputs",
            Self::Counter => "Counter",
            Self::Timer => "Timer",
            Self::Counter200 => "S200 Counter",
            Self::Timer200 => "S200 Timer",
            Self::DataRecord => "Direct Peripheral Access",
            Self::Inputs => "Inputs (I)",
            Self::Outputs => "Outputs (Q)",
            Self::Flags => "Flags (M)",
            Self::DataBlock => "Data Block (DB)",
            Self::DataBlockInst => "Instance DB (DI)",
            Self::LocalData => "Local Data (L)",
            Self::PrevLocalData => "Prev Local Data",
        }
    }
}

/// S7comm Userdata function groups (lower nibble of function_type)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7UserdataGroup {
    ModeTransition = 0x00,
    Programmer = 0x01,
    CyclicData = 0x02,
    BlockFunctions = 0x03,
    CpuFunctions = 0x04,
    Security = 0x05,
    Pbc = 0x06, // Programmable Block Communication (BSEND/BRECV)
    TimeFunctions = 0x07,
    Ncprg = 0x0F, // NC programming
}

impl S7UserdataGroup {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::ModeTransition),
            0x01 => Some(Self::Programmer),
            0x02 => Some(Self::CyclicData),
            0x03 => Some(Self::BlockFunctions),
            0x04 => Some(Self::CpuFunctions),
            0x05 => Some(Self::Security),
            0x06 => Some(Self::Pbc),
            0x07 => Some(Self::TimeFunctions),
            0x0F => Some(Self::Ncprg),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ModeTransition => "Mode Transition",
            Self::Programmer => "Programmer Commands",
            Self::CyclicData => "Cyclic Data",
            Self::BlockFunctions => "Block Functions",
            Self::CpuFunctions => "CPU Functions",
            Self::Security => "Security",
            Self::Pbc => "PBC BSEND/BRECV",
            Self::TimeFunctions => "Time Functions",
            Self::Ncprg => "NC Programming",
        }
    }
}

/// S7comm Security (group 5) subfunctions
pub const S7_SECURITY_PLC_PASSWORD: u8 = 0x01; // PLC password protection
pub const S7_SECURITY_CLEAR_PASSWORD: u8 = 0x02;

/// S7comm CPU functions (group 4) subfunctions
pub const S7_CPU_READ_SZL: u8 = 0x01; // Read System Status List (recon)
pub const S7_CPU_MSG_SERVICE: u8 = 0x02;

/// PLC Control service names (parameter of PlcControl function 0x28)
pub fn plc_control_service(pi_service: &[u8]) -> &'static str {
    // Match on known program-invocation service strings
    if pi_service.windows(5).any(|w| w == b"P_PROGRAM") || pi_service == b"P_PROGRAM" {
        "Program Control"
    } else if pi_service.starts_with(b"_INSE") {
        "Insert Block"
    } else if pi_service.starts_with(b"_DELE") {
        "Delete Block"
    } else if pi_service.starts_with(b"_GARB") {
        "Compress Memory (Garbage Collection)"
    } else if pi_service.starts_with(b"_MODU") {
        "Module Control"
    } else {
        "Unknown Service"
    }
}

/// S7comm function codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7Function {
    CpuServices = 0x00,
    SetupComm = 0xF0,
    ReadVar = 0x04,
    WriteVar = 0x05,
    RequestDownload = 0x1A,
    DownloadBlock = 0x1B,
    DownloadEnded = 0x1C,
    StartUpload = 0x1D,
    Upload = 0x1E,
    EndUpload = 0x1F,
    PlcControl = 0x28,
    PlcStop = 0x29,
}

impl S7Function {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::CpuServices),
            0xF0 => Some(Self::SetupComm),
            0x04 => Some(Self::ReadVar),
            0x05 => Some(Self::WriteVar),
            0x1A => Some(Self::RequestDownload),
            0x1B => Some(Self::DownloadBlock),
            0x1C => Some(Self::DownloadEnded),
            0x1D => Some(Self::StartUpload),
            0x1E => Some(Self::Upload),
            0x1F => Some(Self::EndUpload),
            0x28 => Some(Self::PlcControl),
            0x29 => Some(Self::PlcStop),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CpuServices => "CPU Services",
            Self::SetupComm => "Setup Communication",
            Self::ReadVar => "Read Variable",
            Self::WriteVar => "Write Variable",
            Self::RequestDownload => "Request Download",
            Self::DownloadBlock => "Download Block",
            Self::DownloadEnded => "Download Ended",
            Self::StartUpload => "Start Upload",
            Self::Upload => "Upload",
            Self::EndUpload => "End Upload",
            Self::PlcControl => "PLC Control",
            Self::PlcStop => "PLC Stop",
        }
    }

    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            Self::WriteVar
                | Self::RequestDownload
                | Self::DownloadBlock
                | Self::DownloadEnded
                | Self::StartUpload
                | Self::Upload
                | Self::EndUpload
                | Self::PlcControl
                | Self::PlcStop
        )
    }

    pub fn attack_technique(&self) -> &'static str {
        match self {
            Self::WriteVar => "T0836 Modify Parameter",
            Self::RequestDownload | Self::DownloadBlock | Self::DownloadEnded => {
                "T0843 Program Download"
            }
            Self::StartUpload | Self::Upload | Self::EndUpload => "T0845 Program Upload",
            Self::PlcControl => "T0858 Change Operating Mode",
            Self::PlcStop => "T0858 Change Operating Mode / T0814 Denial of Service",
            Self::SetupComm => "T0886 Remote Services",
            _ => "",
        }
    }
}

/// S7comm-plus (v3) opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7PlusOpcode {
    Request = 0x31,
    Response = 0x32,
    Notification = 0x33,
}

impl S7PlusOpcode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x31 => Some(Self::Request),
            0x32 => Some(Self::Response),
            0x33 => Some(Self::Notification),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Response => "Response",
            Self::Notification => "Notification",
        }
    }
}

/// S7comm-plus (v3) function codes
pub fn s7plus_function_name(func: u16) -> &'static str {
    match func {
        0x04B1 => "Explore",
        0x04BB => "CreateObject",
        0x04D4 => "DeleteObject",
        0x04F2 => "SetVariable",
        0x0524 => "GetLink",
        0x0542 => "SetMultiVariables",
        0x054C => "GetMultiVariables",
        0x0556 => "BeginSequence",
        0x0560 => "EndSequence",
        0x056B => "Invoke",
        0x0586 => "GetVarSubStreamed",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_mapping() {
        assert_eq!(S7Function::from_u8(0x29), Some(S7Function::PlcStop));
        assert_eq!(S7Function::from_u8(0x05), Some(S7Function::WriteVar));
        assert_eq!(S7Function::from_u8(0xAB), None);
        assert!(S7Function::PlcStop.is_dangerous());
        assert!(!S7Function::ReadVar.is_dangerous());
        assert_eq!(
            S7Function::WriteVar.attack_technique(),
            "T0836 Modify Parameter"
        );
    }

    #[test]
    fn test_area_mapping() {
        assert_eq!(S7Area::from_u8(0x84), Some(S7Area::DataBlock));
        assert_eq!(S7Area::from_u8(0x83), Some(S7Area::Flags));
        assert_eq!(S7Area::from_u8(0x82), Some(S7Area::Outputs));
        assert_eq!(S7Area::from_u8(0x00), None);
        assert_eq!(S7Area::DataBlock.as_str(), "Data Block (DB)");
    }

    #[test]
    fn test_userdata_group_mapping() {
        assert_eq!(
            S7UserdataGroup::from_u8(0x05),
            Some(S7UserdataGroup::Security)
        );
        assert_eq!(
            S7UserdataGroup::from_u8(0x04),
            Some(S7UserdataGroup::CpuFunctions)
        );
        assert_eq!(S7UserdataGroup::CpuFunctions.as_str(), "CPU Functions");
    }

    #[test]
    fn test_s7plus_mapping() {
        assert_eq!(S7PlusOpcode::from_u8(0x31), Some(S7PlusOpcode::Request));
        assert_eq!(s7plus_function_name(0x04f2), "SetVariable");
        assert_eq!(s7plus_function_name(0x04b1), "Explore");
        assert_eq!(s7plus_function_name(0xffff), "Unknown");
    }
}
