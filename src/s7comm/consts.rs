// S7comm protocol constants
// Copyright (C) 2026 Critical Path Security
// License: GPL-2.0

/// TPKT version (ISO 8073 transport)
pub const TPKT_VERSION: u8 = 0x03;

/// COTP PDU types
pub const COTP_CR: u8 = 0xE0; // Connection Request
pub const COTP_CC: u8 = 0xD0; // Connection Confirm
pub const COTP_DT: u8 = 0xF0; // Data Transfer
pub const COTP_DR: u8 = 0x80; // Disconnect Request
pub const COTP_DC: u8 = 0xC0; // Disconnect Confirm

/// S7comm protocol ID
pub const S7COMM_PROTOCOL_ID: u8 = 0x32;

/// S7comm-plus protocol ID
pub const S7COMM_PLUS_PROTOCOL_ID: u8 = 0x72;

/// S7comm ROSCTR (PDU type / message type)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7RosCtr {
    Job = 0x01,             // Request from HMI/PG
    Ack = 0x02,             // Acknowledgement without data
    AckData = 0x03,         // Response with data
    Userdata = 0x07,        // Userdata (diagnostics, programmer commands)
}

impl S7RosCtr {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Job),
            0x02 => Some(Self::Ack),
            0x03 => Some(Self::AckData),
            0x07 => Some(Self::Userdata),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Job => "Job",
            Self::Ack => "Ack",
            Self::AckData => "Ack_Data",
            Self::Userdata => "Userdata",
        }
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

    /// Returns true if this function code represents a dangerous/impactful operation
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

    /// Map to ATT&CK for ICS technique
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

/// S7comm Userdata subfunction types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7UserdataType {
    Request = 0x04,
    Response = 0x08,
}

/// S7comm Userdata function groups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum S7UserdataFunctionGroup {
    Programmer = 0x01,
    Cyclic = 0x02,
    Block = 0x03,
    Cpu = 0x04,
    Security = 0x05,
    Time = 0x07,
}

impl S7UserdataFunctionGroup {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Programmer),
            0x02 => Some(Self::Cyclic),
            0x03 => Some(Self::Block),
            0x04 => Some(Self::Cpu),
            0x05 => Some(Self::Security),
            0x07 => Some(Self::Time),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Programmer => "Programmer Commands",
            Self::Cyclic => "Cyclic Data",
            Self::Block => "Block Functions",
            Self::Cpu => "CPU Functions",
            Self::Security => "Security",
            Self::Time => "Time Functions",
        }
    }
}

/// Default S7comm port (ISO-TSAP)
pub const S7COMM_PORT: u16 = 102;

/// Error classes
pub const S7_ERROR_NO_ERROR: u8 = 0x00;
pub const S7_ERROR_APP_RELATIONSHIP: u8 = 0x81;
pub const S7_ERROR_OBJECT_DEFINITION: u8 = 0x82;
pub const S7_ERROR_NO_RESOURCES: u8 = 0x83;
pub const S7_ERROR_SERVICE_ERROR: u8 = 0x84;
pub const S7_ERROR_SUPPLY_ERROR: u8 = 0x85;
pub const S7_ERROR_ACCESS_ERROR: u8 = 0x87;
