// S7comm protocol constants
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

/// TPKT version (ISO 8073 transport)
pub const TPKT_VERSION: u8 = 0x03;

/// COTP PDU types
pub const COTP_CR: u8 = 0xE0; // Connection Request
pub const COTP_CC: u8 = 0xD0; // Connection Confirm
pub const COTP_DT: u8 = 0xF0; // Data Transfer

/// S7comm protocol ID
pub const S7COMM_PROTOCOL_ID: u8 = 0x32;

/// S7comm-plus protocol ID
pub const S7COMM_PLUS_PROTOCOL_ID: u8 = 0x72;

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
