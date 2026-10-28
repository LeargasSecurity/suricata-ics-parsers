// MMS (ISO 9506) constants for the Suricata ICS parser plugin
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

/// MMSpdu CHOICE alternatives (context tag numbers).
pub const PDU_CONFIRMED_REQUEST: u8 = 0;
pub const PDU_CONFIRMED_RESPONSE: u8 = 1;
pub const PDU_CONFIRMED_ERROR: u8 = 2;
pub const PDU_UNCONFIRMED: u8 = 3;
pub const PDU_REJECT: u8 = 4;
pub const PDU_CANCEL_REQUEST: u8 = 5;
pub const PDU_CANCEL_RESPONSE: u8 = 6;
pub const PDU_CANCEL_ERROR: u8 = 7;
pub const PDU_INITIATE_REQUEST: u8 = 8;
pub const PDU_INITIATE_RESPONSE: u8 = 9;
pub const PDU_INITIATE_ERROR: u8 = 10;
pub const PDU_CONCLUDE_REQUEST: u8 = 11;
pub const PDU_CONCLUDE_RESPONSE: u8 = 12;
pub const PDU_CONCLUDE_ERROR: u8 = 13;

const PDU_NAMES: [&str; 14] = [
    "confirmed_request",
    "confirmed_response",
    "confirmed_error",
    "unconfirmed",
    "reject",
    "cancel_request",
    "cancel_response",
    "cancel_error",
    "initiate_request",
    "initiate_response",
    "initiate_error",
    "conclude_request",
    "conclude_response",
    "conclude_error",
];

pub fn pdu_type_name(t: u8) -> &'static str {
    PDU_NAMES.get(t as usize).copied().unwrap_or("unknown")
}

pub fn pdu_type_from_name(name: &str) -> Option<u8> {
    PDU_NAMES
        .iter()
        .position(|n| n.eq_ignore_ascii_case(name))
        .map(|p| p as u8)
}

/// ConfirmedServiceRequest/Response CHOICE alternatives (ISO 9506-2).
pub const SVC_GET_NAME_LIST: u32 = 1;
pub const SVC_IDENTIFY: u32 = 2;
pub const SVC_READ: u32 = 4;
pub const SVC_WRITE: u32 = 5;
pub const SVC_GET_VARIABLE_ACCESS_ATTRIBUTES: u32 = 6;
pub const SVC_DEFINE_NAMED_VARIABLE: u32 = 7;
pub const SVC_DELETE_VARIABLE_ACCESS: u32 = 10;
pub const SVC_DEFINE_NAMED_VARIABLE_LIST: u32 = 11;
pub const SVC_GET_NAMED_VARIABLE_LIST_ATTRIBUTES: u32 = 12;
pub const SVC_DELETE_NAMED_VARIABLE_LIST: u32 = 13;
pub const SVC_INITIATE_DOWNLOAD_SEQUENCE: u32 = 26;
pub const SVC_DOWNLOAD_SEGMENT: u32 = 27;
pub const SVC_TERMINATE_DOWNLOAD_SEQUENCE: u32 = 28;
pub const SVC_INITIATE_UPLOAD_SEQUENCE: u32 = 29;
pub const SVC_UPLOAD_SEGMENT: u32 = 30;
pub const SVC_TERMINATE_UPLOAD_SEQUENCE: u32 = 31;
pub const SVC_REQUEST_DOMAIN_DOWNLOAD: u32 = 32;
pub const SVC_REQUEST_DOMAIN_UPLOAD: u32 = 33;
pub const SVC_LOAD_DOMAIN_CONTENT: u32 = 34;
pub const SVC_STORE_DOMAIN_CONTENT: u32 = 35;
pub const SVC_DELETE_DOMAIN: u32 = 36;
pub const SVC_GET_DOMAIN_ATTRIBUTES: u32 = 37;
pub const SVC_CREATE_PROGRAM_INVOCATION: u32 = 38;
pub const SVC_DELETE_PROGRAM_INVOCATION: u32 = 39;
pub const SVC_START: u32 = 40;
pub const SVC_STOP: u32 = 41;
pub const SVC_RESUME: u32 = 42;
pub const SVC_RESET: u32 = 43;
pub const SVC_KILL: u32 = 44;
pub const SVC_GET_PROGRAM_INVOCATION_ATTRIBUTES: u32 = 45;
pub const SVC_OBTAIN_FILE: u32 = 46;
pub const SVC_READ_JOURNAL: u32 = 65;
pub const SVC_WRITE_JOURNAL: u32 = 66;
pub const SVC_INITIALIZE_JOURNAL: u32 = 67;
pub const SVC_CREATE_JOURNAL: u32 = 69;
pub const SVC_DELETE_JOURNAL: u32 = 70;
pub const SVC_FILE_OPEN: u32 = 72;
pub const SVC_FILE_READ: u32 = 73;
pub const SVC_FILE_RENAME: u32 = 75;
pub const SVC_FILE_DELETE: u32 = 76;
pub const SVC_FILE_DIRECTORY: u32 = 77;

const SERVICE_NAMES: [&str; 78] = [
    "status",
    "getNameList",
    "identify",
    "rename",
    "read",
    "write",
    "getVariableAccessAttributes",
    "defineNamedVariable",
    "defineScatteredAccess",
    "getScatteredAccessAttributes",
    "deleteVariableAccess",
    "defineNamedVariableList",
    "getNamedVariableListAttributes",
    "deleteNamedVariableList",
    "defineNamedType",
    "getNamedTypeAttributes",
    "deleteNamedType",
    "input",
    "output",
    "takeControl",
    "relinquishControl",
    "defineSemaphore",
    "deleteSemaphore",
    "reportSemaphoreStatus",
    "reportPoolSemaphoreStatus",
    "reportSemaphoreEntryStatus",
    "initiateDownloadSequence",
    "downloadSegment",
    "terminateDownloadSequence",
    "initiateUploadSequence",
    "uploadSegment",
    "terminateUploadSequence",
    "requestDomainDownload",
    "requestDomainUpload",
    "loadDomainContent",
    "storeDomainContent",
    "deleteDomain",
    "getDomainAttributes",
    "createProgramInvocation",
    "deleteProgramInvocation",
    "start",
    "stop",
    "resume",
    "reset",
    "kill",
    "getProgramInvocationAttributes",
    "obtainFile",
    "defineEventCondition",
    "deleteEventCondition",
    "getEventConditionAttributes",
    "reportEventConditionStatus",
    "alterEventConditionMonitoring",
    "triggerEvent",
    "defineEventAction",
    "deleteEventAction",
    "getEventActionAttributes",
    "reportEventActionStatus",
    "defineEventEnrollment",
    "deleteEventEnrollment",
    "alterEventEnrollment",
    "reportEventEnrollmentStatus",
    "getEventEnrollmentAttributes",
    "acknowledgeEventNotification",
    "getAlarmSummary",
    "getAlarmEnrollmentSummary",
    "readJournal",
    "writeJournal",
    "initializeJournal",
    "reportJournalStatus",
    "createJournal",
    "deleteJournal",
    "getCapabilityList",
    "fileOpen",
    "fileRead",
    "fileClose",
    "fileRename",
    "fileDelete",
    "fileDirectory",
];

pub fn service_name(svc: u32) -> Option<&'static str> {
    SERVICE_NAMES.get(svc as usize).copied()
}

pub fn service_from_name(name: &str) -> Option<u32> {
    SERVICE_NAMES
        .iter()
        .position(|n| n.eq_ignore_ascii_case(name))
        .map(|p| p as u32)
}

/// UnconfirmedService CHOICE alternatives.
pub fn unconfirmed_service_name(svc: u32) -> Option<&'static str> {
    match svc {
        0 => Some("informationReport"),
        1 => Some("unsolicitedStatus"),
        2 => Some("eventNotification"),
        _ => None,
    }
}

/// ObjectClass basicObjectClass values (getNameList).
pub fn object_class_name(c: u32) -> Option<&'static str> {
    const NAMES: [&str; 14] = [
        "namedVariable",
        "scatteredAccess",
        "namedVariableList",
        "namedType",
        "semaphore",
        "eventCondition",
        "eventAction",
        "eventEnrollment",
        "journal",
        "domain",
        "programInvocation",
        "operatorStation",
        "dataExchange",
        "accessControlList",
    ];
    NAMES.get(c as usize).copied()
}

/// ServiceError errorClass CHOICE alternatives.
pub fn error_class_name(c: u32) -> Option<&'static str> {
    const NAMES: [&str; 13] = [
        "vmd-state",
        "application-reference",
        "definition",
        "resource",
        "service",
        "service-preempt",
        "time-resolution",
        "access",
        "initiate",
        "conclude",
        "cancel",
        "file",
        "others",
    ];
    NAMES.get(c as usize).copied()
}

/// ACSE AARE result.
pub fn acse_result_name(r: u32) -> &'static str {
    match r {
        0 => "accepted",
        1 => "rejected-permanent",
        2 => "rejected-transient",
        _ => "unknown",
    }
}

/// ISO 8327 session SPDU identifiers (SI).
pub const SPDU_DT: u8 = 0x01; // also Give Tokens
pub const SPDU_NF: u8 = 0x08;
pub const SPDU_FN: u8 = 0x09;
pub const SPDU_DN: u8 = 0x0A;
pub const SPDU_RF: u8 = 0x0C;
pub const SPDU_CN: u8 = 0x0D;
pub const SPDU_AC: u8 = 0x0E;
pub const SPDU_AB: u8 = 0x19;
pub const SPDU_AA: u8 = 0x1A;

/// Session PGI codes carrying presentation user data.
pub const SES_PGI_USER_DATA: u8 = 0xC1;
pub const SES_PGI_EXTENDED_USER_DATA: u8 = 0xC2;

pub fn spdu_name(si: u8) -> &'static str {
    match si {
        SPDU_DT => "data",
        SPDU_NF => "not_finished",
        SPDU_FN => "finish",
        SPDU_DN => "disconnect",
        SPDU_RF => "refuse",
        SPDU_CN => "connect",
        SPDU_AC => "accept",
        SPDU_AB => "abort",
        SPDU_AA => "abort_accept",
        _ => "unknown",
    }
}

/// IEC 61850 functional constraints in item names (LN$FC$...).
pub const FC_CONTROL: &str = "$CO$";
pub const FC_SETTINGS: [&str; 3] = ["$SP$", "$SG$", "$SE$"];
/// Report/log control blocks: client-side configuration, not process changes.
pub const FC_CONTROL_BLOCKS: [&str; 3] = ["$RP$", "$BR$", "$LG$"];

/// ICCP (IEC 60870-6-503) object a client reads to obtain a transfer set name.
pub const ICCP_NEXT_DS_TRANSFER_SET: &str = "Next_DSTransfer_Set";

pub const T_REMOTE_SYSTEM_INFO: &str = "T0888 Remote System Information Discovery";
pub const T_POINT_TAG_ID: &str = "T0861 Point & Tag Identification";
pub const T_UNAUTHORIZED_COMMAND: &str = "T0855 Unauthorized Command Message";
pub const T_MODIFY_PARAMETER: &str = "T0836 Modify Parameter";
pub const T_CHANGE_OPERATING_MODE: &str = "T0858 Change Operating Mode";
pub const T_PROGRAM_DOWNLOAD: &str = "T0843 Program Download";
pub const T_PROGRAM_UPLOAD: &str = "T0845 Program Upload";
pub const T_DATA_DESTRUCTION: &str = "T0809 Data Destruction";
pub const T_LATERAL_TOOL_TRANSFER: &str = "T0867 Lateral Tool Transfer";
pub const T_THEFT_OF_INFO: &str = "T0882 Theft of Operational Information";
pub const T_INDICATOR_REMOVAL: &str = "T0872 Indicator Removal on Host";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_names() {
        assert_eq!(service_name(SVC_WRITE), Some("write"));
        assert_eq!(service_name(SVC_FILE_DIRECTORY), Some("fileDirectory"));
        assert_eq!(service_name(SVC_START), Some("start"));
        assert_eq!(service_name(SVC_READ_JOURNAL), Some("readJournal"));
        assert_eq!(service_name(78), None);
        assert_eq!(service_from_name("GetNameList"), Some(SVC_GET_NAME_LIST));
        assert_eq!(service_from_name("fileDelete"), Some(SVC_FILE_DELETE));
        assert_eq!(service_from_name("nope"), None);
    }

    #[test]
    fn test_pdu_names() {
        assert_eq!(pdu_type_name(PDU_CONFIRMED_REQUEST), "confirmed_request");
        assert_eq!(pdu_type_name(PDU_CONCLUDE_ERROR), "conclude_error");
        assert_eq!(pdu_type_name(14), "unknown");
        assert_eq!(pdu_type_from_name("unconfirmed"), Some(PDU_UNCONFIRMED));
        assert_eq!(pdu_type_from_name("x"), None);
    }
}
