// S7comm Suricata plugin registration
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::detect::detect_s7comm_register;
use crate::iec104::detect::detect_iec104_register;
use crate::iec104::log::iec104_logger_log;
use crate::iec104::state::iec104_register_parser;
use crate::log::s7comm_logger_log;
use crate::mms::detect::detect_mms_register;
use crate::mms::log::mms_logger_log;
use crate::mms::state::mms_register_parser;
use crate::s7comm::s7comm_register_parser;
use std::ffi::CString;
use suricata::{SCLogError, SCLogNotice};
use suricata_sys::sys::{
    SCAppLayerPlugin, SCOutputJsonLogDirection, SCPlugin, SCPluginRegisterAppLayer, SC_API_VERSION,
    SC_PACKAGE_VERSION,
};

extern "C" fn s7comm_plugin_init() {
    suricata::plugin::init();
    SCLogNotice!("Initializing S7comm ICS protocol parser plugin");
    let plugin = SCAppLayerPlugin {
        name: b"s7comm\0".as_ptr() as *const libc::c_char,
        logname: b"JsonS7commLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.s7comm\0".as_ptr() as *const libc::c_char,
        dir: SCOutputJsonLogDirection::LOG_DIR_PACKET as u8,
        Register: Some(s7comm_register_parser),
        Logger: Some(s7comm_logger_log),
        KeywordsRegister: Some(detect_s7comm_register),
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            SCLogError!("Failed to register S7comm plugin");
        }
    }

    SCLogNotice!("Initializing IEC 60870-5-104 ICS protocol parser plugin");
    let plugin = SCAppLayerPlugin {
        name: b"iec104\0".as_ptr() as *const libc::c_char,
        logname: b"JsonIec104Log\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.iec104\0".as_ptr() as *const libc::c_char,
        dir: SCOutputJsonLogDirection::LOG_DIR_PACKET as u8,
        Register: Some(iec104_register_parser),
        Logger: Some(iec104_logger_log),
        KeywordsRegister: Some(detect_iec104_register),
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            SCLogError!("Failed to register IEC 60870-5-104 plugin");
        }
    }

    SCLogNotice!("Initializing MMS (IEC 61850 / ICCP) ICS protocol parser plugin");
    let plugin = SCAppLayerPlugin {
        name: b"mms\0".as_ptr() as *const libc::c_char,
        logname: b"JsonMmsLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.mms\0".as_ptr() as *const libc::c_char,
        dir: SCOutputJsonLogDirection::LOG_DIR_PACKET as u8,
        Register: Some(mms_register_parser),
        Logger: Some(mms_logger_log),
        KeywordsRegister: Some(detect_mms_register),
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            SCLogError!("Failed to register MMS plugin");
        }
    }
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin_version =
        CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw() as *const libc::c_char;
    let plugin = SCPlugin {
        version: SC_API_VERSION,
        suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const libc::c_char,
        name: b"s7comm\0".as_ptr() as *const libc::c_char,
        plugin_version,
        license: b"GPL-2.0\0".as_ptr() as *const libc::c_char,
        author: b"Leargas Security\0".as_ptr() as *const libc::c_char,
        Init: Some(s7comm_plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
