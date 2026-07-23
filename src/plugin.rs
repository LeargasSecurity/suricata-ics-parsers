// S7comm Suricata plugin registration
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::detect::detect_s7comm_register;
use crate::log::s7comm_logger_log;
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
