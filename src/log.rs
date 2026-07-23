// S7comm EVE JSON logging for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::s7comm::S7commTransaction;
use std::ffi::CString;
use suricata::cast_pointer;
use suricata_sys::jsonbuilder::{
    SCJbClose, SCJbOpenObject, SCJbSetBool, SCJbSetString, SCJbSetUint, SCJsonBuilder,
};

pub struct SCJsonBuilderWrapper {
    inner: *mut SCJsonBuilder,
}

impl SCJsonBuilderWrapper {
    fn close(&mut self) -> Result<(), ()> {
        if unsafe { !SCJbClose(self.inner) } {
            return Err(());
        }
        Ok(())
    }
    fn open_object(&mut self, key: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbOpenObject(self.inner, keyc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
    fn set_string(&mut self, key: &str, val: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !SCJbSetString(self.inner, keyc.as_ptr(), valc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
    fn set_uint(&mut self, key: &str, val: u64) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetUint(self.inner, keyc.as_ptr(), val) } {
            return Err(());
        }
        Ok(())
    }
    fn set_bool(&mut self, key: &str, val: bool) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetBool(self.inner, keyc.as_ptr(), val) } {
            return Err(());
        }
        Ok(())
    }
}

fn log_s7comm(tx: &S7commTransaction, js: &mut SCJsonBuilderWrapper) -> Result<(), ()> {
    js.open_object("s7comm")?;

    js.set_uint("pdu_reference", tx.pdu_reference as u64)?;

    let rosctr_str = match tx.request_rosctr {
        0x01 => "Job",
        0x02 => "Ack",
        0x03 => "Ack_Data",
        0x07 => "Userdata",
        _ => "Unknown",
    };
    js.set_string("rosctr", rosctr_str)?;

    if tx.request_function_code != 0 {
        js.set_uint("function_code", tx.request_function_code as u64)?;
        let hex = format!("0x{:02x}", tx.request_function_code);
        js.set_string("function_code_hex", &hex)?;
    }

    if let Some(name) = tx.request_function_name {
        js.set_string("function_name", name)?;
    }

    if tx.request_userdata_group != 0 {
        js.set_uint("userdata_group", tx.request_userdata_group as u64)?;
        js.set_uint("userdata_subfunction", tx.request_userdata_subfunction as u64)?;
    }

    js.set_bool("is_dangerous", tx.is_dangerous)?;

    if let Some(technique) = tx.attack_technique {
        js.set_string("attack_technique", technique)?;
    }

    if tx.response_error_class != 0 || tx.response_error_code != 0 {
        js.set_uint("error_class", tx.response_error_class as u64)?;
        js.set_uint("error_code", tx.response_error_code as u64)?;
    }

    if tx.is_s7comm_plus {
        js.set_bool("s7comm_plus", true)?;
    }

    js.close()?;
    Ok(())
}

pub(crate) unsafe extern "C" fn s7comm_logger_log(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, S7commTransaction);
    let js = cast_pointer!(js, SCJsonBuilder);
    let mut js = SCJsonBuilderWrapper { inner: js };
    log_s7comm(tx, &mut js).is_ok()
}
