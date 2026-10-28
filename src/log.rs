// S7comm EVE JSON logging for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::s7comm::S7commTransaction;
use std::ffi::CString;
use suricata::cast_pointer;
use suricata_sys::jsonbuilder::{
    SCJbAppendString, SCJbClose, SCJbOpenArray, SCJbOpenObject, SCJbSetBool, SCJbSetFloat,
    SCJbSetInt, SCJbSetString, SCJbSetUint, SCJbStartObject, SCJsonBuilder,
};

pub struct SCJsonBuilderWrapper {
    pub(crate) inner: *mut SCJsonBuilder,
}

impl SCJsonBuilderWrapper {
    pub(crate) fn close(&mut self) -> Result<(), ()> {
        if unsafe { !SCJbClose(self.inner) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn open_object(&mut self, key: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbOpenObject(self.inner, keyc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn set_string(&mut self, key: &str, val: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !SCJbSetString(self.inner, keyc.as_ptr(), valc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn set_uint(&mut self, key: &str, val: u64) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetUint(self.inner, keyc.as_ptr(), val) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn set_int(&mut self, key: &str, val: i64) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetInt(self.inner, keyc.as_ptr(), val) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn set_float(&mut self, key: &str, val: f64) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetFloat(self.inner, keyc.as_ptr(), val) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn set_bool(&mut self, key: &str, val: bool) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbSetBool(self.inner, keyc.as_ptr(), val) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn open_array(&mut self, key: &str) -> Result<(), ()> {
        let keyc = CString::new(key).unwrap();
        if unsafe { !SCJbOpenArray(self.inner, keyc.as_ptr()) } {
            return Err(());
        }
        Ok(())
    }
    /// Start an anonymous object inside an open array.
    pub(crate) fn start_object(&mut self) -> Result<(), ()> {
        if unsafe { !SCJbStartObject(self.inner) } {
            return Err(());
        }
        Ok(())
    }
    pub(crate) fn append_string(&mut self, val: &str) -> Result<(), ()> {
        let valc = CString::new(val.escape_default().to_string()).unwrap();
        if unsafe { !SCJbAppendString(self.inner, valc.as_ptr()) } {
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
        if let Some(gname) = tx.request_userdata_group_name {
            js.set_string("userdata_group_name", gname)?;
        }
        js.set_uint(
            "userdata_subfunction",
            tx.request_userdata_subfunction as u64,
        )?;
    }

    // Data item (Read/Write Variable addressing)
    if tx.has_data_item {
        js.open_object("item")?;
        js.set_uint("count", tx.item_count as u64)?;
        js.set_uint("area", tx.item_area as u64)?;
        if let Some(aname) = tx.item_area_name {
            js.set_string("area_name", aname)?;
        }
        js.set_uint("db_number", tx.item_db_number as u64)?;
        js.set_uint("address", tx.item_address as u64)?;
        js.set_uint("length", tx.item_length as u64)?;
        js.close()?;
    }

    // COTP connection addressing (rack/slot)
    if tx.has_tsap {
        js.open_object("cotp")?;
        js.set_uint("src_tsap", tx.src_tsap as u64)?;
        js.set_uint("dst_tsap", tx.dst_tsap as u64)?;
        js.set_uint("rack", tx.rack as u64)?;
        js.set_uint("slot", tx.slot as u64)?;
        js.close()?;
    }

    // PLC control service
    if let Some(svc) = tx.plc_control_service {
        js.set_string("plc_control_service", svc)?;
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
        js.open_object("plus")?;
        js.set_uint("version", tx.s7plus_version as u64)?;
        js.set_uint("opcode", tx.s7plus_opcode as u64)?;
        if let Some(oname) = tx.s7plus_opcode_name {
            js.set_string("opcode_name", oname)?;
        }
        if tx.s7plus_has_function {
            js.set_uint("function", tx.s7plus_function as u64)?;
            let fhex = format!("0x{:04x}", tx.s7plus_function);
            js.set_string("function_hex", &fhex)?;
            if let Some(fname) = tx.s7plus_function_name {
                js.set_string("function_name", fname)?;
            }
            js.set_uint("sequence_number", tx.s7plus_seqnum as u64)?;
        }
        js.close()?;
    }

    js.close()?;
    Ok(())
}

pub(crate) unsafe extern "C" fn s7comm_logger_log(
    tx: *const std::os::raw::c_void,
    js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, S7commTransaction);
    let js = cast_pointer!(js, SCJsonBuilder);
    let mut js = SCJsonBuilderWrapper { inner: js };
    log_s7comm(tx, &mut js).is_ok()
}
