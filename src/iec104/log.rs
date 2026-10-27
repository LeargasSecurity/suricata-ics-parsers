// IEC 60870-5-104 EVE JSON logging for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use super::consts::*;
use super::parser::CommandValue;
use super::state::Iec104Transaction;
use crate::log::SCJsonBuilderWrapper;
use suricata::cast_pointer;
use suricata_sys::jsonbuilder::SCJsonBuilder;

fn log_iec104(tx: &Iec104Transaction, js: &mut SCJsonBuilderWrapper) -> Result<(), ()> {
    js.open_object("iec104")?;
    js.set_string("direction", if tx.to_server { "to_server" } else { "to_client" })?;

    js.open_object("apci")?;
    js.set_uint("length", tx.length as u64)?;
    if let Some(ref apdu) = tx.apdu {
        js.set_string("format", apdu.format.as_str())?;
        if let Some(ns) = apdu.send_seq {
            js.set_uint("send_seq", ns as u64)?;
        }
        if let Some(nr) = apdu.recv_seq {
            js.set_uint("recv_seq", nr as u64)?;
        }
        if let Some(u) = apdu.u_function {
            js.set_uint("u_function", u as u64)?;
            js.set_string("u_function_name", u_function_name(u).unwrap_or("unknown"))?;
        }
    }
    js.close()?;

    if let Some(a) = tx.asdu() {
        js.open_object("asdu")?;
        js.set_uint("type_id", a.type_id as u64)?;
        if let Some(name) = type_id_name(a.type_id) {
            js.set_string("type_name", name)?;
        }
        js.set_bool("sq", a.sq)?;
        js.set_uint("num_objects", a.num_objects as u64)?;
        js.set_uint("cot", a.cot as u64)?;
        if let Some(name) = cot_name(a.cot) {
            js.set_string("cot_name", name)?;
        }
        js.set_bool("negative", a.negative)?;
        js.set_bool("test", a.test)?;
        js.set_uint("originator", a.originator as u64)?;
        js.set_uint("common_address", a.common_address as u64)?;
        if let Some(ioa) = a.ioas.first() {
            js.set_uint("ioa", *ioa as u64)?;
        }
        if let Some(q) = a.qualifier {
            js.set_uint("qualifier", q as u64)?;
        }
        if let Some(ref c) = a.command {
            js.open_object("command")?;
            if let Some(select) = c.select {
                js.set_bool("select", select)?;
            }
            if let Some(q) = c.qualifier {
                js.set_uint("qualifier", q as u64)?;
            }
            match c.value {
                CommandValue::State(s) => js.set_uint("state", s as u64)?,
                CommandValue::Normalized(v) => js.set_float("value", v as f64 / 32768.0)?,
                CommandValue::Scaled(v) => js.set_int("value", v as i64)?,
                CommandValue::Float(v) => {
                    // NaN/Inf would produce invalid JSON.
                    if v.is_finite() {
                        js.set_float("value", v as f64)?;
                    }
                }
                CommandValue::Bitstring(v) => js.set_string("bitstring", &format!("0x{:08x}", v))?,
            }
            js.close()?;
        }
        js.close()?;
    }

    js.set_bool("is_dangerous", tx.is_dangerous)?;
    if let Some(technique) = tx.attack_technique {
        js.set_string("attack_technique", technique)?;
    }

    js.close()?;
    Ok(())
}

pub(crate) unsafe extern "C" fn iec104_logger_log(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let js = cast_pointer!(js, SCJsonBuilder);
    let mut js = SCJsonBuilderWrapper { inner: js };
    log_iec104(tx, &mut js).is_ok()
}
