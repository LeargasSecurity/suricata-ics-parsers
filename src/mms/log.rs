// MMS EVE JSON logging for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use super::consts::*;
use super::parser::*;
use super::state::{Missing, MmsTransaction};
use crate::log::SCJsonBuilderWrapper;
use suricata::cast_pointer;
use suricata_sys::jsonbuilder::SCJsonBuilder;

type Js = SCJsonBuilderWrapper;

fn log_initiate(js: &mut Js, info: &InitiateInfo) -> Result<(), ()> {
    js.open_object("initiate")?;
    if let Some(v) = info.local_detail {
        js.set_uint("max_pdu_size", v as u64)?;
    }
    if let Some(v) = info.max_serv_outstanding_calling {
        js.set_uint("max_serv_outstanding_calling", v as u64)?;
    }
    if let Some(v) = info.max_serv_outstanding_called {
        js.set_uint("max_serv_outstanding_called", v as u64)?;
    }
    if let Some(v) = info.nesting_level {
        js.set_uint("nesting_level", v as u64)?;
    }
    if let Some(v) = info.version {
        js.set_uint("version", v as u64)?;
    }
    js.close()
}

fn log_objects(js: &mut Js, key: &str, objects: &[ObjectName]) -> Result<(), ()> {
    if objects.is_empty() {
        return Ok(());
    }
    js.open_array(key)?;
    for o in objects {
        js.start_object()?;
        js.set_string("scope", o.scope.as_str())?;
        if let Some(ref d) = o.domain {
            js.set_string("domain", d)?;
        }
        js.set_string("item", &o.item)?;
        js.close()?;
    }
    js.close()
}

fn log_mms(js: &mut Js, pdu: &MmsPdu) -> Result<(), ()> {
    js.set_string("pdu_type", pdu_type_name(pdu.pdu_type))?;
    if let Some(id) = pdu.invoke_id {
        js.set_uint("invoke_id", id as u64)?;
    }
    if let Some(svc) = pdu.service {
        let name = if pdu.pdu_type == PDU_UNCONFIRMED {
            unconfirmed_service_name(svc)
        } else {
            service_name(svc)
        };
        match name {
            Some(n) => js.set_string("service", n)?,
            None => js.set_uint("service", svc as u64)?,
        }
    }
    if let Some(c) = pdu.object_class {
        match object_class_name(c) {
            Some(n) => js.set_string("object_class", n)?,
            None => js.set_uint("object_class", c as u64)?,
        }
    }
    if let Some(ref d) = pdu.scope_domain {
        js.set_string("domain", d)?;
    }
    log_objects(js, "objects", &pdu.objects)?;
    log_objects(js, "members", &pdu.members)?;
    if !pdu.names.is_empty() {
        js.open_array("names")?;
        for n in &pdu.names {
            js.append_string(n)?;
        }
        js.close()?;
    }
    if !pdu.files.is_empty() {
        js.open_array("files")?;
        for f in &pdu.files {
            js.append_string(f)?;
        }
        js.close()?;
    }
    if pdu.success_count > 0 || pdu.failure_count > 0 {
        js.set_uint("success_count", pdu.success_count as u64)?;
        js.set_uint("failure_count", pdu.failure_count as u64)?;
    }
    if let Some((class, code)) = pdu.error {
        js.open_object("error")?;
        match error_class_name(class) {
            Some(n) => js.set_string("class", n)?,
            None => js.set_uint("class", class as u64)?,
        }
        js.set_uint("code", code as u64)?;
        js.close()?;
    }
    if let Some((reason, code)) = pdu.reject {
        js.open_object("reject")?;
        js.set_uint("reason", reason as u64)?;
        js.set_uint("code", code as u64)?;
        js.close()?;
    }
    if let Some(ref info) = pdu.initiate {
        log_initiate(js, info)?;
    }
    Ok(())
}

fn log_acse(js: &mut Js, a: &AcseApdu) -> Result<(), ()> {
    js.set_string("acse", a.kind.as_str())?;
    if let Some(ref v) = a.context_name {
        js.set_string("application_context", v)?;
    }
    let (called, calling) = match a.kind {
        AcseKind::Aare => ("responding", "calling"),
        _ => ("called", "calling"),
    };
    if let Some(ref v) = a.called_ap_title {
        js.set_string(&format!("{}_ap_title", called), v)?;
    }
    if let Some(v) = a.called_ae_qualifier {
        js.set_int(&format!("{}_ae_qualifier", called), v)?;
    }
    if let Some(ref v) = a.calling_ap_title {
        js.set_string(&format!("{}_ap_title", calling), v)?;
    }
    if let Some(v) = a.calling_ae_qualifier {
        js.set_int(&format!("{}_ae_qualifier", calling), v)?;
    }
    if let Some(ref v) = a.mechanism_name {
        js.set_string("authentication_mechanism", v)?;
    }
    if a.authentication {
        js.set_bool("authentication", true)?;
    }
    if let Some(r) = a.result {
        js.set_string("result", acse_result_name(r))?;
    }
    if let Some(r) = a.reason {
        js.set_uint("reason", r as u64)?;
    }
    if let Some(ref m) = a.mms {
        log_mms(js, m)?;
    }
    Ok(())
}

fn log_apdu(js: &mut Js, key: &str, apdu: &Apdu, to_server: bool) -> Result<(), ()> {
    js.open_object(key)?;
    js.set_string(
        "direction",
        if to_server { "to_server" } else { "to_client" },
    )?;
    match apdu {
        Apdu::Acse(a) => log_acse(js, a)?,
        Apdu::Mms(m) => log_mms(js, m)?,
    }
    js.close()
}

fn log_tx(tx: &MmsTransaction, js: &mut Js) -> Result<(), ()> {
    js.open_object("mms")?;
    if let Some(si) = tx.spdu {
        js.set_string("session", spdu_name(si))?;
    }
    if let Some(ref req) = tx.request {
        log_apdu(js, "request", req, tx.request_to_server)?;
    }
    if let Some(ref resp) = tx.response {
        log_apdu(js, "response", resp, !tx.request_to_server)?;
    }
    // Danger can't be judged when the request itself was not seen; omit the
    // flag rather than report a misleading "false".
    let request_unseen = tx.loss.is_some_and(|l| l.missing != Missing::Response);
    if !request_unseen {
        js.set_bool("is_dangerous", tx.is_dangerous)?;
    }
    if let Some(t) = tx.attack_technique {
        js.set_string("attack_technique", t)?;
    }
    if tx.iccp_transfer_set {
        js.set_bool("iccp_transfer_set", true)?;
    }
    if let Some(l) = tx.loss {
        js.open_object("telemetry")?;
        js.set_bool("complete", false)?;
        js.set_string("reason", l.reason.as_str())?;
        js.set_string("missing", l.missing.as_str())?;
        js.set_string(
            "direction",
            if l.to_server {
                "to_server"
            } else {
                "to_client"
            },
        )?;
        js.close()?;
    }
    js.close()
}

pub(crate) unsafe extern "C" fn mms_logger_log(
    tx: *const std::os::raw::c_void,
    js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    let js = cast_pointer!(js, SCJsonBuilder);
    let mut js = SCJsonBuilderWrapper { inner: js };
    log_tx(tx, &mut js).is_ok()
}
