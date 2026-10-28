// MMS detection keyword registration for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0
//
// Each keyword matches a field in the direction of the message it came from:
// request fields (service, object names, dangerous) in the request direction,
// response fields (response pdu_type) in the response direction.

use super::consts::{pdu_type_from_name, service_from_name};
use super::parser::Apdu;
use super::state::{apdu_mms, MmsTransaction, ALPROTO_MMS};
use std::ffi::{CStr, CString};
use std::os::raw::{c_int, c_void};
use suricata::cast_pointer;
use suricata::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use suricata::detect::uint::{DetectUintData, SCDetectU8Free, SCDetectU8Match, SCDetectU8Parse};
use suricata::detect::{
    helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer, SIGMATCH_NOOPT,
};
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferProgressRegister, SCDetectHelperKeywordRegister,
    SCDetectHelperMultiBufferMpmRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

static mut G_MMS_PDU_TYPE_KW_ID: u16 = 0;
static mut G_MMS_SERVICE_KW_ID: u16 = 0;
static mut G_MMS_DANGEROUS_KW_ID: u16 = 0;
static mut G_MMS_ICCP_TS_KW_ID: u16 = 0;
static mut G_MMS_GENERIC_BUFFER_ID: c_int = 0;
static mut G_MMS_DOMAIN_BUFFER_ID: c_int = 0;
static mut G_MMS_ITEM_BUFFER_ID: c_int = 0;
static mut G_MMS_FILENAME_BUFFER_ID: c_int = 0;

/// True if the inspected direction is the request direction of `tx`.
fn in_request_direction(tx: &MmsTransaction, flags: u8) -> bool {
    (flags & STREAM_TOSERVER != 0) == tx.request_to_server
}

/// Parse a uint keyword value, accepting a symbolic name for an exact match.
unsafe fn parse_u8_named(
    raw: *const libc::c_char,
    lookup: fn(&str) -> Option<u32>,
) -> *mut DetectUintData<u8> {
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    let s = match CStr::from_ptr(raw).to_str() {
        Ok(s) => s.trim(),
        Err(_) => return std::ptr::null_mut(),
    };
    match lookup(s) {
        Some(v) if v <= u8::MAX as u32 => {
            let num = CString::new(v.to_string()).unwrap();
            SCDetectU8Parse(num.as_ptr())
        }
        Some(_) => std::ptr::null_mut(),
        None => SCDetectU8Parse(raw),
    }
}

unsafe fn setup_u8_named(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
    kw_id: u16,
    lookup: fn(&str) -> Option<u32>,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MMS) != 0 {
        return -1;
    }
    let ctx = parse_u8_named(raw, lookup) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        kw_id,
        ctx as *mut SigMatchCtx,
        G_MMS_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        mms_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn mms_detect_u8_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

// --- pdu_type keyword ---

fn pdu_lookup(s: &str) -> Option<u32> {
    pdu_type_from_name(s).map(|v| v as u32)
}

unsafe extern "C" fn mms_pdu_type_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    setup_u8_named(de, s, raw, G_MMS_PDU_TYPE_KW_ID, pdu_lookup)
}

unsafe extern "C" fn mms_pdu_type_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MmsTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    let apdu = if in_request_direction(tx, flags) {
        tx.request.as_ref()
    } else {
        tx.response.as_ref()
    };
    match apdu {
        Some(Apdu::Mms(m)) => SCDetectU8Match(m.pdu_type, ctx),
        Some(Apdu::Acse(a)) => match a.mms {
            Some(ref m) => SCDetectU8Match(m.pdu_type, ctx),
            None => 0,
        },
        None => 0,
    }
}

// --- service keyword ---

unsafe extern "C" fn mms_service_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    setup_u8_named(de, s, raw, G_MMS_SERVICE_KW_ID, service_from_name)
}

unsafe extern "C" fn mms_service_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MmsTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    if !in_request_direction(tx, flags) && tx.request.is_some() {
        return 0;
    }
    match tx.service() {
        Some(svc) if svc <= u8::MAX as u32 => SCDetectU8Match(svc as u8, ctx),
        _ => 0,
    }
}

// --- dangerous keyword ---

unsafe fn flag_setup(de: *mut DetectEngineCtx, s: *mut Signature, kw_id: u16) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MMS) != 0 {
        return -1;
    }
    if SCSigMatchAppendSMToList(de, s, kw_id, std::ptr::null_mut(), G_MMS_GENERIC_BUFFER_ID)
        .is_null()
    {
        return -1;
    }
    0
}

unsafe extern "C" fn mms_dangerous_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    flag_setup(de, s, G_MMS_DANGEROUS_KW_ID)
}

unsafe extern "C" fn mms_dangerous_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    _ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MmsTransaction);
    (tx.is_dangerous && in_request_direction(tx, flags)) as c_int
}

// --- iccp_transfer_set keyword ---

unsafe extern "C" fn mms_iccp_ts_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    flag_setup(de, s, G_MMS_ICCP_TS_KW_ID)
}

unsafe extern "C" fn mms_iccp_ts_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    _ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, MmsTransaction);
    (tx.iccp_transfer_set && in_request_direction(tx, flags)) as c_int
}

// --- multi-buffers: mms.domain, mms.item, mms.filename ---

unsafe fn set_buffer(buf: *mut *const u8, len: *mut u32, s: &str) -> bool {
    *buf = s.as_ptr();
    *len = s.len() as u32;
    true
}

unsafe extern "C" fn mms_domain_get(
    _de: *mut DetectEngineThreadCtx,
    tx: *const c_void,
    flags: u8,
    local_id: u32,
    buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    let pdu = match tx.request.as_ref().and_then(apdu_mms) {
        Some(p) if in_request_direction(tx, flags) => p,
        _ => return false,
    };
    // Object domains, then the getNameList / delete scope domain, then domain service names.
    let domains = pdu
        .objects
        .iter()
        .filter_map(|o| o.domain.as_deref())
        .chain(pdu.scope_domain.as_deref())
        .chain(pdu.names.iter().map(|n| n.as_str()));
    match domains.into_iter().nth(local_id as usize) {
        Some(d) => set_buffer(buf, len, d),
        None => false,
    }
}

unsafe extern "C" fn mms_item_get(
    _de: *mut DetectEngineThreadCtx,
    tx: *const c_void,
    flags: u8,
    local_id: u32,
    buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    match tx.request.as_ref().and_then(apdu_mms) {
        Some(p) if in_request_direction(tx, flags) => match p.objects.get(local_id as usize) {
            Some(o) => set_buffer(buf, len, &o.item),
            None => false,
        },
        _ => false,
    }
}

unsafe extern "C" fn mms_filename_get(
    _de: *mut DetectEngineThreadCtx,
    tx: *const c_void,
    flags: u8,
    local_id: u32,
    buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, MmsTransaction);
    match tx.request.as_ref().and_then(apdu_mms) {
        Some(p) if in_request_direction(tx, flags) => match p.files.get(local_id as usize) {
            Some(f) => set_buffer(buf, len, f),
            None => false,
        },
        _ => false,
    }
}

unsafe extern "C" fn mms_domain_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    sticky_setup(de, s, G_MMS_DOMAIN_BUFFER_ID)
}

unsafe extern "C" fn mms_item_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    sticky_setup(de, s, G_MMS_ITEM_BUFFER_ID)
}

unsafe extern "C" fn mms_filename_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    sticky_setup(de, s, G_MMS_FILENAME_BUFFER_ID)
}

unsafe fn sticky_setup(de: *mut DetectEngineCtx, s: *mut Signature, list: c_int) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_MMS) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, list) < 0 {
        return -1;
    }
    0
}

// --- Registration ---

pub(crate) unsafe extern "C" fn detect_mms_register() {
    G_MMS_GENERIC_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"mms.generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        1,
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"mms.pdu_type\0".as_ptr() as *const libc::c_char,
        desc: b"match MMS PDU type (number or name, e.g. confirmed_request)\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/mms-keywords.html#pdu-type\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mms_pdu_type_match),
        Setup: Some(mms_pdu_type_setup),
        Free: Some(mms_detect_u8_free),
        flags: 0,
    };
    G_MMS_PDU_TYPE_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"mms.service\0".as_ptr() as *const libc::c_char,
        desc: b"match MMS confirmed service (number or name, e.g. write)\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/mms-keywords.html#service\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mms_service_match),
        Setup: Some(mms_service_setup),
        Free: Some(mms_detect_u8_free),
        flags: 0,
    };
    G_MMS_SERVICE_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"mms.dangerous\0".as_ptr() as *const libc::c_char,
        desc: b"match MMS requests that control, reconfigure, download to or delete from a device\0"
            .as_ptr() as *const libc::c_char,
        url: b"/rules/mms-keywords.html#dangerous\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mms_dangerous_match),
        Setup: Some(mms_dangerous_setup),
        Free: None,
        flags: SIGMATCH_NOOPT,
    };
    G_MMS_DANGEROUS_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"mms.iccp_transfer_set\0".as_ptr() as *const libc::c_char,
        desc: b"match MMS writes to an ICCP transfer set learned from Next_DSTransfer_Set\0"
            .as_ptr() as *const libc::c_char,
        url: b"/rules/mms-keywords.html#iccp-transfer-set\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(mms_iccp_ts_match),
        Setup: Some(mms_iccp_ts_setup),
        Free: None,
        flags: SIGMATCH_NOOPT,
    };
    G_MMS_ICCP_TS_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let sticky = SigTableElmtStickyBuffer {
        name: String::from("mms.domain"),
        desc: String::from("sticky buffer to match MMS domain names in a request (multi-buffer)"),
        url: String::from("/rules/mms-keywords.html#domain"),
        setup: mms_domain_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&sticky);
    G_MMS_DOMAIN_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"mms.domain\0".as_ptr() as *const libc::c_char,
        b"MMS domain name\0".as_ptr() as *const libc::c_char,
        ALPROTO_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(mms_domain_get),
    );

    let sticky = SigTableElmtStickyBuffer {
        name: String::from("mms.item"),
        desc: String::from(
            "sticky buffer to match MMS object (item) names in a request (multi-buffer)",
        ),
        url: String::from("/rules/mms-keywords.html#item"),
        setup: mms_item_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&sticky);
    G_MMS_ITEM_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"mms.item\0".as_ptr() as *const libc::c_char,
        b"MMS item name\0".as_ptr() as *const libc::c_char,
        ALPROTO_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(mms_item_get),
    );

    let sticky = SigTableElmtStickyBuffer {
        name: String::from("mms.filename"),
        desc: String::from("sticky buffer to match MMS file names in a request (multi-buffer)"),
        url: String::from("/rules/mms-keywords.html#filename"),
        setup: mms_filename_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&sticky);
    G_MMS_FILENAME_BUFFER_ID = SCDetectHelperMultiBufferMpmRegister(
        b"mms.filename\0".as_ptr() as *const libc::c_char,
        b"MMS file name\0".as_ptr() as *const libc::c_char,
        ALPROTO_MMS,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(mms_filename_get),
    );
}
