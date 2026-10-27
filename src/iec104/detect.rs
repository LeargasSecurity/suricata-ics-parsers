// IEC 60870-5-104 detection keyword registration for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use super::state::{Iec104Transaction, ALPROTO_IEC104};
use std::os::raw::{c_int, c_void};
use suricata::cast_pointer;
use suricata::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use suricata::detect::uint::{
    DetectUintData, SCDetectU16Free, SCDetectU16Match, SCDetectU16Parse, SCDetectU32Free,
    SCDetectU32Match, SCDetectU32Parse, SCDetectU8Free, SCDetectU8Match, SCDetectU8Parse,
};
use suricata::detect::{
    helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer, SIGMATCH_NOOPT,
};
use suricata::direction::Direction;
use suricata_sys::sys::{
    DetectEngineCtx, DetectEngineThreadCtx, Flow, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectHelperBufferProgressRegister,
    SCDetectHelperKeywordRegister, SCDetectSignatureSetAppProto, SCSigMatchAppendSMToList,
    SCSigTableAppLiteElmt, SigMatchCtx, Signature,
};

static mut G_IEC104_TYPE_ID_KW_ID: u16 = 0;
static mut G_IEC104_COT_KW_ID: u16 = 0;
static mut G_IEC104_COMMON_ADDRESS_KW_ID: u16 = 0;
static mut G_IEC104_IOA_KW_ID: u16 = 0;
static mut G_IEC104_U_FUNCTION_KW_ID: u16 = 0;
static mut G_IEC104_DANGEROUS_KW_ID: u16 = 0;
static mut G_IEC104_GENERIC_BUFFER_ID: c_int = 0;
static mut G_IEC104_DATA_BUFFER_ID: c_int = 0;

// --- shared setup / free helpers ---

unsafe fn append_sm(
    de: *mut DetectEngineCtx, s: *mut Signature, kw_id: u16, ctx: *mut c_void,
) -> bool {
    !SCSigMatchAppendSMToList(de, s, kw_id, ctx as *mut SigMatchCtx, G_IEC104_GENERIC_BUFFER_ID)
        .is_null()
}

unsafe fn setup_u8(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char, kw_id: u16,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if !append_sm(de, s, kw_id, ctx) {
        iec104_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe fn setup_u16(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char, kw_id: u16,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if !append_sm(de, s, kw_id, ctx) {
        iec104_detect_u16_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe fn setup_u32(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char, kw_id: u16,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    let ctx = SCDetectU32Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if !append_sm(de, s, kw_id, ctx) {
        iec104_detect_u32_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn iec104_detect_u8_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn iec104_detect_u16_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

unsafe extern "C" fn iec104_detect_u32_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    SCDetectU32Free(ctx);
}

// --- type_id keyword (u8) ---

unsafe extern "C" fn iec104_type_id_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    setup_u8(de, s, raw, G_IEC104_TYPE_ID_KW_ID)
}

unsafe extern "C" fn iec104_type_id_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    match tx.asdu() {
        Some(a) => SCDetectU8Match(a.type_id, ctx),
        None => 0,
    }
}

// --- cot keyword (u8) ---

unsafe extern "C" fn iec104_cot_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    setup_u8(de, s, raw, G_IEC104_COT_KW_ID)
}

unsafe extern "C" fn iec104_cot_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    match tx.asdu() {
        Some(a) => SCDetectU8Match(a.cot, ctx),
        None => 0,
    }
}

// --- common_address keyword (u16) ---

unsafe extern "C" fn iec104_common_address_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    setup_u16(de, s, raw, G_IEC104_COMMON_ADDRESS_KW_ID)
}

unsafe extern "C" fn iec104_common_address_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    match tx.asdu() {
        Some(a) => SCDetectU16Match(a.common_address, ctx),
        None => 0,
    }
}

// --- ioa keyword (u32, matches any information object in the ASDU) ---

unsafe extern "C" fn iec104_ioa_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    setup_u32(de, s, raw, G_IEC104_IOA_KW_ID)
}

unsafe extern "C" fn iec104_ioa_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u32>);
    if let Some(a) = tx.asdu() {
        for ioa in &a.ioas {
            if SCDetectU32Match(*ioa, ctx) == 1 {
                return 1;
            }
        }
    }
    0
}

// --- u_function keyword (u8, U-format frames only) ---

unsafe extern "C" fn iec104_u_function_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, raw: *const libc::c_char,
) -> c_int {
    setup_u8(de, s, raw, G_IEC104_U_FUNCTION_KW_ID)
}

unsafe extern "C" fn iec104_u_function_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    match tx.apdu.as_ref().and_then(|a| a.u_function) {
        Some(u) => SCDetectU8Match(u, ctx),
        None => 0,
    }
}

// --- dangerous keyword ---

unsafe extern "C" fn iec104_dangerous_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    if !append_sm(de, s, G_IEC104_DANGEROUS_KW_ID, std::ptr::null_mut()) {
        return -1;
    }
    0
}

unsafe extern "C" fn iec104_dangerous_match(
    _de: *mut DetectEngineThreadCtx, _f: *mut Flow, _flags: u8, _state: *mut c_void,
    tx: *mut c_void, _sig: *const Signature, _ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, Iec104Transaction);
    if tx.is_dangerous {
        1
    } else {
        0
    }
}

// --- data sticky buffer ---

unsafe extern "C" fn iec104_data_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_IEC104_DATA_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn iec104_data_get(
    tx: *const c_void, flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, Iec104Transaction);
    let to_client = flags & Direction::ToClient as u8 != 0;
    if to_client == tx.to_server || tx.buffer.is_empty() {
        return false;
    }
    *len = tx.buffer.len() as u32;
    *buf = tx.buffer.as_ptr();
    true
}

// --- Registration ---

pub(crate) unsafe extern "C" fn detect_iec104_register() {
    G_IEC104_GENERIC_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"iec104.generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC104,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        1,
    );

    let kw = SCSigTableAppLiteElmt {
        name: b"iec104.type_id\0".as_ptr() as *const libc::c_char,
        desc: b"match IEC 60870-5-104 ASDU type identification\0".as_ptr() as *const libc::c_char,
        url: b"/rules/iec104-keywords.html#type-id\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(iec104_type_id_match),
        Setup: Some(iec104_type_id_setup),
        Free: Some(iec104_detect_u8_free),
        flags: 0,
    };
    G_IEC104_TYPE_ID_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"iec104.cot\0".as_ptr() as *const libc::c_char,
        desc: b"match IEC 60870-5-104 cause of transmission\0".as_ptr() as *const libc::c_char,
        url: b"/rules/iec104-keywords.html#cot\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(iec104_cot_match),
        Setup: Some(iec104_cot_setup),
        Free: Some(iec104_detect_u8_free),
        flags: 0,
    };
    G_IEC104_COT_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"iec104.common_address\0".as_ptr() as *const libc::c_char,
        desc: b"match IEC 60870-5-104 common address of ASDU\0".as_ptr() as *const libc::c_char,
        url: b"/rules/iec104-keywords.html#common-address\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(iec104_common_address_match),
        Setup: Some(iec104_common_address_setup),
        Free: Some(iec104_detect_u16_free),
        flags: 0,
    };
    G_IEC104_COMMON_ADDRESS_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"iec104.ioa\0".as_ptr() as *const libc::c_char,
        desc: b"match any IEC 60870-5-104 information object address in the ASDU\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/iec104-keywords.html#ioa\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(iec104_ioa_match),
        Setup: Some(iec104_ioa_setup),
        Free: Some(iec104_detect_u32_free),
        flags: 0,
    };
    G_IEC104_IOA_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"iec104.u_function\0".as_ptr() as *const libc::c_char,
        desc: b"match IEC 60870-5-104 U-format control function\0".as_ptr() as *const libc::c_char,
        url: b"/rules/iec104-keywords.html#u-function\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(iec104_u_function_match),
        Setup: Some(iec104_u_function_setup),
        Free: Some(iec104_detect_u8_free),
        flags: 0,
    };
    G_IEC104_U_FUNCTION_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let kw = SCSigTableAppLiteElmt {
        name: b"iec104.dangerous\0".as_ptr() as *const libc::c_char,
        desc: b"match if IEC 60870-5-104 operation is a control/parameter/reset command\0".as_ptr()
            as *const libc::c_char,
        url: b"/rules/iec104-keywords.html#dangerous\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(iec104_dangerous_match),
        Setup: Some(iec104_dangerous_setup),
        Free: None,
        flags: SIGMATCH_NOOPT,
    };
    G_IEC104_DANGEROUS_KW_ID = SCDetectHelperKeywordRegister(&kw);

    let sticky = SigTableElmtStickyBuffer {
        name: String::from("iec104.data"),
        desc: String::from("sticky buffer to match on the raw IEC 60870-5-104 APDU"),
        url: String::from("/rules/iec104-keywords.html#data"),
        setup: iec104_data_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&sticky);
    G_IEC104_DATA_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"iec104.data\0".as_ptr() as *const libc::c_char,
        b"IEC 60870-5-104 APDU\0".as_ptr() as *const libc::c_char,
        ALPROTO_IEC104,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(iec104_data_get),
    );
}
