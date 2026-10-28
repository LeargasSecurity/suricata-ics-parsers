// S7comm detection keyword registration for Suricata
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use crate::s7comm::{S7commTransaction, ALPROTO_S7COMM};
use std::os::raw::{c_int, c_void};
use suricata::cast_pointer;
use suricata::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use suricata::detect::uint::{
    DetectUintData, SCDetectU16Free, SCDetectU16Match, SCDetectU16Parse, SCDetectU8Free,
    SCDetectU8Match, SCDetectU8Parse,
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

static mut G_S7COMM_FUNCTION_CODE_KW_ID: u16 = 0;
static mut G_S7COMM_ROSCTR_KW_ID: u16 = 0;
static mut G_S7COMM_DANGEROUS_KW_ID: u16 = 0;
static mut G_S7COMM_USERDATA_GROUP_KW_ID: u16 = 0;
static mut G_S7COMM_SUBFUNCTION_KW_ID: u16 = 0;
static mut G_S7COMM_PLUS_KW_ID: u16 = 0;
static mut G_S7COMM_DB_KW_ID: u16 = 0;
static mut G_S7COMM_AREA_KW_ID: u16 = 0;
static mut G_S7COMM_PLUS_FUNCTION_KW_ID: u16 = 0;
static mut G_S7COMM_GENERIC_BUFFER_ID: c_int = 0;
static mut G_S7COMM_DATA_BUFFER_ID: c_int = 0;

// --- function_code keyword ---

unsafe extern "C" fn s7comm_function_code_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_FUNCTION_CODE_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_function_code_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Match(tx.request_function_code, ctx)
}

// --- rosctr keyword ---

unsafe extern "C" fn s7comm_rosctr_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_ROSCTR_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_rosctr_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Match(tx.request_rosctr, ctx)
}

// --- dangerous keyword ---

unsafe extern "C" fn s7comm_dangerous_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_DANGEROUS_KW_ID,
        std::ptr::null_mut(),
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_dangerous_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    _ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    if tx.is_dangerous {
        1
    } else {
        0
    }
}

// --- userdata_group keyword ---

unsafe extern "C" fn s7comm_userdata_group_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_USERDATA_GROUP_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_userdata_group_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Match(tx.request_userdata_group, ctx)
}

// --- subfunction keyword ---

unsafe extern "C" fn s7comm_subfunction_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_SUBFUNCTION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_subfunction_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Match(tx.request_userdata_subfunction, ctx)
}

// --- plus keyword ---

unsafe extern "C" fn s7comm_plus_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_PLUS_KW_ID,
        std::ptr::null_mut(),
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_plus_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    _ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    if tx.is_s7comm_plus {
        1
    } else {
        0
    }
}

// --- shared free ---

unsafe extern "C" fn s7comm_detect_u8_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Free(ctx);
}

unsafe extern "C" fn s7comm_detect_u16_free(_de: *mut DetectEngineCtx, ctx: *mut c_void) {
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Free(ctx);
}

// --- db keyword (u16) ---

unsafe extern "C" fn s7comm_db_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_DB_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u16_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_db_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    if !tx.has_data_item {
        return 0;
    }
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Match(tx.item_db_number, ctx)
}

// --- area keyword (u8) ---

unsafe extern "C" fn s7comm_area_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU8Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_AREA_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u8_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_area_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    if !tx.has_data_item {
        return 0;
    }
    let ctx = cast_pointer!(ctx, DetectUintData<u8>);
    SCDetectU8Match(tx.item_area, ctx)
}

// --- plus_function keyword (u16) ---

unsafe extern "C" fn s7comm_plus_function_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    let ctx = SCDetectU16Parse(raw) as *mut c_void;
    if ctx.is_null() {
        return -1;
    }
    if SCSigMatchAppendSMToList(
        de,
        s,
        G_S7COMM_PLUS_FUNCTION_KW_ID,
        ctx as *mut SigMatchCtx,
        G_S7COMM_GENERIC_BUFFER_ID,
    )
    .is_null()
    {
        s7comm_detect_u16_free(std::ptr::null_mut(), ctx);
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_plus_function_match(
    _de: *mut DetectEngineThreadCtx,
    _f: *mut Flow,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const Signature,
    ctx: *const SigMatchCtx,
) -> c_int {
    let tx = cast_pointer!(tx, S7commTransaction);
    if !tx.is_s7comm_plus {
        return 0;
    }
    let ctx = cast_pointer!(ctx, DetectUintData<u16>);
    SCDetectU16Match(tx.s7plus_function, ctx)
}

// --- data sticky buffer ---

unsafe extern "C" fn s7comm_data_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const libc::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_S7COMM_DATA_BUFFER_ID) < 0 {
        return -1;
    }
    0
}

unsafe extern "C" fn s7comm_data_get(
    tx: *const c_void,
    flags: u8,
    buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, S7commTransaction);
    if flags & Direction::ToClient as u8 != 0 {
        if !tx.response_buffer.is_empty() {
            *len = tx.response_buffer.len() as u32;
            *buf = tx.response_buffer.as_ptr();
            return true;
        }
    } else if !tx.request_buffer.is_empty() {
        *len = tx.request_buffer.len() as u32;
        *buf = tx.request_buffer.as_ptr();
        return true;
    }
    false
}

// --- Registration ---

pub(crate) unsafe extern "C" fn detect_s7comm_register() {
    // function_code keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.function_code\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm function code\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#function-code\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_function_code_match),
        Setup: Some(s7comm_function_code_setup),
        Free: Some(s7comm_detect_u8_free),
        flags: 0,
    };
    G_S7COMM_FUNCTION_CODE_KW_ID = SCDetectHelperKeywordRegister(&kw);

    G_S7COMM_GENERIC_BUFFER_ID = SCDetectHelperBufferProgressRegister(
        b"s7comm.generic\0".as_ptr() as *const libc::c_char,
        ALPROTO_S7COMM,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        1,
    );

    // rosctr keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.rosctr\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm ROSCTR/PDU type\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#rosctr\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_rosctr_match),
        Setup: Some(s7comm_rosctr_setup),
        Free: Some(s7comm_detect_u8_free),
        flags: 0,
    };
    G_S7COMM_ROSCTR_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // dangerous keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.dangerous\0".as_ptr() as *const libc::c_char,
        desc: b"match if S7comm operation is dangerous\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#dangerous\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_dangerous_match),
        Setup: Some(s7comm_dangerous_setup),
        Free: None,
        flags: SIGMATCH_NOOPT,
    };
    G_S7COMM_DANGEROUS_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // userdata_group keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.userdata_group\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm userdata function group\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#userdata-group\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_userdata_group_match),
        Setup: Some(s7comm_userdata_group_setup),
        Free: Some(s7comm_detect_u8_free),
        flags: 0,
    };
    G_S7COMM_USERDATA_GROUP_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // subfunction keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.subfunction\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm userdata subfunction\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#subfunction\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_subfunction_match),
        Setup: Some(s7comm_subfunction_setup),
        Free: Some(s7comm_detect_u8_free),
        flags: 0,
    };
    G_S7COMM_SUBFUNCTION_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // plus keyword
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.plus\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm-plus protocol variant\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#plus\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_plus_match),
        Setup: Some(s7comm_plus_setup),
        Free: None,
        flags: SIGMATCH_NOOPT,
    };
    G_S7COMM_PLUS_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // db keyword (u16)
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.db\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm data block number (Read/Write Var)\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#db\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_db_match),
        Setup: Some(s7comm_db_setup),
        Free: Some(s7comm_detect_u16_free),
        flags: 0,
    };
    G_S7COMM_DB_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // area keyword (u8)
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.area\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm memory area (Read/Write Var)\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#area\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_area_match),
        Setup: Some(s7comm_area_setup),
        Free: Some(s7comm_detect_u8_free),
        flags: 0,
    };
    G_S7COMM_AREA_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // plus_function keyword (u16)
    let kw = SCSigTableAppLiteElmt {
        name: b"s7comm.plus_function\0".as_ptr() as *const libc::c_char,
        desc: b"match S7comm-plus function code\0".as_ptr() as *const libc::c_char,
        url: b"/rules/s7comm-keywords.html#plus-function\0".as_ptr() as *const libc::c_char,
        AppLayerTxMatch: Some(s7comm_plus_function_match),
        Setup: Some(s7comm_plus_function_setup),
        Free: Some(s7comm_detect_u16_free),
        flags: 0,
    };
    G_S7COMM_PLUS_FUNCTION_KW_ID = SCDetectHelperKeywordRegister(&kw);

    // data sticky buffer
    let sticky = SigTableElmtStickyBuffer {
        name: String::from("s7comm.data"),
        desc: String::from("sticky buffer to match on the raw S7comm PDU payload"),
        url: String::from("/rules/s7comm-keywords.html#data"),
        setup: s7comm_data_setup,
    };
    let _ = helper_keyword_register_sticky_buffer(&sticky);
    G_S7COMM_DATA_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"s7comm.data\0".as_ptr() as *const libc::c_char,
        b"S7comm PDU payload\0".as_ptr() as *const libc::c_char,
        ALPROTO_S7COMM,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(s7comm_data_get),
    );
}
