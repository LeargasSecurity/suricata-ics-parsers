// ISO session / presentation / ACSE / MMS decoding for the TCP/102 MMS parser
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0
//
// Decodes one reassembled COTP TSDU down to an ACSE or MMS APDU. Only the
// fields needed for logging and detection are extracted; everything else is
// skipped by length. All decoding is bounded: no recursion into user data,
// capped string lengths and object counts.

use super::consts::*;
use der_parser::asn1_rs::{Any, Class, FromBer, Oid};
use std::borrow::Cow;

/// Longest identifier / file name component kept (MMS identifiers are <= 32).
pub const MAX_STRING_LEN: usize = 128;
/// Most object names / file names kept per PDU.
pub const MAX_OBJECTS: usize = 64;
/// Most presentation data values processed per TSDU.
const MAX_PDVS: usize = 4;
/// Most items walked in any one SEQUENCE OF.
const MAX_SEQ_ITEMS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectScope {
    Vmd,
    Domain,
    Aa,
}

impl ObjectScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vmd => "vmd",
            Self::Domain => "domain",
            Self::Aa => "aa",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectName {
    pub scope: ObjectScope,
    pub domain: Option<String>,
    pub item: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InitiateInfo {
    pub local_detail: Option<u32>,
    pub max_serv_outstanding_calling: Option<u32>,
    pub max_serv_outstanding_called: Option<u32>,
    pub nesting_level: Option<u32>,
    pub version: Option<u32>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MmsPdu {
    /// MMSpdu CHOICE tag (`PDU_*`).
    pub pdu_type: u8,
    pub invoke_id: Option<u32>,
    /// Confirmed or unconfirmed service tag.
    pub service: Option<u32>,
    pub objects: Vec<ObjectName>,
    /// defineNamedVariableList: the variables placed in the new list (data set).
    pub members: Vec<ObjectName>,
    /// getNameList object class and domain scope.
    pub object_class: Option<u32>,
    pub scope_domain: Option<String>,
    /// Domain / program invocation names for domain and program services.
    pub names: Vec<String>,
    pub files: Vec<String>,
    /// Read/write response results.
    pub success_count: u32,
    pub failure_count: u32,
    /// confirmed-Error / initiate-Error: (errorClass, code).
    pub error: Option<(u32, u32)>,
    /// rejectPDU: (reason class tag, code).
    pub reject: Option<(u32, u32)>,
    pub initiate: Option<InitiateInfo>,
    /// Read response that looks like an ICCP transfer set name: (domain, name).
    pub transfer_set: Option<(Option<String>, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcseKind {
    Aarq,
    Aare,
    Rlrq,
    Rlre,
    Abrt,
}

impl AcseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aarq => "aarq",
            Self::Aare => "aare",
            Self::Rlrq => "rlrq",
            Self::Rlre => "rlre",
            Self::Abrt => "abrt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcseApdu {
    pub kind: AcseKind,
    pub context_name: Option<String>,
    /// Called (AARQ) or responding (AARE) AP title and AE qualifier.
    pub called_ap_title: Option<String>,
    pub called_ae_qualifier: Option<i64>,
    pub calling_ap_title: Option<String>,
    pub calling_ae_qualifier: Option<i64>,
    pub mechanism_name: Option<String>,
    /// True if the AARQ carries an authentication value (e.g. a password).
    pub authentication: bool,
    /// AARE result.
    pub result: Option<u32>,
    /// RLRQ/RLRE reason or ABRT source.
    pub reason: Option<u32>,
    /// MMS initiate PDU carried in user-information.
    pub mms: Option<MmsPdu>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Apdu {
    Acse(AcseApdu),
    Mms(MmsPdu),
}

/// One session SPDU and the APDUs it carries. `spdu` is `None` when the MMS
/// PDU is carried directly on COTP without the OSI upper layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoMessage {
    pub spdu: Option<u8>,
    pub apdus: Vec<Apdu>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoError {
    /// Not a recognisable session SPDU.
    NotSession,
    /// Session/presentation/APDU encoding error.
    Malformed,
}

// --- BER helpers ---

fn tlv(i: &[u8]) -> Result<(&[u8], Any<'_>), IsoError> {
    Any::from_ber(i).map_err(|_| IsoError::Malformed)
}

/// Iterate the TLVs inside a constructed value.
fn children<'a>(data: &'a [u8]) -> impl Iterator<Item = Any<'a>> + 'a {
    let mut rest = data;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match Any::from_ber(rest) {
            Ok((r, a)) => {
                rest = r;
                Some(a)
            }
            Err(_) => {
                rest = &[];
                None
            }
        }
    })
    .take(MAX_SEQ_ITEMS)
}

fn is(a: &Any, class: Class, tag: u32) -> bool {
    a.header.class() == class && a.header.tag().0 == tag
}

fn ctx(a: &Any, tag: u32) -> bool {
    is(a, Class::ContextSpecific, tag)
}

fn first_child<'a>(a: &Any<'a>) -> Option<Any<'a>> {
    children(a.data).next()
}

fn uint(data: &[u8]) -> Option<u32> {
    let data = match data {
        [0, rest @ ..] if !rest.is_empty() => rest,
        d => d,
    };
    if data.is_empty() || data.len() > 4 {
        return None;
    }
    Some(data.iter().fold(0u32, |v, b| (v << 8) | *b as u32))
}

fn int(data: &[u8]) -> Option<i64> {
    if data.is_empty() || data.len() > 8 {
        return None;
    }
    let mut v: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    for b in data {
        v = (v << 8) | *b as i64;
    }
    Some(v)
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() > max {
        let mut n = max;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
}

fn string(data: &[u8]) -> String {
    let data = &data[..data.len().min(MAX_STRING_LEN)];
    // Lossy conversion can grow the string (U+FFFD is 3 bytes); cap it again.
    let mut s = String::from_utf8_lossy(data).into_owned();
    truncate_utf8(&mut s, MAX_STRING_LEN);
    s
}

fn oid(data: &[u8]) -> String {
    let mut s = Oid::new(Cow::Borrowed(data)).to_id_string();
    truncate_utf8(&mut s, MAX_STRING_LEN);
    s
}

fn push_bounded<T>(v: &mut Vec<T>, item: T) {
    if v.len() < MAX_OBJECTS {
        v.push(item);
    }
}

// --- Session (ISO 8327 / X.225) ---

/// Read an SPDU/parameter length: one byte, or 0xFF followed by two bytes.
fn ses_len(i: &[u8]) -> Option<(usize, &[u8])> {
    match i {
        [0xFF, hi, lo, rest @ ..] => Some((u16::from_be_bytes([*hi, *lo]) as usize, rest)),
        [0xFF, ..] => None,
        [len, rest @ ..] => Some((*len as usize, rest)),
        [] => None,
    }
}

/// Split one SPDU into (SI, parameter field, following bytes).
fn spdu(i: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&si, rest) = i.split_first()?;
    let (len, rest) = ses_len(rest)?;
    if rest.len() < len {
        return None;
    }
    Some((si, &rest[..len], &rest[len..]))
}

/// Find session user data (PGI 193/194) in an SPDU parameter field.
fn ses_user_data(mut params: &[u8]) -> Option<&[u8]> {
    while let Some((&code, rest)) = params.split_first() {
        let (len, rest) = ses_len(rest)?;
        if rest.len() < len {
            return None;
        }
        if code == SES_PGI_USER_DATA || code == SES_PGI_EXTENDED_USER_DATA {
            return Some(&rest[..len]);
        }
        params = &rest[len..];
    }
    None
}

/// First octet of an MMSpdu: context-specific tags [0]..[13]. Constructed for
/// most PDUs; primitive for cancel-Request/Response ([5]/[6], Unsigned32) and
/// conclude-Request/Response ([11]/[12], NULL).
pub fn is_mms_pdu_tag(t: u8) -> bool {
    matches!(t, 0xA0..=0xAD | 0x85 | 0x86 | 0x8B | 0x8C)
}

/// Decode one TSDU: either the OSI session/presentation/APDU stack, or an MMS
/// PDU carried directly on COTP (reduced stack).
pub fn parse_iso_message(tsdu: &[u8]) -> Result<IsoMessage, IsoError> {
    // Reduced stack: a BER MMSpdu CHOICE tag directly on COTP, no session layer.
    if tsdu.first().is_some_and(|&t| is_mms_pdu_tag(t)) {
        return Ok(IsoMessage {
            spdu: None,
            apdus: vec![parse_apdu(tsdu)?],
        });
    }
    let (si, params, rest) = spdu(tsdu).ok_or(IsoError::NotSession)?;
    let user_data = match si {
        // Give Tokens + Data Transfer (basic concatenation); user information follows the DT.
        SPDU_DT => match spdu(rest) {
            Some((SPDU_DT, _, data)) => data,
            _ => rest,
        },
        SPDU_CN | SPDU_AC | SPDU_RF | SPDU_FN | SPDU_DN | SPDU_NF | SPDU_AB | SPDU_AA => {
            match ses_user_data(params) {
                Some(d) => d,
                None => {
                    return Ok(IsoMessage {
                        spdu: Some(si),
                        apdus: Vec::new(),
                    })
                }
            }
        }
        _ => return Err(IsoError::NotSession),
    };
    let mut apdus = Vec::new();
    if !user_data.is_empty() {
        for value in presentation_values(user_data)? {
            apdus.push(parse_apdu(value)?);
        }
    }
    Ok(IsoMessage {
        spdu: Some(si),
        apdus,
    })
}

// --- Presentation (ISO 8823) ---

/// Find fully-encoded-data ([APPLICATION 1]) in a PPDU, at most two levels down
/// (CP-type / CPA-PPDU: SET { normal-mode-parameters [2] { ..., user-data } }).
fn find_user_data<'a>(ppdu: &Any<'a>) -> Option<Any<'a>> {
    if is(ppdu, Class::Application, 1) {
        return Some(ppdu.clone());
    }
    if !ppdu.header.is_constructed() {
        return None;
    }
    for child in children(ppdu.data) {
        if is(&child, Class::Application, 1) {
            return Some(child);
        }
        if child.header.is_constructed() && child.header.class() == Class::ContextSpecific {
            if let Some(ud) = children(child.data).find(|c| is(c, Class::Application, 1)) {
                return Some(ud);
            }
        }
    }
    None
}

/// Return the encoded APDUs from each PDV-list in the presentation user data.
fn presentation_values(i: &[u8]) -> Result<Vec<&[u8]>, IsoError> {
    let (_, ppdu) = tlv(i)?;
    let user_data = find_user_data(&ppdu).ok_or(IsoError::Malformed)?;
    let mut values = Vec::new();
    for pdv in children(user_data.data).take(MAX_PDVS) {
        if !is(&pdv, Class::Universal, 16) {
            return Err(IsoError::Malformed);
        }
        // { transfer-syntax-name OID OPTIONAL, context-id INTEGER, values CHOICE }
        let value = children(pdv.data)
            .find(|c| c.header.class() == Class::ContextSpecific)
            .ok_or(IsoError::Malformed)?;
        match value.header.tag().0 {
            // single-ASN1-type [0] and octet-aligned [1] both wrap one encoded APDU.
            0 | 1 => values.push(value.data),
            _ => return Err(IsoError::Malformed),
        }
    }
    Ok(values)
}

/// Decode an ACSE or MMS APDU (by the class of its outer tag).
pub fn parse_apdu(i: &[u8]) -> Result<Apdu, IsoError> {
    let (_, outer) = tlv(i)?;
    match outer.header.class() {
        Class::Application => parse_acse(&outer).map(Apdu::Acse),
        Class::ContextSpecific => parse_mms_any(&outer).map(Apdu::Mms),
        _ => Err(IsoError::Malformed),
    }
}

// --- ACSE (ISO 8650) ---

fn ap_title(a: &Any) -> Option<String> {
    // AP-title CHOICE: form2 OBJECT IDENTIFIER (form1 directory names are not decoded).
    first_child(a)
        .filter(|c| is(c, Class::Universal, 6))
        .map(|c| oid(c.data))
}

fn ae_qualifier(a: &Any) -> Option<i64> {
    first_child(a)
        .filter(|c| is(c, Class::Universal, 2))
        .and_then(|c| int(c.data))
}

/// user-information: SEQUENCE OF EXTERNAL { ..., encoding single-ASN1-type [0] }.
fn acse_user_mms(a: &Any) -> Option<MmsPdu> {
    let external = children(a.data).find(|c| is(c, Class::Universal, 8))?;
    let enc = children(external.data).find(|c| ctx(c, 0) || ctx(c, 1))?;
    let (_, inner) = tlv(enc.data).ok()?;
    parse_mms_any(&inner).ok()
}

fn parse_acse(outer: &Any) -> Result<AcseApdu, IsoError> {
    let kind = match outer.header.tag().0 {
        0 => AcseKind::Aarq,
        1 => AcseKind::Aare,
        2 => AcseKind::Rlrq,
        3 => AcseKind::Rlre,
        4 => AcseKind::Abrt,
        _ => return Err(IsoError::Malformed),
    };
    let mut apdu = AcseApdu {
        kind,
        context_name: None,
        called_ap_title: None,
        called_ae_qualifier: None,
        calling_ap_title: None,
        calling_ae_qualifier: None,
        mechanism_name: None,
        authentication: false,
        result: None,
        reason: None,
        mms: None,
    };
    for f in children(outer.data) {
        if f.header.class() != Class::ContextSpecific {
            continue;
        }
        let tag = f.header.tag().0;
        match (kind, tag) {
            (_, 30) => apdu.mms = acse_user_mms(&f),
            (AcseKind::Aarq | AcseKind::Aare, 1) => {
                apdu.context_name = first_child(&f)
                    .filter(|c| is(c, Class::Universal, 6))
                    .map(|c| oid(c.data));
            }
            (AcseKind::Aarq, 2) | (AcseKind::Aare, 4) => apdu.called_ap_title = ap_title(&f),
            (AcseKind::Aarq, 3) | (AcseKind::Aare, 5) => {
                apdu.called_ae_qualifier = ae_qualifier(&f)
            }
            (AcseKind::Aarq, 6) => apdu.calling_ap_title = ap_title(&f),
            (AcseKind::Aarq, 7) => apdu.calling_ae_qualifier = ae_qualifier(&f),
            (AcseKind::Aarq, 11) | (AcseKind::Aare, 9) => apdu.mechanism_name = Some(oid(f.data)),
            (AcseKind::Aarq, 12) => apdu.authentication = !f.data.is_empty(),
            (AcseKind::Aare, 2) => {
                apdu.result = first_child(&f)
                    .filter(|c| is(c, Class::Universal, 2))
                    .and_then(|c| uint(c.data))
            }
            (AcseKind::Rlrq | AcseKind::Rlre | AcseKind::Abrt, 0) => apdu.reason = uint(f.data),
            _ => {}
        }
    }
    Ok(apdu)
}

// --- MMS (ISO 9506-2) ---

#[cfg(test)]
pub fn parse_mms(i: &[u8]) -> Result<MmsPdu, IsoError> {
    let (_, outer) = tlv(i)?;
    parse_mms_any(&outer)
}

fn parse_mms_any(outer: &Any) -> Result<MmsPdu, IsoError> {
    if outer.header.class() != Class::ContextSpecific || outer.header.tag().0 > 13 {
        return Err(IsoError::Malformed);
    }
    let pdu_type = outer.header.tag().0 as u8;
    let mut pdu = MmsPdu {
        pdu_type,
        ..Default::default()
    };
    match pdu_type {
        PDU_CONFIRMED_REQUEST | PDU_CONFIRMED_RESPONSE => {
            let mut it = children(outer.data);
            let invoke = it.next().ok_or(IsoError::Malformed)?;
            if !is(&invoke, Class::Universal, 2) {
                return Err(IsoError::Malformed);
            }
            pdu.invoke_id = uint(invoke.data);
            // Skip listOfModifier (SEQUENCE) before the service choice.
            let svc = it
                .find(|c| c.header.class() == Class::ContextSpecific)
                .ok_or(IsoError::Malformed)?;
            pdu.service = Some(svc.header.tag().0);
            if pdu_type == PDU_CONFIRMED_REQUEST {
                parse_request_service(&mut pdu, &svc);
            } else {
                parse_response_service(&mut pdu, &svc);
            }
        }
        PDU_CONFIRMED_ERROR => {
            for f in children(outer.data) {
                if ctx(&f, 0) {
                    pdu.invoke_id = uint(f.data);
                } else if ctx(&f, 2) {
                    pdu.error = service_error(&f);
                }
            }
        }
        PDU_UNCONFIRMED => {
            let svc = first_child(outer).ok_or(IsoError::Malformed)?;
            pdu.service = Some(svc.header.tag().0);
            if ctx(&svc, 0) {
                // informationReport { variableAccessSpecification, listOfAccessResult [0] }
                if let Some(vas) = first_child(&svc) {
                    variable_access_spec(&mut pdu, &vas);
                }
            }
        }
        PDU_REJECT => {
            for f in children(outer.data) {
                let tag = f.header.tag().0;
                if tag == 0 {
                    pdu.invoke_id = uint(f.data);
                } else if let Some(code) = uint(f.data) {
                    pdu.reject = Some((tag, code));
                }
            }
        }
        PDU_CANCEL_REQUEST | PDU_CANCEL_RESPONSE => pdu.invoke_id = uint(outer.data),
        PDU_INITIATE_REQUEST | PDU_INITIATE_RESPONSE => pdu.initiate = Some(initiate(outer)),
        // Cancel-ErrorPDU ::= SEQUENCE { originalInvokeID [0], serviceError [1] ServiceError }
        PDU_CANCEL_ERROR => {
            for f in children(outer.data) {
                if ctx(&f, 0) {
                    pdu.invoke_id = uint(f.data);
                } else if ctx(&f, 1) {
                    pdu.error = service_error_fields(&f);
                }
            }
        }
        PDU_INITIATE_ERROR | PDU_CONCLUDE_ERROR => pdu.error = service_error_fields(outer),
        _ => {}
    }
    Ok(pdu)
}

fn initiate(a: &Any) -> InitiateInfo {
    let mut info = InitiateInfo::default();
    for f in children(a.data) {
        match f.header.tag().0 {
            0 => info.local_detail = uint(f.data),
            1 => info.max_serv_outstanding_calling = uint(f.data),
            2 => info.max_serv_outstanding_called = uint(f.data),
            3 => info.nesting_level = uint(f.data),
            4 => {
                info.version = children(f.data)
                    .find(|c| ctx(c, 0))
                    .and_then(|c| uint(c.data))
            }
            _ => {}
        }
    }
    info
}

/// ServiceError { errorClass [0] CHOICE { <class> [n] INTEGER }, ... }
fn service_error_fields(a: &Any) -> Option<(u32, u32)> {
    let class = children(a.data).find(|c| ctx(c, 0))?;
    let choice = first_child(&class)?;
    Some((choice.header.tag().0, uint(choice.data).unwrap_or(0)))
}

fn service_error(a: &Any) -> Option<(u32, u32)> {
    service_error_fields(a)
}

/// ObjectName CHOICE { vmd-specific [0], domain-specific [1] { domainId, itemId }, aa-specific [2] }
fn object_name(a: &Any) -> Option<ObjectName> {
    match a.header.tag().0 {
        0 if a.header.class() == Class::ContextSpecific => Some(ObjectName {
            scope: ObjectScope::Vmd,
            domain: None,
            item: string(a.data),
        }),
        1 if a.header.class() == Class::ContextSpecific => {
            let mut it = children(a.data);
            let domain = it.next()?;
            let item = it.next()?;
            Some(ObjectName {
                scope: ObjectScope::Domain,
                domain: Some(string(domain.data)),
                item: string(item.data),
            })
        }
        2 if a.header.class() == Class::ContextSpecific => Some(ObjectName {
            scope: ObjectScope::Aa,
            domain: None,
            item: string(a.data),
        }),
        _ => None,
    }
}

fn push_object(pdu: &mut MmsPdu, a: &Any) {
    if let Some(name) = object_name(a) {
        push_bounded(&mut pdu.objects, name);
    }
}

/// An explicitly tagged ObjectName: [n] { ObjectName }.
fn push_wrapped_object(pdu: &mut MmsPdu, a: &Any) {
    if let Some(inner) = first_child(a) {
        push_object(pdu, &inner);
    }
}

/// VariableAccessSpecification CHOICE {
///   listOfVariable [0] SEQUENCE OF { variableSpecification CHOICE { name [0] ObjectName, ... } },
///   variableListName [1] ObjectName }
fn variable_access_spec(pdu: &mut MmsPdu, vas: &Any) {
    if ctx(vas, 0) {
        list_of_variable(&mut pdu.objects, vas);
    } else if ctx(vas, 1) {
        push_wrapped_object(pdu, vas);
    }
}

/// SEQUENCE OF { variableSpecification CHOICE { name [0] ObjectName, ... }, ... }
fn list_of_variable(out: &mut Vec<ObjectName>, list: &Any) {
    for item in children(list.data) {
        if let Some(spec) = first_child(&item) {
            if ctx(&spec, 0) {
                if let Some(name) = first_child(&spec).as_ref().and_then(object_name) {
                    push_bounded(out, name);
                }
            }
        }
    }
}

/// FileName ::= SEQUENCE OF GraphicString, joined with '/'.
fn file_name(a: &Any) -> String {
    let parts: Vec<String> = children(a.data).map(|c| string(c.data)).collect();
    let mut s = parts.join("/");
    truncate_utf8(&mut s, MAX_STRING_LEN);
    s
}

fn push_file(pdu: &mut MmsPdu, a: &Any) {
    let name = file_name(a);
    if !name.is_empty() {
        push_bounded(&mut pdu.files, name);
    }
}

fn push_name(pdu: &mut MmsPdu, data: &[u8]) {
    push_bounded(&mut pdu.names, string(data));
}

fn parse_request_service(pdu: &mut MmsPdu, svc: &Any) {
    let tag = svc.header.tag().0;
    match tag {
        SVC_GET_NAME_LIST => {
            for f in children(svc.data) {
                if ctx(&f, 0) {
                    pdu.object_class = first_child(&f).and_then(|c| uint(c.data));
                } else if ctx(&f, 1) {
                    if let Some(scope) = first_child(&f) {
                        if ctx(&scope, 1) {
                            pdu.scope_domain = Some(string(scope.data));
                        }
                    }
                }
            }
        }
        SVC_READ => {
            // { specificationWithResult [0] OPTIONAL, variableAccessSpecification [1] }
            if let Some(vas) = children(svc.data).find(|c| ctx(c, 1)) {
                if let Some(inner) = first_child(&vas) {
                    variable_access_spec(pdu, &inner);
                }
            }
        }
        SVC_WRITE => {
            // { variableAccessSpecification (untagged CHOICE), listOfData [0] }
            if let Some(vas) = first_child(svc) {
                variable_access_spec(pdu, &vas);
            }
        }
        SVC_GET_VARIABLE_ACCESS_ATTRIBUTES | SVC_GET_NAMED_VARIABLE_LIST_ATTRIBUTES => {
            // CHOICE { name [0] ObjectName, ... } / ObjectName
            if let Some(inner) = first_child(svc) {
                if tag == SVC_GET_VARIABLE_ACCESS_ATTRIBUTES {
                    if ctx(&inner, 0) {
                        push_wrapped_object(pdu, &inner);
                    }
                } else {
                    push_object(pdu, &inner);
                }
            }
        }
        SVC_DEFINE_NAMED_VARIABLE_LIST | SVC_DEFINE_NAMED_VARIABLE => {
            // { variableListName ObjectName, listOfVariable [0] ... }
            let mut it = children(svc.data);
            if let Some(name) = it.next() {
                push_object(pdu, &name);
            }
            if tag == SVC_DEFINE_NAMED_VARIABLE_LIST {
                if let Some(list) = it.find(|c| ctx(c, 0)) {
                    list_of_variable(&mut pdu.members, &list);
                }
            }
        }
        SVC_DELETE_NAMED_VARIABLE_LIST | SVC_DELETE_VARIABLE_ACCESS => {
            // { scopeOfDelete [0], listOfName [1] SEQUENCE OF ObjectName, domainName [2] }
            for f in children(svc.data) {
                if ctx(&f, 1) {
                    for name in children(f.data) {
                        push_object(pdu, &name);
                    }
                } else if ctx(&f, 2) {
                    pdu.scope_domain = Some(string(f.data));
                }
            }
        }
        // IMPLICIT Identifier: domain or program invocation name.
        SVC_DOWNLOAD_SEGMENT
        | SVC_INITIATE_UPLOAD_SEQUENCE
        | SVC_DELETE_DOMAIN
        | SVC_GET_DOMAIN_ATTRIBUTES
        | SVC_DELETE_PROGRAM_INVOCATION
        | SVC_GET_PROGRAM_INVOCATION_ATTRIBUTES => {
            if !svc.header.is_constructed() {
                push_name(pdu, svc.data);
            }
        }
        // SEQUENCE { name [0] Identifier, ... } with optional file names.
        SVC_INITIATE_DOWNLOAD_SEQUENCE
        | SVC_TERMINATE_DOWNLOAD_SEQUENCE
        | SVC_REQUEST_DOMAIN_DOWNLOAD
        | SVC_REQUEST_DOMAIN_UPLOAD
        | SVC_LOAD_DOMAIN_CONTENT
        | SVC_STORE_DOMAIN_CONTENT
        | SVC_CREATE_PROGRAM_INVOCATION
        | SVC_START
        | SVC_STOP
        | SVC_RESUME
        | SVC_RESET
        | SVC_KILL => {
            for f in children(svc.data) {
                let ftag = f.header.tag().0;
                if ftag == 0 && !f.header.is_constructed() {
                    push_name(pdu, f.data);
                } else if f.header.is_constructed()
                    && ((tag == SVC_REQUEST_DOMAIN_DOWNLOAD && ftag == 4)
                        || (tag == SVC_LOAD_DOMAIN_CONTENT && ftag == 4)
                        || (tag == SVC_REQUEST_DOMAIN_UPLOAD && ftag == 1)
                        || (tag == SVC_STORE_DOMAIN_CONTENT && ftag == 1))
                {
                    push_file(pdu, &f);
                }
            }
        }
        SVC_OBTAIN_FILE | SVC_FILE_RENAME => {
            // obtainFile { server [0], sourceFile [1], destinationFile [2] }
            // fileRename { currentFileName [0], newFileName [1] }
            for f in children(svc.data) {
                if f.header.is_constructed()
                    && (f.header.tag().0 != 0 || tag == SVC_FILE_RENAME)
                    && f.header.class() == Class::ContextSpecific
                {
                    push_file(pdu, &f);
                }
            }
        }
        SVC_FILE_OPEN | SVC_FILE_DIRECTORY => {
            if let Some(f) = children(svc.data).find(|c| ctx(c, 0)) {
                push_file(pdu, &f);
            }
        }
        SVC_FILE_DELETE => push_file(pdu, svc),
        SVC_READ_JOURNAL
        | SVC_INITIALIZE_JOURNAL
        | SVC_CREATE_JOURNAL
        | SVC_DELETE_JOURNAL
        | SVC_WRITE_JOURNAL => {
            if let Some(name) = children(svc.data).find(|c| ctx(c, 0)) {
                push_wrapped_object(pdu, &name);
            }
        }
        _ => {}
    }
}

/// Data ::= CHOICE { ..., structure [2], ..., unsigned [6], ..., visible-string [10], ... }
/// An ICCP Next_DSTransfer_Set value is structure { scope, domain, name }.
fn transfer_set_name(data: &Any) -> Option<(Option<String>, String)> {
    if !ctx(data, 2) {
        return None;
    }
    let fields: Vec<Any> = children(data.data).take(4).collect();
    match fields.as_slice() {
        [scope, domain, name]
            if (ctx(scope, 5) || ctx(scope, 6)) && ctx(domain, 10) && ctx(name, 10) =>
        {
            let domain = if uint(scope.data) == Some(0) {
                None
            } else {
                Some(string(domain.data))
            };
            Some((domain, string(name.data)))
        }
        _ => None,
    }
}

fn parse_response_service(pdu: &mut MmsPdu, svc: &Any) {
    match svc.header.tag().0 {
        SVC_READ => {
            // { variableAccessSpecification [0] OPTIONAL, listOfAccessResult [1] }
            if let Some(results) = children(svc.data).find(|c| ctx(c, 1)) {
                let mut single = None;
                for (n, r) in children(results.data).enumerate() {
                    if ctx(&r, 0) {
                        pdu.failure_count += 1;
                    } else {
                        pdu.success_count += 1;
                        single = if n == 0 { Some(r) } else { None };
                    }
                }
                if pdu.success_count == 1 && pdu.failure_count == 0 {
                    pdu.transfer_set = single.as_ref().and_then(transfer_set_name);
                }
            }
        }
        SVC_WRITE => {
            // SEQUENCE OF CHOICE { failure [0], success [1] NULL }
            for r in children(svc.data) {
                if ctx(&r, 0) {
                    pdu.failure_count += 1;
                } else {
                    pdu.success_count += 1;
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cotp::parse_tpkt_cotp;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn tsdu(tpkt: &[u8]) -> Vec<u8> {
        parse_tpkt_cotp(tpkt).unwrap().1.payload.to_vec()
    }

    fn mms_of(msg: &IsoMessage) -> &MmsPdu {
        match &msg.apdus[0] {
            Apdu::Mms(m) => m,
            Apdu::Acse(a) => a.mms.as_ref().unwrap(),
        }
    }

    // control.pcap: SetDataValueRequest simpleIOGenericIO GGIO1$CO$SPCSO1$Oper
    const OPER_WRITE: &str = "0300006e02f080010001006161305f020103a05aa058020103a553a02f302da0
        2ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f
        24535043534f31244f706572a020a21e830101a205850103890086010191086a
        e266b16000000083010084020600";

    #[test]
    fn test_iec61850_control_write() {
        let msg = parse_iso_message(&tsdu(&hex(OPER_WRITE))).unwrap();
        assert_eq!(msg.spdu, Some(SPDU_DT));
        let pdu = mms_of(&msg);
        assert_eq!(pdu.pdu_type, PDU_CONFIRMED_REQUEST);
        assert_eq!(pdu.invoke_id, Some(3));
        assert_eq!(pdu.service, Some(SVC_WRITE));
        assert_eq!(
            pdu.objects,
            vec![ObjectName {
                scope: ObjectScope::Domain,
                domain: Some("simpleIOGenericIO".into()),
                item: "GGIO1$CO$SPCSO1$Oper".into(),
            }]
        );
    }

    #[test]
    fn test_read_request_and_response() {
        // read { variableAccessSpecification [1] { listOfVariable [0] { { name [0] { domain-specific } } } } }
        let req = hex("a0 22 02 01 07 a4 1d a1 1b a0 19 30 17 a0 15 a1 13
             1a 03 4c 44 30 1a 0c 47 47 49 4f 31 24 4d 58 24 41 6e 49");
        let pdu = parse_mms(&req).unwrap();
        assert_eq!(pdu.service, Some(SVC_READ));
        assert_eq!(pdu.objects[0].domain.as_deref(), Some("LD0"));
        assert_eq!(pdu.objects[0].item, "GGIO1$MX$AnI");

        // read response: listOfAccessResult [1] { failure [0] 0x0a, success float }
        let resp = hex("a1 0e 02 01 07 a4 09 a1 07 80 01 0a 87 02 08 00");
        let pdu = parse_mms(&resp).unwrap();
        assert_eq!(pdu.pdu_type, PDU_CONFIRMED_RESPONSE);
        assert_eq!(pdu.invoke_id, Some(7));
        assert_eq!((pdu.success_count, pdu.failure_count), (1, 1));
        assert_eq!(pdu.transfer_set, None);
    }

    #[test]
    fn test_iccp_transfer_set_response() {
        // structure { unsigned 1, visible-string "KIRKLAND", visible-string "CITEC_TS0" }
        let resp = hex(
            "a1 22 02 02 11 53 a4 1c a1 1a a2 18 86 01 01 8a 08 4b 49 52 4b 4c 41 4e 44
             8a 09 43 49 54 45 43 5f 54 53 30",
        );
        let pdu = parse_mms(&resp).unwrap();
        assert_eq!(pdu.invoke_id, Some(4435));
        assert_eq!(
            pdu.transfer_set,
            Some((Some("KIRKLAND".into()), "CITEC_TS0".into()))
        );
    }

    #[test]
    fn test_get_name_list_and_identify() {
        // getNameList { objectClass [0] { basicObjectClass [0] 9 }, objectScope [1] { vmdSpecific [0] NULL } }
        let pdu = parse_mms(&hex("a0 0e 02 01 01 a1 09 a0 03 80 01 09 a1 02 80 00")).unwrap();
        assert_eq!(pdu.service, Some(SVC_GET_NAME_LIST));
        assert_eq!(pdu.object_class, Some(9));
        assert_eq!(pdu.scope_domain, None);
        // objectScope domainSpecific [1] "LD0"
        let pdu = parse_mms(&hex(
            "a0 11 02 01 02 a1 0c a0 03 80 01 00 a1 05 81 03 4c 44 30",
        ))
        .unwrap();
        assert_eq!(pdu.object_class, Some(0));
        assert_eq!(pdu.scope_domain.as_deref(), Some("LD0"));
        // identify [2] NULL
        let pdu = parse_mms(&hex("a0 05 02 01 03 82 00")).unwrap();
        assert_eq!(pdu.service, Some(SVC_IDENTIFY));
    }

    #[test]
    fn test_program_and_file_services() {
        // stop [41] { programInvocationName [0] "P1" }  (tag 41 = bf 29)
        let pdu = parse_mms(&hex("a0 0a 02 01 04 bf 29 04 80 02 50 31")).unwrap();
        assert_eq!(pdu.service, Some(SVC_STOP));
        assert_eq!(pdu.names, vec!["P1".to_string()]);
        // fileDelete [76] FileName { "IED", "a.cfg" }  (tag 76 = bf 4c)
        let pdu = parse_mms(&hex(
            "a0 10 02 01 05 bf 4c 0a 19 03 49 45 44 19 03 61 2e 63",
        ))
        .unwrap();
        assert_eq!(pdu.service, Some(SVC_FILE_DELETE));
        assert_eq!(pdu.files, vec!["IED/a.c".to_string()]);
        // deleteDomain [36] IMPLICIT Identifier "D1" (tag 36 = 9f 24)
        let pdu = parse_mms(&hex("a0 08 02 01 06 9f 24 02 44 31")).unwrap();
        assert_eq!(pdu.service, Some(36));
        assert_eq!(pdu.names, vec!["D1".to_string()]);
    }

    #[test]
    fn test_data_set_define_delete() {
        // defineNamedVariableList { domain-specific { "LD0", "LLN0$DS1" },
        //   listOfVariable [0] { { name [0] { vmd-specific [0] "V1" } } } }
        let pdu = parse_mms(&hex(
            "a0 20 02 01 08 ab 1b a1 0f 1a 03 4c 44 30 1a 08 4c 4c 4e 30 24 44 53 31
             a0 08 30 06 a0 04 80 02 56 31",
        ))
        .unwrap();
        assert_eq!(pdu.service, Some(SVC_DEFINE_NAMED_VARIABLE_LIST));
        assert_eq!(pdu.objects.len(), 1);
        assert_eq!(pdu.objects[0].item, "LLN0$DS1");
        assert_eq!(pdu.members.len(), 1);
        assert_eq!(pdu.members[0].scope, ObjectScope::Vmd);
        assert_eq!(pdu.members[0].item, "V1");
        // deleteNamedVariableList { listOfVariableListName [1] { domain-specific {...} } }
        let pdu = parse_mms(&hex(
            "a0 18 02 01 09 ad 13 a1 11 a1 0f 1a 03 4c 44 30 1a 08 4c 4c 4e 30 24 44 53 31",
        ))
        .unwrap();
        assert_eq!(pdu.service, Some(SVC_DELETE_NAMED_VARIABLE_LIST));
        assert_eq!(pdu.objects[0].domain.as_deref(), Some("LD0"));
    }

    #[test]
    fn test_confirmed_error_and_reject() {
        // confirmed-Error { invokeID [0] 5, serviceError [2] { errorClass [0] { access [7] 2 } } }
        let pdu = parse_mms(&hex("a2 0a 80 01 05 a2 05 a0 03 87 01 02")).unwrap();
        assert_eq!(pdu.pdu_type, PDU_CONFIRMED_ERROR);
        assert_eq!(pdu.invoke_id, Some(5));
        assert_eq!(pdu.error, Some((7, 2)));
        // reject { originalInvokeID [0] 9, confirmed-requestPDU [1] 1 }
        let pdu = parse_mms(&hex("a4 06 80 01 09 81 01 01")).unwrap();
        assert_eq!(pdu.invoke_id, Some(9));
        assert_eq!(pdu.reject, Some((1, 1)));
    }

    #[test]
    fn test_information_report() {
        // unconfirmed { informationReport [0] { variableListName [1] { vmd-specific [0] "RPT" }, [0] {} } }
        let pdu = parse_mms(&hex("a3 0d a0 0b a1 05 80 03 52 50 54 a0 02 8a 00")).unwrap();
        assert_eq!(pdu.pdu_type, PDU_UNCONFIRMED);
        assert_eq!(pdu.service, Some(0));
        assert_eq!(pdu.objects[0].scope, ObjectScope::Vmd);
        assert_eq!(pdu.objects[0].item, "RPT");
    }

    #[test]
    fn test_session_connect_with_aarq() {
        // CN { user data PGI c1 { CP-type SET { mode [0], normal [2] { user-data 61 { PDV
        //   { ctx 1, [0] AARQ { context [1] OID 1.0.9506.2.3, calling-AP-title [6] OID 1.1.1,
        //     mech [11], auth [12], user-info [30] { EXTERNAL { 02 03, [0] initiate-Request } } } } } } } }
        let aarq = hex(
            "60 40 a1 07 06 05 28 ca 22 02 03 a6 04 06 02 29 01 8b 03 52 01 00 ac 04 80 02 70 77
             be 24 28 22 02 01 03 a0 1d a8 1b 80 03 00 fd e8 81 01 05 82 01 05 83 01 0a a4 0b 80 01 01
             81 02 05 f1 82 02 00 00",
        );
        let mut pdv = hex("30 00 02 01 01 a0 00");
        pdv[1] = (aarq.len() + 5) as u8;
        pdv[6] = aarq.len() as u8;
        pdv.extend_from_slice(&aarq);
        let mut ud = vec![0x61, pdv.len() as u8];
        ud.extend_from_slice(&pdv);
        let mut normal = vec![0xa2, ud.len() as u8];
        normal.extend_from_slice(&ud);
        let mut cp = vec![0x31, (normal.len() + 5) as u8, 0xa0, 0x03, 0x80, 0x01, 0x01];
        cp.extend_from_slice(&normal);
        let mut params = vec![SES_PGI_USER_DATA, cp.len() as u8];
        params.extend_from_slice(&cp);
        let mut spdu = vec![SPDU_CN, params.len() as u8];
        spdu.extend_from_slice(&params);

        let msg = parse_iso_message(&spdu).unwrap();
        assert_eq!(msg.spdu, Some(SPDU_CN));
        let Apdu::Acse(a) = &msg.apdus[0] else {
            panic!("expected ACSE")
        };
        assert_eq!(a.kind, AcseKind::Aarq);
        assert_eq!(a.context_name.as_deref(), Some("1.0.9506.2.3"));
        assert_eq!(a.calling_ap_title.as_deref(), Some("1.1.1"));
        assert!(a.authentication);
        let init = a.mms.as_ref().unwrap();
        assert_eq!(init.pdu_type, PDU_INITIATE_REQUEST);
        let info = init.initiate.as_ref().unwrap();
        assert_eq!(info.local_detail, Some(65000));
        assert_eq!(info.version, Some(1));
    }

    /// BER TLV with definite length (short or 0x81/0x82 long form).
    fn enc(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut v = tag.to_vec();
        match content.len() {
            n if n < 0x80 => v.push(n as u8),
            n if n < 0x100 => v.extend_from_slice(&[0x81, n as u8]),
            n => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend_from_slice(content);
        v
    }

    /// fileDelete [76] with one GraphicString component of `name`.
    fn file_delete(name: &[u8]) -> Vec<u8> {
        let svc = enc(&[0xbf, 0x4c], &enc(&[0x19], name));
        let mut body = vec![0x02, 0x01, 0x05];
        body.extend_from_slice(&svc);
        enc(&[0xa0], &body)
    }

    #[test]
    fn test_long_non_utf8_names_truncate_on_char_boundary() {
        // 127 ASCII bytes then an invalid byte: lossy conversion yields 130 bytes.
        let mut name = vec![b'a'; 127];
        name.push(0xff);
        let pdu = parse_mms(&file_delete(&name)).unwrap();
        assert!(pdu.files[0].len() <= MAX_STRING_LEN);
        // "a" + 'é' (2 bytes) x 70: the 128-byte cut lands mid-character.
        let mut name = b"a".to_vec();
        for _ in 0..70 {
            name.extend_from_slice("é".as_bytes());
        }
        let pdu = parse_mms(&file_delete(&name)).unwrap();
        assert!(pdu.files[0].len() <= MAX_STRING_LEN);
        assert!(pdu.files[0].starts_with("aé"));
    }

    #[test]
    fn test_cancel_error() {
        // cancel-Error { originalInvokeID [0] 6, serviceError [1] { errorClass [0] { service [4] 3 } } }
        let pdu = parse_mms(&hex("a7 0a 80 01 06 a1 05 a0 03 84 01 03")).unwrap();
        assert_eq!(pdu.pdu_type, PDU_CANCEL_ERROR);
        assert_eq!(pdu.invoke_id, Some(6));
        assert_eq!(pdu.error, Some((4, 3)));
    }

    #[test]
    fn test_reduced_stack_mms_over_cotp() {
        // startRequest [40] { programInvocationName [0] "P1" } directly on COTP,
        // no session/presentation/ACSE. (confirmed-request [0], invoke 1)
        let msg = parse_iso_message(&hex("a0 0a 02 01 01 bf 28 04 80 02 50 31")).unwrap();
        assert_eq!(msg.spdu, None);
        let Apdu::Mms(m) = &msg.apdus[0] else {
            panic!("expected MMS")
        };
        assert_eq!(m.service, Some(SVC_START));
        assert_eq!(m.names, vec!["P1".to_string()]);
    }

    #[test]
    fn test_reduced_stack_primitive_pdus() {
        // conclude-Request [11] NULL and cancel-Request [5] invokeID 7, directly on COTP.
        let msg = parse_iso_message(&[0x8b, 0x00]).unwrap();
        let Apdu::Mms(m) = &msg.apdus[0] else {
            panic!("expected MMS")
        };
        assert_eq!(m.pdu_type, PDU_CONCLUDE_REQUEST);
        let msg = parse_iso_message(&[0x85, 0x01, 0x07]).unwrap();
        let Apdu::Mms(m) = &msg.apdus[0] else {
            panic!("expected MMS")
        };
        assert_eq!((m.pdu_type, m.invoke_id), (PDU_CANCEL_REQUEST, Some(7)));
    }

    #[test]
    fn test_classify_reduced_stack() {
        use crate::cotp::{classify_payload, Iso102Payload};
        assert_eq!(classify_payload(&[0xa0, 0x0a]), Iso102Payload::MmsDirect);
        assert_eq!(classify_payload(&[0xa8, 0x26]), Iso102Payload::MmsDirect);
        assert_eq!(classify_payload(&[0xae]), Iso102Payload::Unknown);
        // Primitive PDUs: cancel-Request/Response, conclude-Request/Response.
        for t in [0x85u8, 0x86, 0x8b, 0x8c] {
            assert_eq!(classify_payload(&[t, 0x00]), Iso102Payload::MmsDirect);
        }
        assert_eq!(classify_payload(&[0x87]), Iso102Payload::Unknown);
        assert_eq!(classify_payload(&[0x0d]), Iso102Payload::IsoSession);
    }

    #[test]
    fn test_not_session() {
        assert_eq!(parse_iso_message(&[]), Err(IsoError::NotSession));
        assert_eq!(parse_iso_message(b"Hello"), Err(IsoError::NotSession));
    }

    #[test]
    fn test_malformed_does_not_panic() {
        let data = tsdu(&hex(OPER_WRITE));
        for n in 0..data.len() {
            let _ = parse_iso_message(&data[..n]);
            let mut corrupt = data.clone();
            corrupt[n] ^= 0xff;
            let _ = parse_iso_message(&corrupt);
        }
        for seed in 0u32..2000 {
            let v: Vec<u8> = (0..64u32)
                .map(|i| (seed.wrapping_mul(2654435761).wrapping_add(i * 40503) >> 7) as u8)
                .collect();
            let _ = parse_iso_message(&v);
            let _ = parse_mms(&v);
        }
    }
}
