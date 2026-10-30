// MMS Suricata app-layer state, transactions and registration
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

use super::consts::*;
use super::parser::*;
use crate::cotp::{
    parse_tpkt_cotp, probe_iso102, tpkt_frame, CotpReassembler, DtAssembly, Iso102Payload,
    Iso102Probe, TpktFrame, COTP_DT,
};
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata::applayer::{
    state_get_tx_iterator, AppLayerEvent, AppLayerFrameType, AppLayerRegisterParser,
    AppLayerRegisterProtocolDetection, AppLayerResult, AppLayerStateData, AppLayerTxData,
    RustParser, State, StreamSlice, Transaction, APP_LAYER_PARSER_EOF_TC, APP_LAYER_PARSER_EOF_TS,
    APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use suricata::conf::conf_get;
use suricata::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP, STREAM_TOSERVER};
use suricata::direction::Direction;
use suricata::frames::Frame;
use suricata::{
    build_slice, cast_pointer, export_state_data_get, export_tx_data_get, SCLogError, SCLogNotice,
};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, Flow, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

pub(crate) static mut ALPROTO_MMS: AppProto = ALPROTO_UNKNOWN;

/// Maximum number of live transactions before we force an error (DoS guard).
static mut MMS_MAX_TX: usize = 1024;

/// Largest reassembled COTP message (MMS PDU) accepted; larger ones raise
/// `message_too_large` and are skipped.
static mut MMS_MAX_MESSAGE_SIZE: usize = 1048576;

/// Most ICCP transfer set names remembered per flow.
const MAX_TRANSFER_SETS: usize = 64;

#[repr(u8)]
pub(crate) enum MmsFrameType {
    /// One TPKT frame (TPKT + COTP + user data segment).
    Pdu = 0,
}

impl AppLayerFrameType for MmsFrameType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Pdu),
            _ => None,
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            Self::Pdu => 0,
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "pdu" => Some(Self::Pdu),
            _ => None,
        }
    }

    fn to_cstring(&self) -> *const c_char {
        match self {
            Self::Pdu => b"pdu\0".as_ptr() as *const c_char,
        }
    }
}

#[derive(AppLayerEvent, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MmsEvent {
    MalformedPdu,
    MessageTooLarge,
    TooManyTransactions,
    AssociationRejected,
    Authentication,
    ControlOperation,
    SettingChange,
    DataSetChange,
    IccpTransferSetWrite,
    ProgramControl,
    ProgramDownload,
    ProgramUpload,
    DomainDelete,
    FileDelete,
    FileRename,
    FileTransfer,
    JournalChange,
    Reject,
    Abort,
    /// Data missing from the TCP stream of an MMS flow.
    StreamGap,
    /// A response whose request was never seen.
    OrphanResponse,
}

/// How a response is matched to its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairKey {
    Invoke(u32),
    Cancel(u32),
    Initiate,
    Conclude,
    Associate,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Request(PairKey),
    Response(PairKey),
    Single,
}

fn role(apdu: &Apdu) -> Role {
    match apdu {
        Apdu::Acse(a) => match a.kind {
            AcseKind::Aarq => Role::Request(PairKey::Associate),
            AcseKind::Aare => Role::Response(PairKey::Associate),
            AcseKind::Rlrq => Role::Request(PairKey::Release),
            AcseKind::Rlre => Role::Response(PairKey::Release),
            AcseKind::Abrt => Role::Single,
        },
        Apdu::Mms(m) => match (m.pdu_type, m.invoke_id) {
            (PDU_CONFIRMED_REQUEST, Some(id)) => Role::Request(PairKey::Invoke(id)),
            (PDU_CONFIRMED_RESPONSE | PDU_CONFIRMED_ERROR, Some(id)) => {
                Role::Response(PairKey::Invoke(id))
            }
            (PDU_CANCEL_REQUEST, Some(id)) => Role::Request(PairKey::Cancel(id)),
            (PDU_CANCEL_RESPONSE | PDU_CANCEL_ERROR, Some(id)) => {
                Role::Response(PairKey::Cancel(id))
            }
            // A reject names the confirmed request it refuses.
            (PDU_REJECT, Some(id)) => Role::Response(PairKey::Invoke(id)),
            (PDU_INITIATE_REQUEST, _) => Role::Request(PairKey::Initiate),
            (PDU_INITIATE_RESPONSE | PDU_INITIATE_ERROR, _) => Role::Response(PairKey::Initiate),
            (PDU_CONCLUDE_REQUEST, _) => Role::Request(PairKey::Conclude),
            (PDU_CONCLUDE_RESPONSE | PDU_CONCLUDE_ERROR, _) => Role::Response(PairKey::Conclude),
            _ => Role::Single,
        },
    }
}

/// The MMS PDU in an APDU, including an initiate PDU carried in ACSE.
pub(crate) fn apdu_mms(apdu: &Apdu) -> Option<&MmsPdu> {
    match apdu {
        Apdu::Mms(m) => Some(m),
        Apdu::Acse(a) => a.mms.as_ref(),
    }
}

#[derive(Debug, Default)]
struct Classification {
    events: Vec<MmsEvent>,
    dangerous: bool,
    technique: Option<&'static str>,
    iccp_transfer_set: bool,
}

impl Classification {
    fn set(&mut self, event: Option<MmsEvent>, dangerous: bool, technique: Option<&'static str>) {
        if let Some(e) = event {
            if !self.events.contains(&e) {
                self.events.push(e);
            }
        }
        self.dangerous |= dangerous;
        if self.technique.is_none() {
            self.technique = technique;
        }
    }
}

fn classify_write(
    c: &mut Classification,
    pdu: &MmsPdu,
    transfer_sets: &[(Option<String>, String)],
) {
    let mut technique = None;
    for o in &pdu.objects {
        let item = o.item.as_str();
        if item.contains(FC_CONTROL) {
            c.set(Some(MmsEvent::ControlOperation), true, None);
            technique = Some(T_UNAUTHORIZED_COMMAND);
        } else if FC_SETTINGS.iter().any(|fc| item.contains(fc)) {
            c.set(Some(MmsEvent::SettingChange), true, None);
            technique = technique.or(Some(T_MODIFY_PARAMETER));
        } else if transfer_sets
            .iter()
            .any(|(d, n)| n == item && (d.is_none() || d == &o.domain))
        {
            c.set(Some(MmsEvent::IccpTransferSetWrite), false, None);
            c.iccp_transfer_set = true;
            technique = technique.or(Some(T_MODIFY_PARAMETER));
        } else if !FC_CONTROL_BLOCKS.iter().any(|fc| item.contains(fc)) {
            technique = technique.or(Some(T_MODIFY_PARAMETER));
        }
    }
    c.set(None, false, technique);
}

/// Classify the first message of a transaction (request, or a single message).
fn classify_request(apdu: &Apdu, transfer_sets: &[(Option<String>, String)]) -> Classification {
    let mut c = Classification::default();
    if let Apdu::Acse(a) = apdu {
        match a.kind {
            AcseKind::Aarq if a.authentication => {
                c.set(Some(MmsEvent::Authentication), false, None)
            }
            AcseKind::Abrt => c.set(Some(MmsEvent::Abort), false, None),
            _ => {}
        }
        return c;
    }
    let pdu = match apdu_mms(apdu) {
        Some(p) => p,
        None => return c,
    };
    match pdu.pdu_type {
        PDU_REJECT => c.set(Some(MmsEvent::Reject), false, None),
        PDU_CONFIRMED_REQUEST => {
            let svc = pdu.service.unwrap_or(u32::MAX);
            match svc {
                SVC_IDENTIFY => c.set(None, false, Some(T_REMOTE_SYSTEM_INFO)),
                SVC_GET_NAME_LIST
                | SVC_GET_VARIABLE_ACCESS_ATTRIBUTES
                | SVC_GET_NAMED_VARIABLE_LIST_ATTRIBUTES
                | SVC_GET_DOMAIN_ATTRIBUTES
                | SVC_GET_PROGRAM_INVOCATION_ATTRIBUTES
                | SVC_FILE_DIRECTORY => c.set(None, false, Some(T_POINT_TAG_ID)),
                SVC_WRITE => classify_write(&mut c, pdu, transfer_sets),
                SVC_DEFINE_NAMED_VARIABLE_LIST | SVC_DEFINE_NAMED_VARIABLE => c.set(
                    Some(MmsEvent::DataSetChange),
                    false,
                    Some(T_MODIFY_PARAMETER),
                ),
                SVC_DELETE_NAMED_VARIABLE_LIST | SVC_DELETE_VARIABLE_ACCESS => c.set(
                    Some(MmsEvent::DataSetChange),
                    true,
                    Some(T_MODIFY_PARAMETER),
                ),
                SVC_CREATE_PROGRAM_INVOCATION => c.set(
                    Some(MmsEvent::ProgramControl),
                    false,
                    Some(T_CHANGE_OPERATING_MODE),
                ),
                SVC_START | SVC_STOP | SVC_RESUME | SVC_RESET | SVC_KILL => c.set(
                    Some(MmsEvent::ProgramControl),
                    true,
                    Some(T_CHANGE_OPERATING_MODE),
                ),
                SVC_DELETE_DOMAIN | SVC_DELETE_PROGRAM_INVOCATION => {
                    c.set(Some(MmsEvent::DomainDelete), true, Some(T_DATA_DESTRUCTION))
                }
                SVC_INITIATE_DOWNLOAD_SEQUENCE
                | SVC_DOWNLOAD_SEGMENT
                | SVC_TERMINATE_DOWNLOAD_SEQUENCE
                | SVC_REQUEST_DOMAIN_DOWNLOAD
                | SVC_LOAD_DOMAIN_CONTENT => c.set(
                    Some(MmsEvent::ProgramDownload),
                    true,
                    Some(T_PROGRAM_DOWNLOAD),
                ),
                SVC_INITIATE_UPLOAD_SEQUENCE
                | SVC_UPLOAD_SEGMENT
                | SVC_TERMINATE_UPLOAD_SEQUENCE
                | SVC_REQUEST_DOMAIN_UPLOAD
                | SVC_STORE_DOMAIN_CONTENT => {
                    c.set(Some(MmsEvent::ProgramUpload), false, Some(T_PROGRAM_UPLOAD))
                }
                SVC_OBTAIN_FILE => c.set(
                    Some(MmsEvent::FileTransfer),
                    true,
                    Some(T_LATERAL_TOOL_TRANSFER),
                ),
                SVC_FILE_DELETE => {
                    c.set(Some(MmsEvent::FileDelete), true, Some(T_DATA_DESTRUCTION))
                }
                SVC_FILE_RENAME => c.set(Some(MmsEvent::FileRename), false, None),
                SVC_FILE_OPEN | SVC_FILE_READ => c.set(None, false, Some(T_THEFT_OF_INFO)),
                SVC_INITIALIZE_JOURNAL | SVC_DELETE_JOURNAL => c.set(
                    Some(MmsEvent::JournalChange),
                    true,
                    Some(T_INDICATOR_REMOVAL),
                ),
                SVC_WRITE_JOURNAL | SVC_CREATE_JOURNAL => {
                    c.set(Some(MmsEvent::JournalChange), false, None)
                }
                _ => {}
            }
        }
        _ => {}
    }
    c
}

fn classify_response(apdu: &Apdu) -> Classification {
    let mut c = Classification::default();
    match apdu {
        Apdu::Mms(m) if m.pdu_type == PDU_REJECT => c.set(Some(MmsEvent::Reject), false, None),
        Apdu::Acse(a) if a.kind == AcseKind::Aare && a.result.is_some_and(|r| r != 0) => {
            c.set(Some(MmsEvent::AssociationRejected), false, None)
        }
        Apdu::Mms(m) if m.pdu_type == PDU_INITIATE_ERROR => {
            c.set(Some(MmsEvent::AssociationRejected), false, None)
        }
        Apdu::Acse(a)
            if a.mms
                .as_ref()
                .is_some_and(|m| m.pdu_type == PDU_INITIATE_ERROR) =>
        {
            c.set(Some(MmsEvent::AssociationRejected), false, None)
        }
        _ => {}
    }
    c
}

pub(crate) struct MmsTransaction {
    pub tx_id: u64,
    /// Direction of the request (or of the only message).
    pub request_to_server: bool,
    pub request: Option<Apdu>,
    pub response: Option<Apdu>,
    /// Session SPDU of the first message.
    pub spdu: Option<u8>,
    key: Option<PairKey>,
    pub complete: bool,
    pub is_dangerous: bool,
    pub attack_technique: Option<&'static str>,
    pub iccp_transfer_set: bool,
    /// Set when part of this exchange was not observed or could not be decoded.
    pub loss: Option<TelemetryLoss>,
    tx_data: AppLayerTxData,
}

/// Why telemetry for a transaction is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LossReason {
    /// Data missing from the TCP stream (capture loss or sensor overload).
    StreamGap,
    /// A reassembled message exceeded max-message-size and was skipped.
    MessageTooLarge,
    /// Closed at the max-tx limit before a response arrived.
    MaxTx,
    /// A response arrived for a request that was never seen.
    RequestNotSeen,
    /// The message could not be decoded.
    Malformed,
    /// The connection ended before a response arrived.
    ConnectionClosed,
}

impl LossReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StreamGap => "stream_gap",
            Self::MessageTooLarge => "message_too_large",
            Self::MaxTx => "max_tx",
            Self::RequestNotSeen => "request_not_seen",
            Self::Malformed => "malformed",
            Self::ConnectionClosed => "connection_closed",
        }
    }
}

/// Which part of the exchange is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Missing {
    Request,
    Response,
    /// One message (or part of one) of unknown type.
    Message,
}

impl Missing {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Message => "message",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TelemetryLoss {
    pub reason: LossReason,
    pub missing: Missing,
    /// Direction of the data that is missing.
    pub to_server: bool,
}

impl Transaction for MmsTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl MmsTransaction {
    fn new(tx_id: u64, request_to_server: bool) -> Self {
        Self {
            tx_id,
            request_to_server,
            request: None,
            response: None,
            spdu: None,
            key: None,
            complete: false,
            is_dangerous: false,
            attack_technique: None,
            iccp_transfer_set: false,
            loss: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    pub fn mms_request(&self) -> Option<&MmsPdu> {
        self.request.as_ref().and_then(apdu_mms)
    }

    pub fn mms_response(&self) -> Option<&MmsPdu> {
        self.response.as_ref().and_then(apdu_mms)
    }

    /// Confirmed service of the request, or of an orphan response.
    pub fn service(&self) -> Option<u32> {
        let confirmed = |m: &MmsPdu| {
            if m.pdu_type == PDU_CONFIRMED_REQUEST || m.pdu_type == PDU_CONFIRMED_RESPONSE {
                m.service
            } else {
                None
            }
        };
        self.mms_request()
            .and_then(confirmed)
            .or_else(|| self.mms_response().and_then(confirmed))
    }

    fn apply(&mut self, c: Classification) {
        for e in c.events {
            self.tx_data.set_event(e as u8);
        }
        self.is_dangerous |= c.dangerous;
        if self.attack_technique.is_none() {
            self.attack_technique = c.technique;
        }
        self.iccp_transfer_set |= c.iccp_transfer_set;
    }

    fn set_event(&mut self, e: MmsEvent) {
        self.tx_data.set_event(e as u8);
    }

    /// Limit detection to the direction of the only message in this
    /// transaction, so event rules match once. Must be called before any
    /// event is set.
    fn single_message(&mut self, to_server: bool) {
        self.tx_data = AppLayerTxData::for_direction(if to_server {
            Direction::ToServer
        } else {
            Direction::ToClient
        });
    }
}

#[derive(Default)]
pub(crate) struct MmsState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<MmsTransaction>,
    reassembly_ts: CotpReassembler,
    reassembly_tc: CotpReassembler,
    /// ICCP transfer set names learned from Next_DSTransfer_Set reads.
    transfer_sets: Vec<(Option<String>, String)>,
    /// Transaction count at which to next close pending requests (see parse()).
    limit_check_at: usize,
    /// A stream gap has occurred in this direction at some point.
    gap_seen_ts: bool,
    gap_seen_tc: bool,
    /// A gap occurred and no message has decoded since: a decode failure now
    /// is the remainder of a message cut by the gap, not a malformed PDU.
    after_gap_ts: bool,
    after_gap_tc: bool,
    /// A message in this direction was dropped for exceeding max-message-size.
    oversize_seen_ts: bool,
    oversize_seen_tc: bool,
}

impl State<MmsTransaction> for MmsState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&MmsTransaction> {
        self.transactions.get(index)
    }
}

impl MmsState {
    pub fn new() -> Self {
        Default::default()
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1)
        {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&self, tx_id: u64) -> Option<&MmsTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self, request_to_server: bool) -> &mut MmsTransaction {
        self.tx_id += 1;
        self.transactions
            .push_back(MmsTransaction::new(self.tx_id, request_to_server));
        self.transactions.back_mut().unwrap()
    }

    /// A complete transaction carrying only an event.
    fn event_tx(&mut self, to_server: bool, event: MmsEvent) {
        self.record_tx(to_server, Some(event), None);
    }

    /// A complete single-direction transaction recording an event and/or a
    /// telemetry loss for data in direction `to_server`.
    fn record_tx(
        &mut self,
        to_server: bool,
        event: Option<MmsEvent>,
        loss: Option<(LossReason, Missing)>,
    ) {
        let tx = self.new_tx(to_server);
        tx.single_message(to_server);
        tx.complete = true;
        if let Some(e) = event {
            tx.set_event(e);
        }
        tx.loss = loss.map(|(reason, missing)| TelemetryLoss {
            reason,
            missing,
            to_server,
        });
    }

    fn after_gap(&mut self, to_server: bool) -> &mut bool {
        if to_server {
            &mut self.after_gap_ts
        } else {
            &mut self.after_gap_tc
        }
    }

    /// A message in this direction could not be framed or decoded. Right
    /// after a stream gap that is the remainder of a message cut by the gap,
    /// already reported by the gap's own record; otherwise it is malformed.
    fn undecodable(&mut self, to_server: bool) {
        if !*self.after_gap(to_server) {
            self.record_tx(
                to_server,
                Some(MmsEvent::MalformedPdu),
                Some((LossReason::Malformed, Missing::Message)),
            );
        }
    }

    /// Most likely reason a response travelling in `to_server` was not seen
    /// by the time the connection ended.
    fn unanswered_reason(&self, to_server: bool) -> LossReason {
        let (oversize, gap) = if to_server {
            (self.oversize_seen_ts, self.gap_seen_ts)
        } else {
            (self.oversize_seen_tc, self.gap_seen_tc)
        };
        if oversize {
            LossReason::MessageTooLarge
        } else if gap {
            LossReason::StreamGap
        } else {
            LossReason::ConnectionClosed
        }
    }

    /// Close pending requests whose response would travel in direction
    /// `to_server`, marking the response as missing for `reason`.
    fn close_awaiting(&mut self, to_server: bool, reason: LossReason) {
        for tx in self.transactions.iter_mut() {
            if !tx.complete && tx.request_to_server != to_server {
                tx.complete = true;
                if tx.loss.is_none() {
                    tx.loss = Some(TelemetryLoss {
                        reason,
                        missing: Missing::Response,
                        to_server,
                    });
                }
            }
        }
    }

    /// Drop partial messages, and close requests whose response would have
    /// travelled in the direction with the gap: it may never be seen.
    fn on_gap(&mut self, to_server: bool) {
        if to_server {
            self.reassembly_ts.reset();
            self.gap_seen_ts = true;
        } else {
            self.reassembly_tc.reset();
            self.gap_seen_tc = true;
        }
        *self.after_gap(to_server) = true;
        self.close_awaiting(to_server, LossReason::StreamGap);
        self.record_tx(
            to_server,
            Some(MmsEvent::StreamGap),
            Some((LossReason::StreamGap, Missing::Message)),
        );
    }

    /// The stream in direction `to_server` has ended: responses that would
    /// travel that way can no longer arrive.
    fn on_close(&mut self, to_server: bool) {
        let reason = self.unanswered_reason(to_server);
        self.close_awaiting(to_server, reason);
    }

    /// At the transaction limit, close every pending request so it can be
    /// logged and freed instead of giving up on the flow, and raise
    /// too_many_transactions once.
    fn close_pending(&mut self, to_server: bool) {
        for tx in self.transactions.iter_mut() {
            if !tx.complete {
                tx.complete = true;
                tx.loss = Some(TelemetryLoss {
                    reason: LossReason::MaxTx,
                    missing: Missing::Response,
                    to_server: !tx.request_to_server,
                });
            }
        }
        self.event_tx(to_server, MmsEvent::TooManyTransactions);
    }

    /// Remember the transfer set name returned for a Next_DSTransfer_Set read.
    fn learn_transfer_set(&mut self, request: Option<&MmsPdu>, response: &MmsPdu) {
        let asked = request.is_some_and(|r| {
            r.service == Some(SVC_READ)
                && r.objects
                    .iter()
                    .any(|o| o.item == ICCP_NEXT_DS_TRANSFER_SET)
        });
        if let (true, Some(ts)) = (asked, response.transfer_set.as_ref()) {
            if !self.transfer_sets.contains(ts) && self.transfer_sets.len() < MAX_TRANSFER_SETS {
                self.transfer_sets.push(ts.clone());
            }
        }
    }

    fn handle_apdu(&mut self, apdu: Apdu, spdu: Option<u8>, to_server: bool) {
        match role(&apdu) {
            Role::Request(key) => {
                let c = classify_request(&apdu, &self.transfer_sets);
                let tx = self.new_tx(to_server);
                tx.spdu = spdu;
                tx.key = Some(key);
                tx.request = Some(apdu);
                tx.apply(c);
            }
            Role::Response(key) => {
                let c = classify_response(&apdu);
                let pending = self.transactions.iter().rposition(|tx| {
                    !tx.complete && tx.key == Some(key) && tx.request_to_server != to_server
                });
                let index = match pending {
                    Some(i) => i,
                    None => {
                        // Orphan response: the request was lost in a gap or
                        // sent before the capture started.
                        let gap = if to_server {
                            self.gap_seen_tc
                        } else {
                            self.gap_seen_ts
                        };
                        let tx = self.new_tx(!to_server);
                        tx.single_message(to_server);
                        tx.spdu = spdu;
                        tx.set_event(MmsEvent::OrphanResponse);
                        tx.loss = Some(TelemetryLoss {
                            reason: if gap {
                                LossReason::StreamGap
                            } else {
                                LossReason::RequestNotSeen
                            },
                            missing: Missing::Request,
                            to_server: !to_server,
                        });
                        self.transactions.len() - 1
                    }
                };
                if let Some(resp) = apdu_mms(&apdu) {
                    let request = self.transactions[index].mms_request().cloned();
                    self.learn_transfer_set(request.as_ref(), resp);
                }
                let tx = &mut self.transactions[index];
                tx.response = Some(apdu);
                tx.complete = true;
                tx.apply(c);
            }
            Role::Single => {
                let c = classify_request(&apdu, &self.transfer_sets);
                let tx = self.new_tx(to_server);
                tx.single_message(to_server);
                tx.spdu = spdu;
                tx.request = Some(apdu);
                tx.complete = true;
                tx.apply(c);
            }
        }
    }

    fn handle_tsdu(&mut self, tsdu: &[u8], to_server: bool) {
        match parse_iso_message(tsdu) {
            Ok(msg) if msg.apdus.is_empty() => {
                // Session-level abort/refuse without user data.
                match msg.spdu {
                    Some(SPDU_AB) => self.event_tx(to_server, MmsEvent::Abort),
                    Some(SPDU_RF) => self.event_tx(to_server, MmsEvent::AssociationRejected),
                    _ => {}
                }
                if let Some(tx) = self.transactions.back_mut() {
                    if tx.spdu.is_none() {
                        tx.spdu = msg.spdu;
                    }
                }
            }
            Ok(msg) => {
                *self.after_gap(to_server) = false;
                for apdu in msg.apdus {
                    self.handle_apdu(apdu, msg.spdu, to_server);
                }
            }
            Err(_) => self.undecodable(to_server),
        }
    }

    fn handle_frame(&mut self, frame: &[u8], to_server: bool) {
        let cotp = match parse_tpkt_cotp(frame) {
            Ok((_, cotp)) => cotp,
            Err(_) => {
                self.undecodable(to_server);
                return;
            }
        };
        if cotp.pdu_type != COTP_DT {
            return;
        }
        let max = unsafe { MMS_MAX_MESSAGE_SIZE };
        let reassembly = if to_server {
            &mut self.reassembly_ts
        } else {
            &mut self.reassembly_tc
        };
        match reassembly.push(cotp.payload, cotp.eot, max) {
            DtAssembly::Complete(tsdu) if !tsdu.is_empty() => self.handle_tsdu(&tsdu, to_server),
            DtAssembly::Overflow => {
                if to_server {
                    self.oversize_seen_ts = true;
                } else {
                    self.oversize_seen_tc = true;
                }
                self.record_tx(
                    to_server,
                    Some(MmsEvent::MessageTooLarge),
                    Some((LossReason::MessageTooLarge, Missing::Message)),
                )
            }
            _ => {}
        }
    }

    fn parse(
        &mut self,
        flow: *const Flow,
        stream_slice: &StreamSlice,
        to_server: bool,
    ) -> AppLayerResult {
        let input = stream_slice.as_slice();
        let max_tx = unsafe { MMS_MAX_TX };
        self.limit_check_at = max_tx;
        let mut start = input;
        while !start.is_empty() {
            let len = match tpkt_frame(start, u16::MAX as usize) {
                TpktFrame::Complete(len) => len,
                TpktFrame::Incomplete(needed) => {
                    let consumed = input.len() - start.len();
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                // A malformed TPKT can't be resynchronised, but it must not
                // disable inspection of the whole flow (e.g. of the other,
                // well-formed direction). Flag it and drop the rest of this
                // slice instead of erroring the flow.
                TpktFrame::Invalid => {
                    self.undecodable(to_server);
                    return AppLayerResult::ok();
                }
            };
            let frame = &start[..len];
            let _ = Frame::new(
                flow,
                stream_slice,
                frame,
                len as i64,
                MmsFrameType::Pdu as u8,
                None,
            );
            self.handle_frame(frame, to_server);
            start = &start[len..];

            // Transactions are only freed between calls, so space the scans out
            // to keep a large input linear.
            if self.transactions.len() >= self.limit_check_at {
                self.close_pending(to_server);
                self.limit_check_at = self.transactions.len() + max_tx;
            }
        }
        AppLayerResult::ok()
    }
}

// C FFI exports

unsafe extern "C" fn mms_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    if input.is_null() || input_len == 0 {
        return ALPROTO_UNKNOWN;
    }
    let slice = build_slice!(input, input_len as usize);
    match probe_iso102(slice) {
        Iso102Probe::Detected(Iso102Payload::IsoSession | Iso102Payload::MmsDirect) => ALPROTO_MMS,
        Iso102Probe::NeedMore => ALPROTO_UNKNOWN,
        _ => ALPROTO_FAILED,
    }
}

extern "C" fn mms_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = MmsState::new();
    Box::into_raw(Box::new(state)) as *mut c_void
}

unsafe extern "C" fn mms_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut MmsState));
}

unsafe extern "C" fn mms_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, MmsState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn mms_parse_ts(
    flow: *mut Flow,
    state: *mut c_void,
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, MmsState);
    if stream_slice.is_gap() {
        state.on_gap(true);
        return AppLayerResult::ok();
    }
    let result = state.parse(flow, &stream_slice, true);
    if SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
        state.on_close(true);
    }
    result
}

unsafe extern "C" fn mms_parse_tc(
    flow: *mut Flow,
    state: *mut c_void,
    pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let state = cast_pointer!(state, MmsState);
    if stream_slice.is_gap() {
        state.on_gap(false);
        return AppLayerResult::ok();
    }
    let result = state.parse(flow, &stream_slice, false);
    if SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
        state.on_close(false);
    }
    result
}

unsafe extern "C" fn mms_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, MmsState);
    match state.get_tx(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn mms_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, MmsState);
    state.tx_id
}

/// The request direction is done as soon as the request is seen; the other
/// direction when the response arrives (or for single-message transactions).
unsafe extern "C" fn mms_tx_get_alstate_progress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = cast_pointer!(tx, MmsTransaction);
    let to_server = direction & STREAM_TOSERVER != 0;
    if tx.complete || (to_server == tx.request_to_server && tx.request.is_some()) {
        1
    } else {
        0
    }
}

export_tx_data_get!(mms_get_tx_data, MmsTransaction);
export_state_data_get!(mms_get_state_data, MmsState);

const PARSER_NAME: &[u8] = b"mms\0";

fn conf_usize(key: &str, target: &mut usize) {
    if let Some(val) = conf_get(key) {
        match val.parse::<usize>() {
            Ok(v) if v > 0 => *target = v,
            _ => {
                SCLogError!("Invalid value for {}", key);
            }
        }
    }
}

pub(crate) unsafe extern "C" fn mms_register_parser() {
    let default_port = CString::new("[102]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(mms_probing_parser),
        probe_tc: Some(mms_probing_parser),
        min_depth: 0,
        // Room for the COTP CR before the first DT.
        max_depth: 512,
        state_new: mms_state_new,
        state_free: mms_state_free,
        tx_free: mms_state_tx_free,
        parse_ts: mms_parse_ts,
        parse_tc: mms_parse_tc,
        get_tx_count: mms_state_get_tx_count,
        get_tx: mms_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: mms_tx_get_alstate_progress,
        get_eventinfo: Some(MmsEvent::get_event_info),
        get_eventinfo_byid: Some(MmsEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<MmsState, MmsTransaction>),
        get_tx_data: mms_get_tx_data,
        get_state_data: mms_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: Some(MmsFrameType::ffi_id_from_name),
        get_frame_name_by_id: Some(MmsFrameType::ffi_name_from_id),
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MMS = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        // Optional config: app-layer.protocols.mms.{max-tx,max-message-size}
        conf_usize(
            "app-layer.protocols.mms.max-tx",
            &mut *std::ptr::addr_of_mut!(MMS_MAX_TX),
        );
        conf_usize(
            "app-layer.protocols.mms.max-message-size",
            &mut *std::ptr::addr_of_mut!(MMS_MAX_MESSAGE_SIZE),
        );
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MMS);
        SCLogNotice!("MMS parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for mms.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(domain: &str, item: &str) -> ObjectName {
        ObjectName {
            scope: ObjectScope::Domain,
            domain: Some(domain.into()),
            item: item.into(),
        }
    }

    fn request(invoke: u32, service: u32, objects: Vec<ObjectName>) -> Apdu {
        Apdu::Mms(MmsPdu {
            pdu_type: PDU_CONFIRMED_REQUEST,
            invoke_id: Some(invoke),
            service: Some(service),
            objects,
            ..Default::default()
        })
    }

    fn response(invoke: u32, service: u32) -> MmsPdu {
        MmsPdu {
            pdu_type: PDU_CONFIRMED_RESPONSE,
            invoke_id: Some(invoke),
            service: Some(service),
            success_count: 1,
            ..Default::default()
        }
    }

    #[test]
    fn test_request_response_pairing() {
        let mut s = MmsState::new();
        s.handle_apdu(
            request(1, SVC_READ, vec![obj("LD0", "A")]),
            Some(SPDU_DT),
            true,
        );
        s.handle_apdu(
            request(2, SVC_READ, vec![obj("LD0", "B")]),
            Some(SPDU_DT),
            true,
        );
        assert_eq!(s.transactions.len(), 2);
        assert!(s.transactions.iter().all(|t| !t.complete));
        // Responses out of order, matched by invoke ID and direction.
        s.handle_apdu(Apdu::Mms(response(2, SVC_READ)), Some(SPDU_DT), false);
        assert!(!s.transactions[0].complete);
        assert!(s.transactions[1].complete);
        // A response in the request's own direction does not complete it.
        s.handle_apdu(Apdu::Mms(response(1, SVC_READ)), Some(SPDU_DT), true);
        assert!(!s.transactions[0].complete);
        assert_eq!(s.transactions.len(), 3);
        s.handle_apdu(Apdu::Mms(response(1, SVC_READ)), Some(SPDU_DT), false);
        assert!(s.transactions[0].complete);
        assert_eq!(s.transactions[0].service(), Some(SVC_READ));
    }

    #[test]
    fn test_control_write_is_dangerous() {
        let mut s = MmsState::new();
        s.handle_apdu(
            request(3, SVC_WRITE, vec![obj("LD0", "GGIO1$CO$SPCSO1$Oper")]),
            Some(SPDU_DT),
            true,
        );
        let tx = &s.transactions[0];
        assert!(tx.is_dangerous);
        assert_eq!(tx.attack_technique, Some(T_UNAUTHORIZED_COMMAND));
        // Report control block writes are configuration, not process changes.
        s.handle_apdu(
            request(4, SVC_WRITE, vec![obj("LD0", "LLN0$RP$EventsRCB01$RptEna")]),
            Some(SPDU_DT),
            true,
        );
        let tx = &s.transactions[1];
        assert!(!tx.is_dangerous);
        assert_eq!(tx.attack_technique, None);
    }

    #[test]
    fn test_iccp_transfer_set_tracking() {
        let mut s = MmsState::new();
        s.handle_apdu(
            request(
                10,
                SVC_READ,
                vec![obj("KIRKLAND", ICCP_NEXT_DS_TRANSFER_SET)],
            ),
            Some(SPDU_DT),
            true,
        );
        let mut resp = response(10, SVC_READ);
        resp.transfer_set = Some((Some("KIRKLAND".into()), "CITEC_TS0".into()));
        s.handle_apdu(Apdu::Mms(resp), Some(SPDU_DT), false);
        assert_eq!(s.transfer_sets.len(), 1);

        s.handle_apdu(
            request(11, SVC_WRITE, vec![obj("KIRKLAND", "CITEC_TS0")]),
            Some(SPDU_DT),
            true,
        );
        assert!(s.transactions.back().unwrap().iccp_transfer_set);
        // Same name in another domain is a different object.
        s.handle_apdu(
            request(12, SVC_WRITE, vec![obj("BELLEVUE", "CITEC_TS0")]),
            Some(SPDU_DT),
            true,
        );
        assert!(!s.transactions.back().unwrap().iccp_transfer_set);
    }

    #[test]
    fn test_transfer_set_only_learned_from_next_ds_transfer_set() {
        let mut s = MmsState::new();
        s.handle_apdu(
            request(1, SVC_READ, vec![obj("LD0", "Other")]),
            Some(SPDU_DT),
            true,
        );
        let mut resp = response(1, SVC_READ);
        resp.transfer_set = Some((Some("LD0".into()), "X".into()));
        s.handle_apdu(Apdu::Mms(resp), Some(SPDU_DT), false);
        assert!(s.transfer_sets.is_empty());
    }

    #[test]
    fn test_orphan_response_and_single() {
        let mut s = MmsState::new();
        s.handle_apdu(Apdu::Mms(response(99, SVC_READ)), Some(SPDU_DT), false);
        let tx = &s.transactions[0];
        assert!(tx.complete && tx.request.is_none());
        assert!(tx.request_to_server);
        s.handle_apdu(
            Apdu::Mms(MmsPdu {
                pdu_type: PDU_UNCONFIRMED,
                service: Some(0),
                ..Default::default()
            }),
            Some(SPDU_DT),
            false,
        );
        let tx = &s.transactions[1];
        assert!(tx.complete && !tx.request_to_server);
    }

    #[test]
    fn test_parse_frames_with_segmented_message() {
        // OPER write from control.pcap split across two DTs (EOT=0, then EOT=1).
        let full: Vec<u8> = {
            let h = "0300006e02f080010001006161305f020103a05aa058020103a553a02f302da0\
                2ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f\
                24535043534f31244f706572a020a21e830101a205850103890086010191086a\
                e266b16000000083010084020600";
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect()
        };
        let tsdu = &full[7..];
        let (a, b) = tsdu.split_at(40);
        let dt = |data: &[u8], eot: bool| {
            let mut f = vec![0x03, 0x00, 0, 0, 0x02, 0xF0, if eot { 0x80 } else { 0x00 }];
            f.extend_from_slice(data);
            let len = (f.len() as u16).to_be_bytes();
            f[2] = len[0];
            f[3] = len[1];
            f
        };
        let mut s = MmsState::new();
        s.handle_frame(&dt(a, false), true);
        assert!(s.transactions.is_empty());
        s.handle_frame(&dt(b, true), true);
        assert_eq!(s.transactions.len(), 1);
        let tx = &s.transactions[0];
        assert_eq!(tx.service(), Some(SVC_WRITE));
        assert!(tx.is_dangerous);
    }

    #[test]
    fn test_garbage_tsdu_is_malformed_event() {
        let mut s = MmsState::new();
        s.handle_tsdu(b"\x0d\xff", true);
        assert_eq!(s.transactions.len(), 1);
        assert!(s.transactions[0].complete);
    }

    fn aare(result: u32, initiate_error: bool) -> Apdu {
        Apdu::Acse(AcseApdu {
            kind: AcseKind::Aare,
            context_name: None,
            called_ap_title: None,
            called_ae_qualifier: None,
            calling_ap_title: None,
            calling_ae_qualifier: None,
            mechanism_name: None,
            authentication: false,
            result: Some(result),
            reason: None,
            mms: Some(MmsPdu {
                pdu_type: if initiate_error {
                    PDU_INITIATE_ERROR
                } else {
                    PDU_INITIATE_RESPONSE
                },
                ..Default::default()
            }),
        })
    }

    fn mms(pdu_type: u8, invoke: u32) -> Apdu {
        Apdu::Mms(MmsPdu {
            pdu_type,
            invoke_id: Some(invoke),
            ..Default::default()
        })
    }

    #[test]
    fn test_reject_and_cancel_error_close_their_request() {
        let mut s = MmsState::new();
        s.handle_apdu(request(5, SVC_READ, vec![]), Some(SPDU_DT), true);
        s.handle_apdu(mms(PDU_REJECT, 5), Some(SPDU_DT), false);
        assert_eq!(s.transactions.len(), 1);
        assert!(s.transactions[0].complete);
        assert!(matches!(
            s.transactions[0].response,
            Some(Apdu::Mms(MmsPdu {
                pdu_type: PDU_REJECT,
                ..
            }))
        ));
        assert!(
            classify_response(s.transactions[0].response.as_ref().unwrap())
                .events
                .contains(&MmsEvent::Reject)
        );

        s.handle_apdu(mms(PDU_CANCEL_REQUEST, 9), Some(SPDU_DT), true);
        s.handle_apdu(mms(PDU_CANCEL_ERROR, 9), Some(SPDU_DT), false);
        assert_eq!(s.transactions.len(), 2);
        assert!(s.transactions[1].complete);
    }

    #[test]
    fn test_gap_closes_requests_awaiting_that_direction() {
        let mut s = MmsState::new();
        s.handle_apdu(request(1, SVC_READ, vec![]), Some(SPDU_DT), true);
        s.handle_apdu(request(2, SVC_READ, vec![]), Some(SPDU_DT), false);
        // Gap in the to-client direction: the response to request 1 may be lost.
        s.on_gap(false);
        assert!(s.transactions[0].complete);
        assert!(!s.transactions[1].complete);
    }

    #[test]
    fn test_transaction_limit_closes_pending_once() {
        let mut s = MmsState::new();
        for id in 0..10 {
            s.handle_apdu(request(id, SVC_READ, vec![]), Some(SPDU_DT), true);
        }
        s.close_pending(true);
        assert_eq!(s.transactions.len(), 11);
        assert!(s.transactions.iter().all(|t| t.complete));
        // Only the added event transaction carries no request.
        assert_eq!(
            s.transactions
                .iter()
                .filter(|t| t.request.is_none())
                .count(),
            1
        );
    }

    #[test]
    fn test_gap_marks_lost_responses_and_records_gap() {
        let mut s = MmsState::new();
        s.handle_apdu(request(1, SVC_WRITE, vec![]), Some(SPDU_DT), true);
        s.on_gap(false);
        let tx = &s.transactions[0];
        assert!(tx.complete);
        assert_eq!(
            tx.loss,
            Some(TelemetryLoss {
                reason: LossReason::StreamGap,
                missing: Missing::Response,
                to_server: false
            })
        );
        // A record for the gap itself.
        let gap = s.transactions.back().unwrap();
        assert!(gap.request.is_none());
        assert_eq!(gap.loss.unwrap().reason, LossReason::StreamGap);
        assert_eq!(gap.loss.unwrap().missing, Missing::Message);
    }

    #[test]
    fn test_decode_failure_after_gap_is_gap_not_malformed() {
        let mut s = MmsState::new();
        s.on_gap(true);
        let n = s.transactions.len();
        s.handle_tsdu(b"\x0d\xff", true);
        // Covered by the gap's own record: no extra record, no malformed_pdu.
        assert_eq!(s.transactions.len(), n);
        // The other direction is unaffected.
        s.handle_tsdu(b"\x0d\xff", false);
        assert_eq!(
            s.transactions.back().unwrap().loss.unwrap().reason,
            LossReason::Malformed
        );
    }

    #[test]
    fn test_after_gap_cleared_by_successful_decode() {
        let mut s = MmsState::new();
        s.on_gap(true);
        // A good message (conclude-Request, reduced stack) clears the gap state.
        s.handle_tsdu(&[0x8b, 0x00], true);
        s.handle_tsdu(b"\x0d\xff", true);
        assert_eq!(
            s.transactions.back().unwrap().loss.unwrap().reason,
            LossReason::Malformed
        );
    }

    #[test]
    fn test_orphan_response_reason() {
        let mut s = MmsState::new();
        s.handle_apdu(Apdu::Mms(response(7, SVC_WRITE)), Some(SPDU_DT), false);
        let l = s.transactions.back().unwrap().loss.unwrap();
        assert_eq!(
            (l.reason, l.missing, l.to_server),
            (LossReason::RequestNotSeen, Missing::Request, true)
        );
        // After a gap in the request direction the gap explains it.
        s.on_gap(true);
        s.handle_apdu(Apdu::Mms(response(8, SVC_WRITE)), Some(SPDU_DT), false);
        let l = s.transactions.back().unwrap().loss.unwrap();
        assert_eq!(l.reason, LossReason::StreamGap);
    }

    #[test]
    fn test_max_tx_and_close_mark_missing_response() {
        let mut s = MmsState::new();
        s.handle_apdu(request(1, SVC_READ, vec![]), Some(SPDU_DT), true);
        s.handle_apdu(request(2, SVC_READ, vec![]), Some(SPDU_DT), false);
        // Client side ends: responses to the server's request can't arrive.
        s.on_close(true);
        assert!(!s.transactions[0].complete);
        assert_eq!(
            s.transactions[1].loss.unwrap().reason,
            LossReason::ConnectionClosed
        );
        s.close_pending(true);
        let l = s.transactions[0].loss.unwrap();
        assert_eq!(
            (l.reason, l.missing, l.to_server),
            (LossReason::MaxTx, Missing::Response, false)
        );
        // A completed exchange is not marked.
        let mut s = MmsState::new();
        s.handle_apdu(request(3, SVC_READ, vec![]), Some(SPDU_DT), true);
        s.handle_apdu(Apdu::Mms(response(3, SVC_READ)), Some(SPDU_DT), false);
        s.on_close(false);
        assert_eq!(s.transactions[0].loss, None);
    }

    #[test]
    fn test_unanswered_reason_prefers_observed_loss() {
        let mut s = MmsState::new();
        s.handle_apdu(request(1, SVC_READ, vec![]), Some(SPDU_DT), true);
        s.oversize_seen_tc = true;
        s.on_close(false);
        assert_eq!(
            s.transactions[0].loss.unwrap().reason,
            LossReason::MessageTooLarge
        );
    }

    #[test]
    fn test_oversize_message_records_loss() {
        let mut s = MmsState::new();
        let big = vec![0u8; 2 * 1048576];
        let mut frame = vec![0x03, 0x00, 0x00, 0x00, 0x02, 0xF0, 0x00];
        frame.extend_from_slice(&big[..60000]);
        let len = (frame.len() as u16).to_be_bytes();
        frame[2] = len[0];
        frame[3] = len[1];
        // Feed EOT=0 segments until the 1 MB default limit is exceeded.
        for _ in 0..20 {
            s.handle_frame(&frame, false);
        }
        let l = s.transactions.back().unwrap().loss.unwrap();
        assert_eq!(
            (l.reason, l.missing, l.to_server),
            (LossReason::MessageTooLarge, Missing::Message, false)
        );
    }

    #[test]
    fn test_association_rejected() {
        let rejected = |a: &Apdu| {
            classify_response(a)
                .events
                .contains(&MmsEvent::AssociationRejected)
        };
        assert!(!rejected(&aare(0, false)));
        assert!(rejected(&aare(1, false)));
        assert!(rejected(&aare(2, false)));
        // Accepted by ACSE but refused by MMS (initiate-Error).
        assert!(rejected(&aare(0, true)));
    }

    #[test]
    fn test_classification_by_service() {
        let class = |svc: u32| classify_request(&request(1, svc, vec![]), &[]);
        let c = class(SVC_STOP);
        assert!(c.dangerous && c.events.contains(&MmsEvent::ProgramControl));
        assert_eq!(c.technique, Some(T_CHANGE_OPERATING_MODE));
        let c = class(SVC_INITIATE_DOWNLOAD_SEQUENCE);
        assert!(c.dangerous && c.events.contains(&MmsEvent::ProgramDownload));
        let c = class(SVC_FILE_DELETE);
        assert!(c.dangerous && c.events.contains(&MmsEvent::FileDelete));
        let c = class(SVC_INITIALIZE_JOURNAL);
        assert!(c.dangerous && c.events.contains(&MmsEvent::JournalChange));
        let c = class(SVC_IDENTIFY);
        assert!(!c.dangerous && c.events.is_empty());
        assert_eq!(c.technique, Some(T_REMOTE_SYSTEM_INFO));
        let c = class(SVC_READ);
        assert!(!c.dangerous && c.events.is_empty() && c.technique.is_none());
    }
}

/// Fuzzing harness: drive the state machine like `parse()` does, without FFI.
/// Each frame is preceded by a control byte: bit 0 picks the direction,
/// bit 7 injects a stream gap instead of a frame.
#[cfg(fuzzing)]
pub(crate) fn fuzz_feed(data: &[u8]) {
    unsafe {
        // Small limit so oversize handling is reachable.
        MMS_MAX_MESSAGE_SIZE = 4096;
    }
    let mut s = MmsState::new();
    let mut input = data;
    while let Some((&ctl, rest)) = input.split_first() {
        input = rest;
        let to_server = ctl & 1 == 0;
        if ctl & 0x80 != 0 {
            s.on_gap(to_server);
            continue;
        }
        match tpkt_frame(input, u16::MAX as usize) {
            TpktFrame::Complete(len) => {
                s.handle_frame(&input[..len], to_server);
                input = &input[len..];
            }
            TpktFrame::Invalid => {
                s.undecodable(to_server);
                break;
            }
            TpktFrame::Incomplete(_) => break,
        }
        for tx in s.transactions.iter() {
            let _ = (tx.service(), tx.mms_request(), tx.mms_response());
        }
        if s.transactions.len() >= 64 {
            s.close_pending(to_server);
        }
        // Suricata frees completed transactions after inspection/logging.
        s.transactions.retain(|t| !t.complete);
    }
}
