// Suricata ICS protocol parsers plugin (S7comm, IEC 60870-5-104, MMS)
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0

mod consts;
mod cotp;
mod detect;
#[cfg(fuzzing)]
pub mod fuzz_api;
mod iec104;
mod log;
mod mms;
mod parser;
pub mod plugin;
mod s7comm;
