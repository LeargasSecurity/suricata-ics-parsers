// Suricata version check for the ICS parsers plugin
// Copyright (C) 2026 Leargas Security
// License: GPL-2.0
//
// The plugin embeds parts of Suricata's own Rust code from the source tree it
// was built against, and Suricata does not refuse a plugin built for another
// release. Warn at load time when the versions differ so a Suricata upgrade
// without a matching plugin rebuild does not go unnoticed.

use std::ffi::CStr;
use std::os::raw::c_char;
use suricata::SCLogWarning;
use suricata_sys::sys::SC_PACKAGE_VERSION;

/// Suricata version this plugin was built against, e.g. "8.0.8".
pub(crate) fn build_version() -> &'static str {
    CStr::from_bytes_with_nul(SC_PACKAGE_VERSION)
        .ok()
        .and_then(|c| c.to_str().ok())
        .unwrap_or("")
}

/// Running Suricata's version string, e.g. "8.0.8 RELEASE". Looked up with
/// dlsym so a renamed or missing symbol skips the check instead of stopping
/// the plugin from loading.
fn running_version() -> Option<String> {
    unsafe {
        let sym = libc::dlsym(
            libc::RTLD_DEFAULT,
            b"GetProgramVersion\0".as_ptr() as *const c_char,
        );
        if sym.is_null() {
            return None;
        }
        let get: extern "C" fn() -> *const c_char = std::mem::transmute(sym);
        let ptr = get();
        if ptr.is_null() {
            return None;
        }
        CStr::from_ptr(ptr).to_str().ok().map(str::to_owned)
    }
}

/// True if a GetProgramVersion() string ("8.0.8 RELEASE", "9.0.0-dev (abc)")
/// is for the same version as `build`.
pub(crate) fn version_matches(build: &str, running: &str) -> bool {
    running.split_whitespace().next() == Some(build)
}

pub(crate) fn check_suricata_version() {
    let build = build_version();
    if let Some(running) = running_version() {
        if !version_matches(build, &running) {
            SCLogWarning!(
                "ics-parsers plugin was built against Suricata {} but is running in Suricata {}; \
                 rebuild the plugin for this Suricata version (make build SURICATA_SRC=...)",
                build,
                running
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_matches() {
        assert!(version_matches("8.0.8", "8.0.8 RELEASE"));
        assert!(!version_matches("8.0.6", "8.0.8 RELEASE"));
        assert!(!version_matches("8.0.8", "8.0.80 RELEASE"));
        assert!(version_matches("9.0.0-dev", "9.0.0-dev (4f3e2a1)"));
        assert!(!version_matches("8.0.8", ""));
    }

    #[test]
    fn test_build_version() {
        let v = build_version();
        assert!(!v.is_empty());
        assert!(v.chars().next().unwrap().is_ascii_digit());
    }
}
