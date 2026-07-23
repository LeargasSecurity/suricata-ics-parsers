// S7comm Eve JSON logging
// Copyright (C) 2026 Critical Path Security
// License: GPL-2.0

use crate::s7comm::state::S7commTransaction;

/// Represents the JSON structure for Eve logging
#[derive(Debug)]
pub struct S7commLogEntry {
    pub tx_id: u64,
    pub pdu_reference: u16,
    pub rosctr: &'static str,
    pub function_code: Option<u8>,
    pub function_name: Option<&'static str>,
    pub is_dangerous: bool,
    pub attack_technique: Option<&'static str>,
    pub error_class: Option<u8>,
    pub error_code: Option<u8>,
    pub is_s7comm_plus: bool,
}

impl S7commLogEntry {
    pub fn from_transaction(tx: &S7commTransaction) -> Self {
        let rosctr_str = match tx.request_rosctr {
            Some(0x01) => "Job",
            Some(0x02) => "Ack",
            Some(0x03) => "Ack_Data",
            Some(0x07) => "Userdata",
            _ => "Unknown",
        };

        Self {
            tx_id: tx.id,
            pdu_reference: tx.pdu_reference,
            rosctr: rosctr_str,
            function_code: tx.request_function_code,
            function_name: tx.request_function_name,
            is_dangerous: tx.is_dangerous,
            attack_technique: tx.attack_technique,
            error_class: tx.response_error_class,
            error_code: tx.response_error_code,
            is_s7comm_plus: tx.is_s7comm_plus,
        }
    }

    /// Serialize to JSON string (manual — avoids serde dependency for Suricata compat)
    pub fn to_json(&self) -> String {
        let mut json = String::from("{");

        json.push_str(&format!("\"tx_id\":{}", self.tx_id));
        json.push_str(&format!(",\"pdu_reference\":{}", self.pdu_reference));
        json.push_str(&format!(",\"rosctr\":\"{}\"", self.rosctr));

        if let Some(fc) = self.function_code {
            json.push_str(&format!(",\"function_code\":{}", fc));
            json.push_str(&format!(",\"function_code_hex\":\"0x{:02x}\"", fc));
        }

        if let Some(name) = self.function_name {
            json.push_str(&format!(",\"function_name\":\"{}\"", name));
        }

        json.push_str(&format!(",\"is_dangerous\":{}", self.is_dangerous));

        if let Some(technique) = self.attack_technique {
            json.push_str(&format!(",\"attack_technique\":\"{}\"", technique));
        }

        if let Some(ec) = self.error_class {
            json.push_str(&format!(",\"error_class\":{}", ec));
        }
        if let Some(code) = self.error_code {
            json.push_str(&format!(",\"error_code\":{}", code));
        }

        if self.is_s7comm_plus {
            json.push_str(",\"s7comm_plus\":true");
        }

        json.push('}');
        json
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s7comm::state::S7commTransaction;

    #[test]
    fn test_log_entry_json() {
        let mut tx = S7commTransaction::new(1);
        tx.pdu_reference = 5;
        tx.request_rosctr = Some(0x01);
        tx.request_function_code = Some(0x29);
        tx.request_function_name = Some("PLC Stop");
        tx.is_dangerous = true;
        tx.attack_technique = Some("T0858 Change Operating Mode / T0814 Denial of Service");

        let entry = S7commLogEntry::from_transaction(&tx);
        let json = entry.to_json();

        assert!(json.contains("\"function_code\":41"));
        assert!(json.contains("\"function_name\":\"PLC Stop\""));
        assert!(json.contains("\"is_dangerous\":true"));
        assert!(json.contains("T0858"));
    }
}
