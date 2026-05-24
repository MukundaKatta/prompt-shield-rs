use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::findings::{Finding, RiskLevel};
use crate::rule::Rule;
use crate::rules::{format_break, role_override, secret_extract, tool_call_inject};

pub const NAME: &str = "encoded_payload";

static BASE64_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap());
static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)[0-9a-f]{40,}").unwrap());

fn decode_base64(s: &str) -> Option<String> {
    // Pad to multiple of 4 for standard alphabet.
    let mut padded = s.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    let stripped = padded.trim_end_matches('=');
    let bytes = STANDARD_NO_PAD.decode(stripped.as_bytes()).ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    if printable_ratio(&decoded) < 0.8 {
        return None;
    }
    Some(decoded)
}

fn decode_hex(s: &str) -> Option<String> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let s_bytes = s.as_bytes();
    let mut i = 0;
    while i < s_bytes.len() {
        let hi = hex_val(s_bytes[i])?;
        let lo = hex_val(s_bytes[i + 1])?;
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    let decoded = String::from_utf8(bytes).ok()?;
    if printable_ratio(&decoded) < 0.8 {
        return None;
    }
    Some(decoded)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

fn printable_ratio(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let total = s.chars().count() as f32;
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .count() as f32;
    printable / total
}

// Inner scanners (a subset of rules that make sense inside decoded payloads).
fn inner_scan(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(role_override::RoleOverride.scan(text));
    out.extend(tool_call_inject::ToolCallInject.scan(text));
    out.extend(secret_extract::SecretExtract.scan(text));
    out.extend(format_break::FormatBreak.scan(text));
    out
}

pub struct EncodedPayload;

impl Rule for EncodedPayload {
    fn name(&self) -> &str {
        NAME
    }

    fn scan(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        // Track outer spans we already reported so we do not double up.
        for m in BASE64_RE.find_iter(text) {
            if let Some(decoded) = decode_base64(m.as_str()) {
                let inner = inner_scan(&decoded);
                if !inner.is_empty() {
                    let messages: Vec<String> =
                        inner.iter().map(|f| f.message.clone()).collect();
                    let max_risk = inner.iter().map(|f| f.risk).max().unwrap_or(RiskLevel::Medium);
                    out.push(Finding::new(
                        NAME,
                        m.start(),
                        m.end(),
                        format!("base64-encoded payload contains: {}", messages.join("; ")),
                        max_risk,
                    ));
                }
            }
        }
        for m in HEX_RE.find_iter(text) {
            if let Some(decoded) = decode_hex(m.as_str()) {
                let inner = inner_scan(&decoded);
                if !inner.is_empty() {
                    let messages: Vec<String> =
                        inner.iter().map(|f| f.message.clone()).collect();
                    let max_risk = inner.iter().map(|f| f.risk).max().unwrap_or(RiskLevel::Medium);
                    out.push(Finding::new(
                        NAME,
                        m.start(),
                        m.end(),
                        format!("hex-encoded payload contains: {}", messages.join("; ")),
                        max_risk,
                    ));
                }
            }
        }
        out
    }
}
