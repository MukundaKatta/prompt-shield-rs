use prompt_shield::rules::DelimiterSmuggle;
use prompt_shield::{RiskLevel, Rule};

#[test]
fn rtl_override_is_high_risk() {
    let text = "before\u{202E}after";
    let findings = DelimiterSmuggle.scan(text);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].risk, RiskLevel::High);
    assert!(findings[0].message.contains("bidi"));
}

#[test]
fn zero_width_space_is_medium_risk() {
    let text = "hello\u{200B}world";
    let findings = DelimiterSmuggle.scan(text);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].risk, RiskLevel::Medium);
}

#[test]
fn multiple_hidden_chars_each_flagged() {
    let text = "a\u{200B}b\u{200C}c\u{200D}d";
    let findings = DelimiterSmuggle.scan(text);
    assert_eq!(findings.len(), 3);
}

#[test]
fn byte_order_mark_is_flagged() {
    let text = "\u{FEFF}file-start";
    let findings = DelimiterSmuggle.scan(text);
    assert!(!findings.is_empty());
}

#[test]
fn pure_ascii_is_safe() {
    let findings = DelimiterSmuggle.scan("Just a normal English sentence with punctuation!");
    assert!(findings.is_empty());
}

#[test]
fn non_latin_letters_are_safe() {
    let findings = DelimiterSmuggle.scan("こんにちは, 你好, привет, مرحبا");
    assert!(findings.is_empty());
}

#[test]
fn span_is_single_codepoint() {
    let text = "x\u{202E}y";
    let findings = DelimiterSmuggle.scan(text);
    assert!(!findings.is_empty());
    let slice = &text[findings[0].start..findings[0].end];
    assert_eq!(slice, "\u{202E}");
}
