use crate::findings::{Finding, RiskLevel};
use crate::rule::Rule;

pub const NAME: &str = "delimiter_smuggle";

fn classify(ch: char) -> Option<(&'static str, RiskLevel)> {
    match ch {
        '\u{202A}' => Some(("left-to-right embedding (bidi)", RiskLevel::High)),
        '\u{202B}' => Some(("right-to-left embedding (bidi)", RiskLevel::High)),
        '\u{202C}' => Some(("pop directional formatting (bidi)", RiskLevel::High)),
        '\u{202D}' => Some(("left-to-right override (bidi)", RiskLevel::High)),
        '\u{202E}' => Some(("right-to-left override (bidi)", RiskLevel::High)),
        '\u{2066}' => Some(("left-to-right isolate (bidi)", RiskLevel::High)),
        '\u{2067}' => Some(("right-to-left isolate (bidi)", RiskLevel::High)),
        '\u{2068}' => Some(("first-strong isolate (bidi)", RiskLevel::High)),
        '\u{2069}' => Some(("pop directional isolate (bidi)", RiskLevel::High)),
        '\u{200B}' => Some(("zero-width space", RiskLevel::Medium)),
        '\u{200C}' => Some(("zero-width non-joiner", RiskLevel::Medium)),
        '\u{200D}' => Some(("zero-width joiner", RiskLevel::Medium)),
        '\u{2060}' => Some(("word joiner", RiskLevel::Medium)),
        '\u{FEFF}' => Some(("byte-order mark / zero-width no-break space", RiskLevel::Medium)),
        '\u{200E}' => Some(("left-to-right mark", RiskLevel::Medium)),
        '\u{200F}' => Some(("right-to-left mark", RiskLevel::Medium)),
        _ => None,
    }
}

pub struct DelimiterSmuggle;

impl Rule for DelimiterSmuggle {
    fn name(&self) -> &str {
        NAME
    }

    fn scan(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for (idx, ch) in text.char_indices() {
            if let Some((label, risk)) = classify(ch) {
                let end = idx + ch.len_utf8();
                out.push(Finding::new(
                    NAME,
                    idx,
                    end,
                    format!("hidden character: {label}"),
                    risk,
                ));
            }
        }
        out
    }
}
