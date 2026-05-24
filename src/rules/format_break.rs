use once_cell::sync::Lazy;
use regex::Regex;

use crate::findings::{Finding, RiskLevel};
use crate::rule::Rule;

pub const NAME: &str = "format_break";

struct PatternSpec {
    re: Regex,
    message: &'static str,
    risk: RiskLevel,
}

static PATTERNS: Lazy<Vec<PatternSpec>> = Lazy::new(|| {
    vec![
        PatternSpec {
            re: Regex::new(
                r"(?i)<\|(?:im_start|im_end|endoftext|end_of_text|system|user|assistant|start_header_id|end_header_id|eot_id)\|>",
            )
            .unwrap(),
            message: "chat-template control token",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)</?\s*(?:system|assistant|user|developer|tool|tools|function|functions|instructions?)\s*>",
            )
            .unwrap(),
            message: "role XML tag injection",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r"(?i)\[/?\s*(?:INST|SYS|S|/S)\s*\]").unwrap(),
            message: "instruction-tuned bracket token",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r"(?i)###\s*(?:system|instructions?|new\s+(?:instructions?|prompt))\b")
                .unwrap(),
            message: "markdown header role injection",
            risk: RiskLevel::Medium,
        },
        PatternSpec {
            re: Regex::new(r"(?i)```\s*(?:system|assistant|developer|instructions?)\b").unwrap(),
            message: "code-fence role injection",
            risk: RiskLevel::Medium,
        },
    ]
});

pub struct FormatBreak;

impl Rule for FormatBreak {
    fn name(&self) -> &str {
        NAME
    }

    fn scan(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for spec in PATTERNS.iter() {
            for m in spec.re.find_iter(text) {
                out.push(Finding::new(
                    NAME,
                    m.start(),
                    m.end(),
                    spec.message,
                    spec.risk,
                ));
            }
        }
        out
    }
}
