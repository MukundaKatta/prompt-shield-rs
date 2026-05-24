use once_cell::sync::Lazy;
use regex::Regex;

use crate::findings::{Finding, RiskLevel};
use crate::rule::Rule;

pub const NAME: &str = "tool_call_inject";

struct PatternSpec {
    re: Regex,
    message: &'static str,
    risk: RiskLevel,
}

static PATTERNS: Lazy<Vec<PatternSpec>> = Lazy::new(|| {
    vec![
        PatternSpec {
            re: Regex::new(r#"(?i)"function_call"\s*:\s*\{"#).unwrap(),
            message: "embedded function_call JSON",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r#"(?i)"tool_calls?"\s*:\s*[\[\{]"#).unwrap(),
            message: "embedded tool_calls JSON",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r"(?i)\bfunction_call\s*:\s*\w").unwrap(),
            message: "function_call marker",
            risk: RiskLevel::Medium,
        },
        PatternSpec {
            re: Regex::new(r"(?i)<\s*(?:function|tool)[_\-]?call\b[^>]*>").unwrap(),
            message: "tool-call XML tag injection",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r#"(?i)"name"\s*:\s*"[A-Za-z0-9_\-]{1,64}"\s*,\s*"arguments"\s*:"#)
                .unwrap(),
            message: "OpenAI-style tool invocation payload",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r#"(?i)\{\s*"type"\s*:\s*"tool_use""#).unwrap(),
            message: "Anthropic-style tool_use payload",
            risk: RiskLevel::High,
        },
    ]
});

pub struct ToolCallInject;

impl Rule for ToolCallInject {
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
