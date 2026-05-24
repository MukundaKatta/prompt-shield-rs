use once_cell::sync::Lazy;
use regex::Regex;

use crate::findings::{Finding, RiskLevel};
use crate::rule::Rule;

pub const NAME: &str = "role_override";

struct PatternSpec {
    re: Regex,
    message: &'static str,
    risk: RiskLevel,
}

static PATTERNS: Lazy<Vec<PatternSpec>> = Lazy::new(|| {
    vec![
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,40}\b(?:instruction|instructions|prompt|prompts|rule|rules|message|messages)\b",
            )
            .unwrap(),
            message: "instruction override attempt",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:ignore|disregard|forget)\s+(?:everything|all|what(?:'s|\s+is)?\s+(?:said|written))\s+(?:above|before|prior|earlier)\b",
            )
            .unwrap(),
            message: "instruction override attempt",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,20}\b(?:system|developer)\b[^.\n]{0,20}\b(?:prompt|instruction|instructions|message)\b",
            )
            .unwrap(),
            message: "system prompt override attempt",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r"(?i)\byou\s+are\s+now\b[^.\n]{0,80}").unwrap(),
            message: "persona reassignment attempt",
            risk: RiskLevel::Medium,
        },
        PatternSpec {
            re: Regex::new(r"(?i)\b(?:act|pretend|roleplay|role-play)\s+as\b[^.\n]{0,60}")
                .unwrap(),
            message: "roleplay coercion attempt",
            risk: RiskLevel::Medium,
        },
        PatternSpec {
            re: Regex::new(r"(?im)(?:^|\n)\s*(?:system|assistant|developer)\s*:\s*\S").unwrap(),
            message: "inline role header injection",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(r"(?i)\bnew\s+(?:system\s+)?(?:instructions?|prompt|rules?)\s*[:\-]")
                .unwrap(),
            message: "new-instructions header injection",
            risk: RiskLevel::High,
        },
    ]
});

pub struct RoleOverride;

impl Rule for RoleOverride {
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
