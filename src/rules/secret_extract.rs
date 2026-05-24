use once_cell::sync::Lazy;
use regex::Regex;

use crate::findings::{Finding, RiskLevel};
use crate::rule::Rule;

pub const NAME: &str = "secret_extract";

struct PatternSpec {
    re: Regex,
    message: &'static str,
    risk: RiskLevel,
}

static PATTERNS: Lazy<Vec<PatternSpec>> = Lazy::new(|| {
    vec![
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:what|tell\s+me|show|print|reveal|repeat|output|display|give\s+me)\b[^.\n]{0,60}\b(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|configuration)\b",
            )
            .unwrap(),
            message: "system-prompt extraction probe",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:repeat|print|output|echo|display)\s+(?:everything|all)\s+(?:above|before|prior)\b",
            )
            .unwrap(),
            message: "transcript dump probe",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\bwhat\s+(?:tools?|functions?|apis?|capabilit(?:y|ies))\s+(?:do\s+)?you\s+(?:have|use|can\s+(?:call|access))\b",
            )
            .unwrap(),
            message: "tool-list enumeration probe",
            risk: RiskLevel::Medium,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:list|enumerate|show)\s+(?:all\s+)?(?:your\s+)?(?:tools?|functions?|apis?|capabilit(?:y|ies))\b",
            )
            .unwrap(),
            message: "tool-list enumeration probe",
            risk: RiskLevel::Medium,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\b(?:reveal|leak|expose|share)\s+(?:your\s+)?(?:secret|api[_\s-]?key|password|token|credential)s?\b",
            )
            .unwrap(),
            message: "credential extraction probe",
            risk: RiskLevel::High,
        },
        PatternSpec {
            re: Regex::new(
                r"(?i)\bprint\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:above|prior|earlier)\s+(?:message|conversation|context)s?\b",
            )
            .unwrap(),
            message: "context dump probe",
            risk: RiskLevel::High,
        },
    ]
});

pub struct SecretExtract;

impl Rule for SecretExtract {
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
