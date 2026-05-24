use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Block,
}

impl RiskLevel {
    pub fn rank(self) -> u8 {
        match self {
            RiskLevel::Safe => 0,
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Block => 4,
        }
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RiskLevel::Safe => "SAFE",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Block => "BLOCK",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: String,
    pub start: usize,
    pub end: usize,
    pub message: String,
    pub risk: RiskLevel,
}

impl Finding {
    pub fn new(
        rule: impl Into<String>,
        start: usize,
        end: usize,
        message: impl Into<String>,
        risk: RiskLevel,
    ) -> Self {
        Self {
            rule: rule.into(),
            start,
            end,
            message: message.into(),
            risk,
        }
    }

    pub fn span(&self) -> (usize, usize) {
        (self.start, self.end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub input: String,
    pub findings: Vec<Finding>,
    pub risk: RiskLevel,
    pub redacted: String,
}

impl ScanReport {
    pub fn is_safe(&self) -> bool {
        self.risk == RiskLevel::Safe
    }

    pub fn is_blocked(&self) -> bool {
        self.risk >= RiskLevel::High
    }

    pub fn blocked(&self) -> bool {
        self.is_blocked()
    }
}
