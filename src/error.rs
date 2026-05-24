use crate::findings::ScanReport;

#[derive(Debug, Clone)]
pub struct ShieldBlocked {
    pub report: ScanReport,
}

impl ShieldBlocked {
    pub fn new(report: ScanReport) -> Self {
        Self { report }
    }
}

impl std::fmt::Display for ShieldBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.report.findings.is_empty() {
            return write!(f, "prompt-shield blocked input: high-risk input");
        }
        let joined = self
            .report
            .findings
            .iter()
            .map(|x| x.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        write!(f, "prompt-shield blocked input: {joined}")
    }
}

impl std::error::Error for ShieldBlocked {}
