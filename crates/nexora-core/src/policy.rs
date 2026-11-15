//! Explicit resource policy for deterministic static analysis.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisPolicy {
    pub max_input_bytes: u64,
    pub max_evidence_records: usize,
    pub max_findings: usize,
    pub max_printable_strings: usize,
    pub min_printable_string_length: usize,
    pub allow_external_tools: bool,
    pub allow_dynamic_execution: bool,
}

impl Default for AnalysisPolicy {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_evidence_records: 10_000,
            max_findings: 2_000,
            max_printable_strings: 2_000,
            min_printable_string_length: 4,
            allow_external_tools: false,
            allow_dynamic_execution: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InputTooLarge { actual: u64, maximum: u64 },
    ZeroLimit(&'static str),
    DynamicExecutionDisabled,
    ExternalToolsDisabled,
    OutputLimitExceeded { actual: usize, maximum: usize },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => write!(f, "input size {actual} exceeds policy limit {maximum}"),
            Self::ZeroLimit(name) => write!(f, "policy limit {name} must be greater than zero"),
            Self::DynamicExecutionDisabled => write!(f, "dynamic execution is disabled by the active policy"),
            Self::ExternalToolsDisabled => write!(f, "external tools are disabled by the active policy"),
            Self::OutputLimitExceeded { actual, maximum } => write!(f, "output count {actual} exceeds policy limit {maximum}"),
        }
    }
}
impl std::error::Error for PolicyError {}

impl AnalysisPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.max_input_bytes == 0 { return Err(PolicyError::ZeroLimit("max_input_bytes")); }
        if self.max_evidence_records == 0 { return Err(PolicyError::ZeroLimit("max_evidence_records")); }
        if self.max_findings == 0 { return Err(PolicyError::ZeroLimit("max_findings")); }
        if self.max_printable_strings == 0 { return Err(PolicyError::ZeroLimit("max_printable_strings")); }
        if self.min_printable_string_length == 0 { return Err(PolicyError::ZeroLimit("min_printable_string_length")); }
        Ok(())
    }

    pub fn check_input_size(&self, actual: u64) -> Result<(), PolicyError> {
        self.validate()?;
        if actual > self.max_input_bytes {
            return Err(PolicyError::InputTooLarge { actual, maximum: self.max_input_bytes });
        }
        Ok(())
    }

    pub fn check_evidence_count(&self, actual: usize) -> Result<(), PolicyError> {
        if actual > self.max_evidence_records {
            return Err(PolicyError::OutputLimitExceeded { actual, maximum: self.max_evidence_records });
        }
        Ok(())
    }

    pub fn require_external_tools(&self) -> Result<(), PolicyError> {
        if self.allow_external_tools { Ok(()) } else { Err(PolicyError::ExternalToolsDisabled) }
    }

    pub fn require_dynamic_execution(&self) -> Result<(), PolicyError> {
        if self.allow_dynamic_execution { Ok(()) } else { Err(PolicyError::DynamicExecutionDisabled) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_static_only() {
        let policy = AnalysisPolicy::default();
        assert!(!policy.allow_external_tools);
        assert!(!policy.allow_dynamic_execution);
        assert!(policy.require_dynamic_execution().is_err());
        assert!(policy.require_external_tools().is_err());
    }

    #[test]
    fn enforces_input_and_evidence_limits() {
        let policy = AnalysisPolicy { max_input_bytes: 10, max_evidence_records: 2, ..Default::default() };
        assert!(policy.check_input_size(10).is_ok());
        assert!(matches!(policy.check_input_size(11), Err(PolicyError::InputTooLarge { .. })));
        assert!(matches!(policy.check_evidence_count(3), Err(PolicyError::OutputLimitExceeded { .. })));
    }
}
