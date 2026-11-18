//! Structured, reproducible evidence records for NEXORA analysis results.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Confidence {
    Observed,
    StronglyInferred,
    WeaklyInferred,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Authority {
    OriginalArtifact,
    LocalAnalyzer,
    ExternalTool,
    ExternalService,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub offset: u64,
    pub length: u64,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub schema_version: u32,
    pub evidence_id: String,
    pub artifact_sha256: String,
    pub analyzer: String,
    pub evidence_type: String,
    pub summary: String,
    pub confidence: Confidence,
    pub authority: Authority,
    pub location: Option<SourceLocation>,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub analyzed_bytes: u64,
    pub total_bytes: u64,
    pub categories: Vec<String>,
    pub partial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceLimitation {
    pub code: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: u32,
    pub artifact_sha256: String,
    pub records: Vec<EvidenceRecord>,
    pub coverage: Coverage,
    pub limitations: Vec<EvidenceLimitation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    InvalidArtifactHash,
    EmptyField(&'static str),
    InvalidLocation,
    DuplicateEvidenceId,
    CoverageExceedsArtifact,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArtifactHash => {
                write!(f, "artifact SHA-256 must be 64 hexadecimal characters")
            }
            Self::EmptyField(name) => write!(f, "{name} must not be empty"),
            Self::InvalidLocation => write!(f, "evidence location is invalid"),
            Self::DuplicateEvidenceId => write!(f, "evidence bundle contains duplicate IDs"),
            Self::CoverageExceedsArtifact => {
                write!(f, "analyzed bytes exceed total artifact bytes")
            }
        }
    }
}
impl std::error::Error for EvidenceError {}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

impl EvidenceRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_sha256: impl Into<String>,
        analyzer: impl Into<String>,
        evidence_type: impl Into<String>,
        summary: impl Into<String>,
        confidence: Confidence,
        authority: Authority,
        location: Option<SourceLocation>,
        payload: serde_json::Value,
    ) -> Result<Self, EvidenceError> {
        let artifact_sha256 = artifact_sha256.into().to_ascii_lowercase();
        let analyzer = analyzer.into();
        let evidence_type = evidence_type.into();
        let summary = summary.into();
        if !valid_sha256(&artifact_sha256) {
            return Err(EvidenceError::InvalidArtifactHash);
        }
        if analyzer.trim().is_empty() {
            return Err(EvidenceError::EmptyField("analyzer"));
        }
        if evidence_type.trim().is_empty() {
            return Err(EvidenceError::EmptyField("evidence_type"));
        }
        if summary.trim().is_empty() {
            return Err(EvidenceError::EmptyField("summary"));
        }
        if location
            .as_ref()
            .is_some_and(|v| v.length == 0 || v.offset.checked_add(v.length).is_none())
        {
            return Err(EvidenceError::InvalidLocation);
        }
        let identity = serde_json::json!({
            "artifact_sha256": artifact_sha256,
            "analyzer": analyzer,
            "evidence_type": evidence_type,
            "summary": summary,
            "confidence": confidence,
            "authority": authority,
            "location": location,
            "payload": payload
        });
        let canonical =
            serde_json::to_vec(&identity).expect("JSON value serialization is infallible");
        let evidence_id = format!("{:x}", Sha256::digest(canonical));
        Ok(Self {
            schema_version: 1,
            evidence_id,
            artifact_sha256,
            analyzer,
            evidence_type,
            summary,
            confidence,
            authority,
            location,
            payload,
        })
    }
}

impl EvidenceBundle {
    pub fn new(
        artifact_sha256: impl Into<String>,
        records: Vec<EvidenceRecord>,
        coverage: Coverage,
        limitations: Vec<EvidenceLimitation>,
    ) -> Result<Self, EvidenceError> {
        let artifact_sha256 = artifact_sha256.into().to_ascii_lowercase();
        if !valid_sha256(&artifact_sha256) {
            return Err(EvidenceError::InvalidArtifactHash);
        }
        if coverage.analyzed_bytes > coverage.total_bytes {
            return Err(EvidenceError::CoverageExceedsArtifact);
        }
        let mut ids = BTreeSet::new();
        for record in &records {
            if record.artifact_sha256 != artifact_sha256 {
                return Err(EvidenceError::InvalidArtifactHash);
            }
            if !ids.insert(record.evidence_id.as_str()) {
                return Err(EvidenceError::DuplicateEvidenceId);
            }
        }
        Ok(Self {
            schema_version: 1,
            artifact_sha256,
            records,
            coverage,
            limitations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> String {
        "a".repeat(64)
    }

    #[test]
    fn evidence_id_is_deterministic_for_same_observation() {
        let make = || {
            EvidenceRecord::new(
                hash(),
                "binary_header",
                "format",
                "ELF header observed",
                Confidence::Observed,
                Authority::LocalAnalyzer,
                None,
                serde_json::json!({"format":"elf"}),
            )
            .unwrap()
        };
        assert_eq!(make().evidence_id, make().evidence_id);
    }

    #[test]
    fn rejects_invalid_hash_and_zero_length_location() {
        assert_eq!(
            EvidenceRecord::new(
                "bad",
                "analyzer",
                "kind",
                "summary",
                Confidence::Observed,
                Authority::LocalAnalyzer,
                None,
                serde_json::json!({})
            )
            .unwrap_err(),
            EvidenceError::InvalidArtifactHash
        );
        assert_eq!(
            EvidenceRecord::new(
                hash(),
                "analyzer",
                "kind",
                "summary",
                Confidence::Observed,
                Authority::LocalAnalyzer,
                Some(SourceLocation {
                    offset: 0,
                    length: 0,
                    label: None
                }),
                serde_json::json!({})
            )
            .unwrap_err(),
            EvidenceError::InvalidLocation
        );
    }

    #[test]
    fn bundle_rejects_coverage_beyond_artifact_size() {
        let result = EvidenceBundle::new(
            hash(),
            vec![],
            Coverage {
                analyzed_bytes: 11,
                total_bytes: 10,
                categories: vec![],
                partial: false,
            },
            vec![],
        );
        assert_eq!(result.unwrap_err(), EvidenceError::CoverageExceedsArtifact);
    }
}
