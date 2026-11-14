//! NEXORA core domain primitives.
//!
//! This crate intentionally starts with deterministic metadata types.
//! File parsing and execution capabilities will be added behind reviewed
//! interfaces with explicit resource and permission policies.

use std::fmt;

/// Stable identifier for an artifact within a NEXORA project.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Creates an identifier after rejecting empty or whitespace-only values.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(CoreError::InvalidArtifactId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Cryptographic digest metadata for an ingested artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDigest {
    pub algorithm: DigestAlgorithm,
    pub value_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Sha256,
}

/// Current trust classification for an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactTrust {
    Untrusted,
    AuthorizedForAnalysis,
}

/// A finding must be backed by one or more evidence references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    InvalidArtifactId,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifactId => write!(f, "artifact ID must not be empty"),
        }
    }
}

impl std::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_id_rejects_blank_values() {
        assert_eq!(ArtifactId::new("   "), Err(CoreError::InvalidArtifactId));
    }

    #[test]
    fn artifact_id_preserves_valid_value() {
        let id = ArtifactId::new("sample-001").expect("valid ID");
        assert_eq!(id.as_str(), "sample-001");
    }
}
