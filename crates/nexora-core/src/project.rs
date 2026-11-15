//! Local-first project metadata and guarded analysis-job state transitions.
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectManifest {
    pub schema_version: u32,
    pub project_id: String,
    pub name: String,
    pub created_at: String,
    pub artifacts: Vec<ProjectArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectArtifact {
    pub artifact_id: String,
    pub sha256: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub format: String,
    pub trust: ArtifactTrust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTrust {
    Untrusted,
    AuthorizedForAnalysis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisJob {
    pub job_id: String,
    pub project_id: String,
    pub artifact_id: String,
    pub state: JobState,
    pub attempt: u32,
    pub created_at: String,
    pub updated_at: String,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobTransition {
    pub job_id: String,
    pub from: JobState,
    pub to: JobState,
    pub occurred_at: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectError {
    EmptyField(&'static str),
    InvalidSha256,
    UnsafeArtifactPath,
    DuplicateArtifact,
    InvalidTransition { from: JobState, to: JobState },
    InvalidAttempt,
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} must not be empty"),
            Self::InvalidSha256 => write!(f, "artifact SHA-256 must contain 64 hexadecimal characters"),
            Self::UnsafeArtifactPath => write!(f, "artifact path must be a safe relative path"),
            Self::DuplicateArtifact => write!(f, "project contains a duplicate artifact ID"),
            Self::InvalidTransition { from, to } => write!(f, "job transition {from:?} -> {to:?} is not allowed"),
            Self::InvalidAttempt => write!(f, "job attempt must be greater than zero"),
        }
    }
}
impl std::error::Error for ProjectError {}

fn non_empty(value: &str, field: &'static str) -> Result<(), ProjectError> {
    if value.trim().is_empty() { Err(ProjectError::EmptyField(field)) } else { Ok(()) }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn safe_relative_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\\') || value.contains(':') {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

impl ProjectManifest {
    pub fn validate(&self) -> Result<(), ProjectError> {
        non_empty(&self.project_id, "project_id")?;
        non_empty(&self.name, "name")?;
        non_empty(&self.created_at, "created_at")?;
        let mut seen = std::collections::BTreeSet::new();
        for artifact in &self.artifacts {
            non_empty(&artifact.artifact_id, "artifact_id")?;
            if !valid_sha256(&artifact.sha256) { return Err(ProjectError::InvalidSha256); }
            if !safe_relative_path(&artifact.relative_path) { return Err(ProjectError::UnsafeArtifactPath); }
            if !seen.insert(artifact.artifact_id.as_str()) { return Err(ProjectError::DuplicateArtifact); }
        }
        Ok(())
    }
}

impl AnalysisJob {
    pub fn validate(&self) -> Result<(), ProjectError> {
        non_empty(&self.job_id, "job_id")?;
        non_empty(&self.project_id, "project_id")?;
        non_empty(&self.artifact_id, "artifact_id")?;
        non_empty(&self.created_at, "created_at")?;
        non_empty(&self.updated_at, "updated_at")?;
        if self.attempt == 0 { return Err(ProjectError::InvalidAttempt); }
        Ok(())
    }

    /// Applies a legal state transition and returns an immutable audit event.
    pub fn transition(
        &mut self,
        next: JobState,
        occurred_at: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<JobTransition, ProjectError> {
        let allowed = matches!(
            (self.state, next),
            (JobState::Queued, JobState::Running)
                | (JobState::Queued, JobState::Cancelled)
                | (JobState::Running, JobState::Completed)
                | (JobState::Running, JobState::Failed)
                | (JobState::Running, JobState::Cancelled)
                | (JobState::Failed, JobState::Queued)
        );
        if !allowed {
            return Err(ProjectError::InvalidTransition { from: self.state, to: next });
        }
        if next == JobState::Queued && self.state == JobState::Failed {
            self.attempt = self.attempt.checked_add(1).ok_or(ProjectError::InvalidAttempt)?;
        }
        let event = JobTransition {
            job_id: self.job_id.clone(),
            from: self.state,
            to: next,
            occurred_at: occurred_at.into(),
            reason: reason.into(),
        };
        self.state = next;
        self.updated_at = event.occurred_at.clone();
        if next != JobState::Failed { self.error_code = None; }
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> AnalysisJob {
        AnalysisJob {
            job_id: "job-1".into(), project_id: "project-1".into(),
            artifact_id: "artifact-1".into(), state: JobState::Queued,
            attempt: 1, created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(), error_code: None,
        }
    }

    #[test]
    fn job_state_machine_rejects_skipping_running() {
        let mut value = job();
        assert!(matches!(
            value.transition(JobState::Completed, "2026-01-01T00:01:00Z", "skip"),
            Err(ProjectError::InvalidTransition { .. })
        ));
        assert_eq!(value.state, JobState::Queued);
    }

    #[test]
    fn failed_job_can_be_requeued_with_incremented_attempt() {
        let mut value = job();
        value.transition(JobState::Running, "t1", "worker claimed").unwrap();
        value.transition(JobState::Failed, "t2", "parser error").unwrap();
        value.transition(JobState::Queued, "t3", "retry").unwrap();
        assert_eq!(value.attempt, 2);
        assert_eq!(value.state, JobState::Queued);
    }

    #[test]
    fn manifest_rejects_path_traversal_and_duplicate_artifacts() {
        let artifact = ProjectArtifact {
            artifact_id: "a1".into(), sha256: "a".repeat(64),
            relative_path: "../outside".into(), size_bytes: 10,
            format: "elf".into(), trust: ArtifactTrust::Untrusted,
        };
        let manifest = ProjectManifest {
            schema_version: 1, project_id: "p1".into(), name: "demo".into(),
            created_at: "now".into(), artifacts: vec![artifact],
        };
        assert_eq!(manifest.validate(), Err(ProjectError::UnsafeArtifactPath));
    }
}
