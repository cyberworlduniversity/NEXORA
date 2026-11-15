//! Deterministic static-analysis orchestration and evidence normalization.
use crate::{
    analyze_file,
    evidence::{Authority, Confidence, Coverage, EvidenceBundle, EvidenceLimitation, EvidenceRecord},
    policy::{AnalysisPolicy, PolicyError},
    CoreError, StaticAnalysisReport,
};
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct PipelineReport {
    pub schema_version: u32,
    pub engine: String,
    pub engine_version: String,
    pub analysis_mode: String,
    pub static_analysis: StaticAnalysisReport,
    pub evidence: EvidenceBundle,
    pub limitations: Vec<String>,
}

#[derive(Debug)]
pub enum PipelineError {
    Core(CoreError),
    Policy(PolicyError),
    Evidence(crate::evidence::EvidenceError),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Policy(error) => write!(f, "{error}"),
            Self::Evidence(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for PipelineError {}
impl From<CoreError> for PipelineError { fn from(v: CoreError) -> Self { Self::Core(v) } }
impl From<PolicyError> for PipelineError { fn from(v: PolicyError) -> Self { Self::Policy(v) } }
impl From<crate::evidence::EvidenceError> for PipelineError { fn from(v: crate::evidence::EvidenceError) -> Self { Self::Evidence(v) } }

pub struct AnalysisPipeline {
    policy: AnalysisPolicy,
}

impl AnalysisPipeline {
    pub fn new(policy: AnalysisPolicy) -> Result<Self, PipelineError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn policy(&self) -> &AnalysisPolicy { &self.policy }

    /// Runs bounded, read-only analyzers. It never executes the supplied artifact.
    pub fn analyze_file(&self, path: &Path) -> Result<PipelineReport, PipelineError> {
        let metadata = std::fs::metadata(path).map_err(CoreError::Io)?;
        self.policy.check_input_size(metadata.len())?;
        let mut report = analyze_file(path, self.policy.max_input_bytes)?;
        report.printable_strings.retain(|value| value.len() >= self.policy.min_printable_string_length);
        if report.printable_strings.len() > self.policy.max_printable_strings {
            report.printable_strings.truncate(self.policy.max_printable_strings);
            report.strings_truncated = true;
        }
        if report.analyzer_findings.len() > self.policy.max_findings {
            report.analyzer_findings.truncate(self.policy.max_findings);
        }
        let artifact_hash = report.sha256.clone();
        let mut records = Vec::new();

        records.push(EvidenceRecord::new(
            &artifact_hash, "nexora.static.triage", "artifact_identity",
            "Artifact size, detected format and SHA-256 were observed from the input bytes.",
            Confidence::Observed, Authority::OriginalArtifact, None,
            serde_json::json!({
                "file_name": report.file_name,
                "size_bytes": report.size_bytes,
                "format": report.format,
                "sha256": report.sha256
            })
        )?);

        records.push(EvidenceRecord::new(
            &artifact_hash, "nexora.static.entropy", "byte_entropy",
            "Shannon byte entropy was calculated over the complete bounded input.",
            Confidence::Observed, Authority::LocalAnalyzer, None,
            serde_json::json!({ "bits_per_byte": report.entropy_bits_per_byte })
        )?);

        if let Some(binary) = &report.binary_metadata {
            records.push(EvidenceRecord::new(
                &artifact_hash, "nexora.binary.header", "binary_header",
                "A structurally bounded executable header was parsed.",
                Confidence::Observed, Authority::LocalAnalyzer, None,
                serde_json::to_value(binary).expect("binary metadata serialization")
            )?);
        }

        if let Some(dependencies) = &report.dependencies {
            records.push(EvidenceRecord::new(
                &artifact_hash, "nexora.binary.dependencies", "binary_dependencies",
                "Shared-library dependency names were parsed from bounded executable metadata.",
                Confidence::Observed, Authority::LocalAnalyzer, None,
                serde_json::to_value(dependencies).expect("dependency report serialization")
            )?);
        }

        records.push(EvidenceRecord::new(
            &artifact_hash, "nexora.static.strings", "printable_strings",
            "Printable ASCII strings were extracted using the current minimum run length.",
            Confidence::Observed, Authority::LocalAnalyzer, None,
            serde_json::json!({
                "count": report.printable_strings.len(),
                "truncated": report.strings_truncated,
                "values": report.printable_strings
            })
        )?);

        self.policy.check_evidence_count(records.len())?;
        let mut limitations = vec![
            EvidenceLimitation {
                code: "static_only".into(),
                description: "No sample code was executed; dynamic behavior was not observed.".into(),
            },
            EvidenceLimitation {
                code: "no_symbol_or_import_resolution".into(),
                description: "This pipeline extracts basic shared-library names where supported, but does not yet resolve imported symbols, relocations, or call graphs.".into(),
            },
            EvidenceLimitation {
                code: "no_external_engine".into(),
                description: "No Ghidra, IDA, radare2, or external analysis engine was invoked.".into(),
            },
        ];
        if report.strings_truncated {
            limitations.push(EvidenceLimitation {
                code: "strings_truncated".into(),
                description: "The printable-string output reached the built-in collection cap.".into(),
            });
        }
        let bundle = EvidenceBundle::new(
            artifact_hash,
            records,
            Coverage {
                analyzed_bytes: report.size_bytes,
                total_bytes: report.size_bytes,
                categories: vec![
                    "artifact_identity".into(),
                    "format_detection".into(),
                    "byte_entropy".into(),
                    "printable_strings".into(),
                    "executable_header_metadata".into(),
                    "binary_dependency_metadata".into(),
                ],
                partial: true,
            },
            limitations,
        )?;
        let limitation_text = bundle.limitations.iter().map(|v| v.description.clone()).collect();
        Ok(PipelineReport {
            schema_version: 1,
            engine: "NEXORA".into(),
            engine_version: env!("CARGO_PKG_VERSION").into(),
            analysis_mode: "static_read_only".into(),
            static_analysis: report,
            evidence: bundle,
            limitations: limitation_text,
        })
    }
}

impl Default for AnalysisPipeline {
    fn default() -> Self {
        Self::new(AnalysisPolicy::default()).expect("default analysis policy is valid")
    }
}
