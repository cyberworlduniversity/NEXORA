//! NEXORA deterministic artifact-ingestion core. Untrusted input is never executed.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactId(String);

impl ArtifactId {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactDigest {
    pub algorithm: String,
    pub value_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Elf,
    Pe,
    MachO,
    Pdf,
    Zip,
    Png,
    Jpeg,
    Gzip,
    Sqlite,
    Wasm,
    Unknown,
}

impl ArtifactFormat {
    pub fn detect(bytes: &[u8]) -> Self {
        if bytes.starts_with(b"\x7fELF") {
            Self::Elf
        } else if bytes.starts_with(b"MZ") {
            Self::Pe
        } else if bytes.starts_with(b"%PDF-") {
            Self::Pdf
        } else if bytes.starts_with(b"PK\x03\x04")
            || bytes.starts_with(b"PK\x05\x06")
            || bytes.starts_with(b"PK\x07\x08")
        {
            Self::Zip
        } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Self::Png
        } else if bytes.starts_with(b"\xff\xd8\xff") {
            Self::Jpeg
        } else if bytes.starts_with(b"\x1f\x8b") {
            Self::Gzip
        } else if bytes.starts_with(b"SQLite format 3\0") {
            Self::Sqlite
        } else if bytes.starts_with(b"\0asm") {
            Self::Wasm
        } else if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
            || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
            || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
            || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
            || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        {
            Self::MachO
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactRecord {
    pub schema_version: u32,
    pub artifact_id: String,
    pub original_name: String,
    pub size_bytes: u64,
    pub format: ArtifactFormat,
    pub digest: ArtifactDigest,
    pub stored_path: String,
    pub trust: String,
    pub execution_performed: bool,
}

#[derive(Clone, Debug)]
pub struct IngestOptions {
    pub max_bytes: u64,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum CoreError {
    InvalidArtifactId,
    NotRegularFile,
    TooLarge { limit: u64 },
    Io(io::Error),
    Manifest(serde_json::Error),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifactId => write!(formatter, "artifact ID must not be empty"),
            Self::NotRegularFile => write!(formatter, "input must be a regular file"),
            Self::TooLarge { limit } => {
                write!(formatter, "input exceeds configured limit of {limit} bytes")
            }
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Manifest(error) => write!(formatter, "manifest serialization error: {error}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Manifest(error)
    }
}

/// Store an input by SHA-256; apply a hard size limit; never execute it.
pub fn ingest_file(
    source: &Path,
    workspace: &Path,
    options: &IngestOptions,
) -> Result<ArtifactRecord, CoreError> {
    let input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err(CoreError::NotRegularFile);
    }

    let mut bytes = Vec::new();
    input
        .take(options.max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > options.max_bytes {
        return Err(CoreError::TooLarge {
            limit: options.max_bytes,
        });
    }

    let digest_hex = format!("{:x}", Sha256::digest(&bytes));
    let id = ArtifactId::new(digest_hex.clone())?;
    let artifacts = workspace.join("artifacts");
    fs::create_dir_all(&artifacts)?;
    let destination = artifacts.join(id.as_str());

    if !destination.exists() {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
        {
            Ok(mut output) => {
                output.write_all(&bytes)?;
                output.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(CoreError::Io(error)),
        }
    }

    let record = ArtifactRecord {
        schema_version: 1,
        artifact_id: id.as_str().to_owned(),
        original_name: source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unnamed")
            .to_owned(),
        size_bytes: bytes.len() as u64,
        format: ArtifactFormat::detect(&bytes),
        digest: ArtifactDigest {
            algorithm: "sha256".into(),
            value_hex: digest_hex,
        },
        stored_path: PathBuf::from("artifacts")
            .join(id.as_str())
            .to_string_lossy()
            .into_owned(),
        trust: "untrusted".into(),
        execution_performed: false,
    };

    let mut manifest = OpenOptions::new()
        .create(true)
        .append(true)
        .open(workspace.join("manifest.jsonl"))?;
    serde_json::to_writer(&mut manifest, &record)?;
    manifest.write_all(b"\n")?;
    manifest.sync_all()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_signatures() {
        assert_eq!(ArtifactFormat::detect(b"\x7fELF"), ArtifactFormat::Elf);
        assert_eq!(ArtifactFormat::detect(b"MZ"), ArtifactFormat::Pe);
        assert_eq!(ArtifactFormat::detect(b"%PDF-1.7"), ArtifactFormat::Pdf);
        assert_eq!(ArtifactFormat::detect(b"PK\x03\x04"), ArtifactFormat::Zip);
        assert_eq!(
            ArtifactFormat::detect(b"\0asm\x01\0\0\0"),
            ArtifactFormat::Wasm
        );
        assert_eq!(ArtifactFormat::detect(b"plain"), ArtifactFormat::Unknown);
    }

    #[test]
    fn rejects_blank_ids() {
        assert!(matches!(
            ArtifactId::new("  "),
            Err(CoreError::InvalidArtifactId)
        ));
    }

    #[test]
    fn ingests_and_deduplicates() {
        let root = std::env::temp_dir().join(format!("nexora-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("sample.bin");
        fs::write(&source, b"\x7fELFsample").unwrap();
        let workspace = root.join("project");

        let first = ingest_file(&source, &workspace, &IngestOptions::default()).unwrap();
        let second = ingest_file(&source, &workspace, &IngestOptions::default()).unwrap();

        assert_eq!(first.digest, second.digest);
        assert_eq!(first.format, ArtifactFormat::Elf);
        assert!(!first.execution_performed);
        assert_eq!(
            fs::read_dir(workspace.join("artifacts")).unwrap().count(),
            1
        );
        assert_eq!(
            fs::read_to_string(workspace.join("manifest.jsonl"))
                .unwrap()
                .lines()
                .count(),
            2
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn enforces_size_limit() {
        let root = std::env::temp_dir().join(format!("nexora-limit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("large.bin");
        fs::write(&source, b"12345").unwrap();

        assert!(matches!(
            ingest_file(
                &source,
                &root.join("workspace"),
                &IngestOptions { max_bytes: 4 }
            ),
            Err(CoreError::TooLarge { limit: 4 })
        ));
        let _ = fs::remove_dir_all(root);
    }
}
