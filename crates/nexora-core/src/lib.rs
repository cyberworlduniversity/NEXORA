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

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BinaryMetadata {
    Elf {
        class: String,
        endian: String,
        machine: u16,
        entry_point: u64,
        section_header_offset: u64,
        section_header_entry_size: u16,
        section_count: u16,
    },
    Pe {
        machine: u16,
        section_count: u16,
        optional_header_size: u16,
        pe_header_offset: u32,
    },
    MachO {
        class: String,
        endian: String,
        cpu_type: u32,
        load_command_count: u32,
        load_commands_size: u32,
    },
}

fn read_u16(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let value: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(value)
    } else {
        u16::from_be_bytes(value)
    })
}

fn read_u32(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

fn read_u64(bytes: &[u8], offset: usize, little: bool) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

/// Parse bounded structural metadata only. No sections, commands, or payloads are executed.
pub fn parse_binary_metadata(bytes: &[u8]) -> Option<BinaryMetadata> {
    if bytes.starts_with(b"\x7fELF") {
        let class = *bytes.get(4)?;
        let data = *bytes.get(5)?;
        let little = match data {
            1 => true,
            2 => false,
            _ => return None,
        };
        let (class_name, entry_point, section_offset) = match class {
            1 => (
                "elf32",
                read_u32(bytes, 24, little)? as u64,
                read_u32(bytes, 32, little)? as u64,
            ),
            2 => (
                "elf64",
                read_u64(bytes, 24, little)?,
                read_u64(bytes, 40, little)?,
            ),
            _ => return None,
        };
        if bytes.get(6).copied()? != 1 || bytes.len() < if class == 1 { 52 } else { 64 } {
            return None;
        }
        let machine = read_u16(bytes, 18, little)?;
        let (entry_size_offset, count_offset, minimum_entry_size) = if class == 1 {
            (46, 48, 40)
        } else {
            (58, 60, 64)
        };
        let entry_size = read_u16(bytes, entry_size_offset, little)?;
        let count = read_u16(bytes, count_offset, little)?;
        if count > 0 {
            let table_start = usize::try_from(section_offset).ok()?;
            let table_bytes = usize::from(entry_size).checked_mul(usize::from(count))?;
            let table_end = table_start.checked_add(table_bytes)?;
            if usize::from(entry_size) < minimum_entry_size || table_end > bytes.len() {
                return None;
            }
        }
        return Some(BinaryMetadata::Elf {
            class: class_name.into(),
            endian: if little { "little" } else { "big" }.into(),
            machine,
            entry_point,
            section_header_offset: section_offset,
            section_header_entry_size: entry_size,
            section_count: count,
        });
    }

    if bytes.starts_with(b"MZ") {
        let pe_offset = read_u32(bytes, 0x3c, true)?;
        let pe = usize::try_from(pe_offset).ok()?;
        if bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let coff = pe.checked_add(4)?;
        let machine = read_u16(bytes, coff, true)?;
        let sections = read_u16(bytes, coff.checked_add(2)?, true)?;
        let optional_size = read_u16(bytes, coff.checked_add(16)?, true)?;
        let section_table = coff
            .checked_add(20)?
            .checked_add(usize::from(optional_size))?;
        let table_size = usize::from(sections).checked_mul(40)?;
        if section_table.checked_add(table_size)? > bytes.len() {
            return None;
        }
        return Some(BinaryMetadata::Pe {
            machine,
            section_count: sections,
            optional_header_size: optional_size,
            pe_header_offset: pe_offset,
        });
    }

    let magic: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let (little, is_64) = match magic {
        [0xce, 0xfa, 0xed, 0xfe] => (true, false),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, true),
        [0xfe, 0xed, 0xfa, 0xce] => (false, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, true),
        _ => return None,
    };
    let header_size = if is_64 { 32 } else { 28 };
    if bytes.len() < header_size {
        return None;
    }
    let load_command_count = read_u32(bytes, 16, little)?;
    let load_commands_size = read_u32(bytes, 20, little)?;
    let commands_end = header_size.checked_add(usize::try_from(load_commands_size).ok()?)?;
    if commands_end > bytes.len() {
        return None;
    }
    Some(BinaryMetadata::MachO {
        class: if is_64 { "macho64" } else { "macho32" }.into(),
        endian: if little { "little" } else { "big" }.into(),
        cpu_type: read_u32(bytes, 4, little)?,
        load_command_count,
        load_commands_size,
    })
}

/// One deterministic analyzer. Implementations must be bounded and read-only.
/// They receive bytes already capped by the caller and must never execute the input.
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, bytes: &[u8]) -> Option<serde_json::Value>;
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AnalyzerFinding {
    pub analyzer: String,
    pub findings: serde_json::Value,
}

/// In-process registry for trusted analyzer implementations.
/// Dynamic library loading and executing sample-provided code are intentionally unsupported.
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self { analyzers: Vec::new() }
    }

    pub fn register<A: Analyzer + 'static>(&mut self, analyzer: A) {
        self.analyzers.push(Box::new(analyzer));
    }

    pub fn analyze(&self, bytes: &[u8]) -> Vec<AnalyzerFinding> {
        self.analyzers
            .iter()
            .filter_map(|analyzer| {
                analyzer.analyze(bytes).map(|findings| AnalyzerFinding {
                    analyzer: analyzer.name().to_owned(),
                    findings,
                })
            })
            .collect()
    }
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register(BinaryHeaderAnalyzer);
        registry
    }
}

/// Built-in bounded ELF, PE, and Mach-O header analyzer.
pub struct BinaryHeaderAnalyzer;

impl Analyzer for BinaryHeaderAnalyzer {
    fn name(&self) -> &'static str {
        "binary_header"
    }

    fn analyze(&self, bytes: &[u8]) -> Option<serde_json::Value> {
        serde_json::to_value(parse_binary_metadata(bytes).ok()?).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StaticAnalysisReport {
    pub schema_version: u32,
    pub file_name: String,
    pub size_bytes: u64,
    pub format: ArtifactFormat,
    pub sha256: String,
    pub binary_metadata: Option<BinaryMetadata>,
    pub analyzer_findings: Vec<AnalyzerFinding>,
    pub entropy_bits_per_byte: f64,
    pub printable_strings: Vec<String>,
    pub strings_truncated: bool,
}

/// Perform bounded, read-only triage. This does not load or execute the sample.
pub fn analyze_file(source: &Path, max_bytes: u64) -> Result<StaticAnalysisReport, CoreError> {
    let input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err(CoreError::NotRegularFile);
    }

    let mut bytes = Vec::new();
    input
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(CoreError::TooLarge { limit: max_bytes });
    }

    let mut strings = Vec::new();
    let mut current = Vec::new();
    let mut strings_truncated = false;
    for byte in &bytes {
        if (0x20..=0x7e).contains(byte) {
            current.push(*byte);
        } else if current.len() >= 4 {
            if strings.len() < 2_000 {
                strings.push(String::from_utf8_lossy(&current).into_owned());
            } else {
                strings_truncated = true;
            }
            current.clear();
        } else {
            current.clear();
        }
    }
    if current.len() >= 4 {
        if strings.len() < 2_000 {
            strings.push(String::from_utf8_lossy(&current).into_owned());
        } else {
            strings_truncated = true;
        }
    }

    let entropy_bits_per_byte = if bytes.is_empty() {
        0.0
    } else {
        let mut counts = [0u64; 256];
        for byte in &bytes {
            counts[*byte as usize] += 1;
        }
        let length = bytes.len() as f64;
        counts
            .iter()
            .filter(|count| **count > 0)
            .fold(0.0, |sum, count| {
                let probability = *count as f64 / length;
                sum - probability * probability.log2()
            })
    };

    Ok(StaticAnalysisReport {
        schema_version: 2,
        file_name: source
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unnamed")
            .to_owned(),
        size_bytes: bytes.len() as u64,
        format: ArtifactFormat::detect(&bytes),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        binary_metadata: parse_binary_metadata(&bytes),
        analyzer_findings: AnalyzerRegistry::default().analyze(&bytes),
        entropy_bits_per_byte,
        printable_strings: strings,
        strings_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysFindingAnalyzer;

    impl Analyzer for AlwaysFindingAnalyzer {
        fn name(&self) -> &'static str {
            "test_probe"
        }

        fn analyze(&self, bytes: &[u8]) -> Option<serde_json::Value> {
            Some(serde_json::json!({ "input_bytes": bytes.len() }))
        }
    }

    #[test]
    fn analyzer_registry_runs_registered_analyzers_without_executing_input() {
        let mut registry = AnalyzerRegistry::new();
        registry.register(AlwaysFindingAnalyzer);
        let findings = registry.analyze(b"untrusted sample");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].analyzer, "test_probe");
        assert_eq!(findings[0].findings["input_bytes"], 16);
    }

    #[test]
    fn default_registry_reports_binary_header_metadata() {
        let mut bytes = vec![0u8; 32 + 8];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&8u32.to_le_bytes());
        let findings = AnalyzerRegistry::default().analyze(&bytes);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].analyzer, "binary_header");
        assert_eq!(findings[0].findings["kind"], "mach_o");
    }

    #[test]
    fn parses_minimal_elf64_header_and_rejects_truncated_section_table() {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            parse_binary_metadata(&bytes),
            Some(BinaryMetadata::Elf {
                machine: 62,
                entry_point: 0x401000,
                ..
            })
        ));
        bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
        assert!(parse_binary_metadata(&bytes).is_none());
    }

    #[test]
    fn parses_pe_headers_and_rejects_bad_signature() {
        let mut bytes = vec![0u8; 0x100];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            parse_binary_metadata(&bytes),
            Some(BinaryMetadata::Pe {
                machine: 0x8664,
                section_count: 2,
                ..
            })
        ));
        bytes[0x80] = b'X';
        assert!(parse_binary_metadata(&bytes).is_none());
    }

    #[test]
    fn parses_macho64_header_and_rejects_truncated_load_commands() {
        // A 32-byte Mach-O64 header declares 120 bytes of load commands.
        // Include the complete declared command region in this valid fixture.
        let mut bytes = vec![0u8; 32 + 120];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&120u32.to_le_bytes());
        assert!(matches!(
            parse_binary_metadata(&bytes),
            Some(BinaryMetadata::MachO {
                cpu_type: 0x01000007,
                load_command_count: 3,
                load_commands_size: 120,
                ..
            })
        ));

        // The parser must reject a file shorter than its declared command region.
        bytes.truncate(32 + 119);
        assert!(parse_binary_metadata(&bytes).is_none());
    }

    #[test]
    fn malformed_binary_headers_return_no_metadata() {
        assert!(parse_binary_metadata(b"\x7fELF").is_none());
        assert!(parse_binary_metadata(b"MZ").is_none());
        assert!(parse_binary_metadata(b"\xcf\xfa\xed\xfe").is_none());
    }

    #[test]
    fn analyzes_entropy_and_printable_strings() {
        let root = std::env::temp_dir().join(format!("nexora-analysis-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("triage.bin");
        fs::write(&source, b"\0hello world\0AAAA").unwrap();

        let report = analyze_file(&source, 1024).unwrap();
        assert_eq!(report.size_bytes, 17);
        assert!(report.entropy_bits_per_byte > 0.0);
        assert!(report.printable_strings.contains(&"hello world".to_owned()));
        assert!(report.printable_strings.contains(&"AAAA".to_owned()));
        let _ = fs::remove_dir_all(root);
    }

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
