use nexora_core::{analyze_file, ingest_file, AnalysisPipeline, AnalysisPolicy, IngestOptions};
use std::{env, path::PathBuf, process::ExitCode};

fn usage() {
    eprintln!("NEXORA — local-first reverse engineering toolkit");
    eprintln!("Usage: nexora version | inspect <file> | analyze <file> | report <file> [--max-bytes <n>] | ingest <file> --workspace <directory>");
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") => println!("nexora {}", env!("CARGO_PKG_VERSION")),
        Some("analyze") => {
            let file = args.next().ok_or("missing input file")?;
            if args.next().is_some() {
                return Err("unexpected extra arguments".into());
            }
            let report =
                analyze_file(&PathBuf::from(file), 512 * 1024 * 1024).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        }
        Some("report") => {\n            let file = args.next().ok_or("missing input file")?;\n            let mut policy = AnalysisPolicy::default();\n            while let Some(option) = args.next() {\n                match option.as_str() {\n                    "--max-bytes" => {\n                        let value = args.next().ok_or("missing value for --max-bytes")?;\n                        policy.max_input_bytes = value.parse().map_err(|_| "invalid --max-bytes value")?;\n                    }\n                    _ => return Err(format!("unknown report option: {option}")),\n                }\n            }\n            let pipeline = AnalysisPipeline::new(policy).map_err(|e| e.to_string())?;\n            let report = pipeline.analyze_file(&PathBuf::from(file)).map_err(|e| e.to_string())?;\n            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);\n        }\n        Some("inspect") => {
            let file = args.next().ok_or("missing input file")?;
            let path = PathBuf::from(file);
            let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
            if !meta.is_file() {
                return Err("input must be a regular file".into());
            }
            println!("File: {}", path.display());
            println!("Size: {} bytes", meta.len());
            println!("Use ingest to calculate a digest and identify the format.");
        }
        Some("ingest") => {
            let file = args.next().ok_or("missing input file")?;
            if args.next().as_deref() != Some("--workspace") {
                return Err("expected --workspace <directory>".into());
            }
            let workspace = args.next().ok_or("missing workspace directory")?;
            if args.next().is_some() {
                return Err("unexpected extra arguments".into());
            }
            let record = ingest_file(
                &PathBuf::from(file),
                &PathBuf::from(workspace),
                &IngestOptions::default(),
            )
            .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?
            );
        }
        _ => usage(),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
