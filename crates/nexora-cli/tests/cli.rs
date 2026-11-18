use std::process::Command;

fn run_cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nexora-cli"))
        .args(arguments)
        .output()
        .expect("CLI process should start")
}

#[test]
fn unknown_command_exits_with_failure() {
    let output = run_cli(&["unknown-command"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command"));
}

#[test]
fn missing_command_exits_with_failure() {
    let output = run_cli(&[]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing command"));
}

#[test]
fn version_rejects_extra_arguments() {
    let output = run_cli(&["version", "unexpected"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected extra arguments"));
}

#[test]
fn inspect_rejects_extra_arguments_before_opening_the_path() {
    let output = run_cli(&["inspect", "/path/that/does/not/exist", "unexpected"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected extra arguments"));
}
